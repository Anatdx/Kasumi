/*
 * Kasumi - per-open virtual file backend.
 *
 * A captured source remains private to the virtual descriptor. Reads, writes
 * and driver ioctls are forwarded to it; regular-file mmap is copied into a
 * private shmem file before the VMA is installed.
 */
#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/poll.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/xarray.h>

#include "kasumi_base.h"
#include "kasumi_path_policy.h"
#include "kasumi_runtime.h"
#include "kasumi_virtual_file.h"

struct kasumi_virtual_file {
	struct file *real_file;
	struct file *mmap_file;
	struct cdev *cdev;
	struct path source_path;
	struct file_operations fops;
	char *source_name;
	struct dentry *path_dentry;
	struct vfsmount *path_mnt;
	unsigned long target_ino;
	unsigned long target_dev;
	unsigned long source_ino;
	unsigned long source_dev;
	struct kstat visible_stat;
	pid_t tgid;
	struct list_head mappings;
	unsigned int mapping_count;
	bool regular;
	bool directory;
	bool source_path_valid;
	bool visible_stat_valid;
	bool preserve_visible_metadata;
	bool extra_cdev_ref;
	bool tracked;
	struct mutex io_lock;
	struct mutex mmap_lock;
	struct list_head node;
};

struct kasumi_virtual_dir_context {
	struct dir_context ctx;
	struct dir_context *target;
	struct kasumi_virtual_file *virtual;
	char child_path[KSM_MAX_LEN_PATHNAME];
};

struct kasumi_virtual_exec_alias {
	struct rcu_head rcu;
	refcount_t refs;
	unsigned long target_ino;
	unsigned long target_dev;
	unsigned long visible_ino;
	unsigned long visible_dev;
	char path[];
};

/*
 * A VMA keeps an extra reference to the virtual file after vm_file is changed
 * to the real target (or to the shmem snapshot).  The cloned vm_ops table is
 * per mmap call, so two mappings whose drivers return different vm_ops cannot
 * overwrite each other's callback state.  Fork/split VMAs share this object;
 * vm_ops->open/close account for the additional file references.
 */
struct kasumi_virtual_mapping {
	struct kasumi_virtual_file *virtual;
	struct file *hold_file;
	const struct vm_operations_struct *orig_vm_ops;
	struct vm_operations_struct vm_ops;
	atomic_t vma_refs;
	unsigned long map_ino;
	unsigned long map_dev;
	struct list_head node;
};

static DEFINE_SPINLOCK(kasumi_virtual_file_lock);
static LIST_HEAD(kasumi_virtual_file_list);
static atomic_t kasumi_virtual_file_shutdown_state = ATOMIC_INIT(0);
static atomic_t kasumi_virtual_file_live_count = ATOMIC_INIT(0);
static atomic64_t kasumi_virtual_file_opened_count = ATOMIC64_INIT(0);
static atomic64_t kasumi_virtual_dir_iterated_count = ATOMIC64_INIT(0);
static DEFINE_XARRAY(kasumi_virtual_exec_aliases);
static int kasumi_virtual_files_param = 1;
module_param_named(kasumi_virtual_files, kasumi_virtual_files_param, int, 0600);
MODULE_PARM_DESC(kasumi_virtual_files,
		 "1=route supported exact redirects through virtual files (default=1)");

static const struct file_operations kasumi_virtual_fops;
/* __fput() calls fops_put() after ->release().  A per-file fops table cannot
 * be freed from ->release(), so hand that final module reference to a static
 * owner-only table before reclaiming the virtual object. */
static const struct file_operations kasumi_virtual_closed_fops = {
	.owner = THIS_MODULE,
};

static void kasumi_virtual_mapping_close(struct vm_area_struct *vma);
static void kasumi_virtual_mapping_open(struct vm_area_struct *vma);

/* cdev_get() is file-local in the kernel, but adopting a target inode makes
 * __fput() perform the matching cdev_put() for the virtual file as well. */
static bool kasumi_virtual_cdev_get(struct cdev *cdev)
{
	struct module *owner;

	if (!cdev)
		return true;
	owner = cdev->owner;
	if (owner && !try_module_get(owner))
		return false;
	if (!kobject_get_unless_zero(&cdev->kobj)) {
		if (owner)
			module_put(owner);
		return false;
	}
	return true;
}

static struct file *kasumi_virtual_real_file(struct file *file)
{
	struct kasumi_virtual_file *virtual = file ? file->private_data : NULL;

	return virtual ? READ_ONCE(virtual->real_file) : NULL;
}

static void kasumi_virtual_pin_source(struct kasumi_virtual_file *virtual,
				      const struct path *source_path)
{
	virtual->source_path = *source_path;
	kasumi_path_get(&virtual->source_path);
	virtual->source_path_valid = true;
}

static void kasumi_virtual_drop_source(struct kasumi_virtual_file *virtual)
{
	if (!virtual || !virtual->source_path_valid)
		return;
	virtual->source_path_valid = false;
	kasumi_path_put(&virtual->source_path);
	memset(&virtual->source_path, 0, sizeof(virtual->source_path));
}

static bool kasumi_virtual_adopt_real_file(struct file *file,
							   struct file *real_file,
							   bool anon_read_open,
							   bool adopt_inode)
{
	struct path old;
	struct inode *old_inode;
	struct inode *new_inode;

	if (!file || !real_file || !real_file->f_path.dentry ||
	    !real_file->f_path.mnt || !real_file->f_inode ||
	    !kasumi_path_get_ptr || !kasumi_path_put_ptr)
		return false;

	old = file->f_path;
	old_inode = file->f_inode;
	new_inode = real_file->f_inode;
	kasumi_path_get(&real_file->f_path);
	file->f_path = real_file->f_path;
	file->f_mapping = real_file->f_mapping;
	WRITE_ONCE(file->f_wb_err, READ_ONCE(real_file->f_wb_err));
	WRITE_ONCE(file->f_sb_err, READ_ONCE(real_file->f_sb_err));
	if (adopt_inode) {
		file->f_inode = new_inode;
		/* anon_inode_getfile() counted a read open against the shared anon
		 * inode. Move that accounting before the old path/inode is dropped so
		 * the final fput() decrements the target inode instead. */
		if (anon_read_open && old_inode && old_inode != new_inode) {
			i_readcount_dec(old_inode);
			if ((real_file->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
				i_readcount_inc(new_inode);
		}
	}
	if (old.dentry && old.mnt)
		kasumi_path_put(&old);
	return true;
}

static bool kasumi_virtual_adopt_path(struct file *file,
				      const struct path *source)
{
	struct path old;
	struct inode *inode;

	if (!file || !source || !source->dentry || !source->mnt ||
	    !kasumi_path_get_ptr || !kasumi_path_put_ptr)
		return false;
	inode = d_inode(source->dentry);
	if (!inode)
		return false;
	old = file->f_path;
	kasumi_path_get(source);
	file->f_path = *source;
	file->f_inode = inode;
	file->f_mapping = inode->i_mapping;
	if (old.dentry && old.mnt)
		kasumi_path_put(&old);
	return true;
}

static bool kasumi_virtual_track(struct kasumi_virtual_file *virtual)
{
	bool tracked = false;

	spin_lock(&kasumi_virtual_file_lock);
	if (!atomic_read(&kasumi_virtual_file_shutdown_state)) {
		list_add(&virtual->node, &kasumi_virtual_file_list);
		virtual->tracked = true;
		atomic_inc(&kasumi_virtual_file_live_count);
		tracked = true;
	}
	spin_unlock(&kasumi_virtual_file_lock);
	return tracked;
}

static struct kasumi_virtual_mapping *kasumi_virtual_mapping_create(
		struct kasumi_virtual_file *virtual, struct file *hold_file,
		struct file *mapped_file, const struct vm_operations_struct *orig_vm_ops)
{
	struct kasumi_virtual_mapping *mapping;
	struct inode *inode;

	if (!virtual || !hold_file || !mapped_file)
		return NULL;
	mapping = kzalloc(sizeof(*mapping), GFP_KERNEL);
	if (!mapping)
		return NULL;
	mapping->virtual = virtual;
	mapping->hold_file = hold_file;
	mapping->orig_vm_ops = orig_vm_ops;
	if (orig_vm_ops)
		mapping->vm_ops = *orig_vm_ops;
	mapping->vm_ops.open = kasumi_virtual_mapping_open;
	mapping->vm_ops.close = kasumi_virtual_mapping_close;
	atomic_set(&mapping->vma_refs, 1);
	INIT_LIST_HEAD(&mapping->node);
	inode = file_inode(mapped_file);
	if (inode && inode->i_sb) {
		mapping->map_ino = inode->i_ino;
		mapping->map_dev = inode->i_sb->s_dev;
	}

	spin_lock(&kasumi_virtual_file_lock);
	if (!virtual->tracked || atomic_read(&kasumi_virtual_file_shutdown_state)) {
		spin_unlock(&kasumi_virtual_file_lock);
		kfree(mapping);
		return NULL;
	}
	list_add(&mapping->node, &virtual->mappings);
	virtual->mapping_count++;
	spin_unlock(&kasumi_virtual_file_lock);
	return mapping;
}

static void kasumi_virtual_mapping_open(struct vm_area_struct *vma)
{
	struct kasumi_virtual_mapping *mapping;
	const struct vm_operations_struct *orig_vm_ops;

	if (!vma || !vma->vm_ops)
		return;
	mapping = container_of(vma->vm_ops, struct kasumi_virtual_mapping,
				      vm_ops);
	get_file(mapping->hold_file);
	atomic_inc(&mapping->vma_refs);
	orig_vm_ops = READ_ONCE(mapping->orig_vm_ops);
	if (orig_vm_ops && orig_vm_ops->open)
		orig_vm_ops->open(vma);
}

static void kasumi_virtual_mapping_close(struct vm_area_struct *vma)
{
	struct kasumi_virtual_mapping *mapping;
	const struct vm_operations_struct *orig_vm_ops;
	struct kasumi_virtual_file *virtual;
	bool last;

	if (!vma || !vma->vm_ops)
		return;
	mapping = container_of(vma->vm_ops, struct kasumi_virtual_mapping,
				      vm_ops);
	virtual = mapping->virtual;
	orig_vm_ops = READ_ONCE(mapping->orig_vm_ops);
	if (orig_vm_ops && orig_vm_ops->close)
		orig_vm_ops->close(vma);

	spin_lock(&kasumi_virtual_file_lock);
	last = atomic_dec_and_test(&mapping->vma_refs);
	if (last && !list_empty(&mapping->node)) {
		list_del_init(&mapping->node);
		if (virtual->mapping_count)
			virtual->mapping_count--;
	}
	spin_unlock(&kasumi_virtual_file_lock);

	/* The file reference is released only after all virtual state was read. */
	fput(mapping->hold_file);
	if (last)
		kfree(mapping);
}

static int kasumi_virtual_mapping_install(struct kasumi_virtual_file *virtual,
		struct vm_area_struct *vma, struct file *hold_file,
		struct file *mapped_file)
{
	struct kasumi_virtual_mapping *mapping;

	mapping = kasumi_virtual_mapping_create(virtual, hold_file, mapped_file,
			vma ? vma->vm_ops : NULL);
	if (!mapping)
		return -ENOMEM;
	vma->vm_ops = &mapping->vm_ops;
	return 0;
}

static ssize_t KASUMI_NOCFI kasumi_virtual_sync_read_iter(
	struct file *real_file, char __user *buf, size_t count, loff_t *pos)
{
	struct iovec iov = { .iov_base = buf, .iov_len = count };
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	init_sync_kiocb(&kiocb, real_file);
	kiocb.ki_pos = pos ? *pos : 0;
	iov_iter_init(&iter, READ, &iov, 1, count);
	ret = real_file->f_op->read_iter(&kiocb, &iter);
	if (ret == -EIOCBQUEUED)
		return -EOPNOTSUPP;
	if (pos)
		*pos = kiocb.ki_pos;
	return ret;
}

static ssize_t KASUMI_NOCFI kasumi_virtual_sync_write_iter(
	struct file *real_file, const char __user *buf, size_t count, loff_t *pos)
{
	struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = count };
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	init_sync_kiocb(&kiocb, real_file);
	kiocb.ki_pos = pos ? *pos : 0;
	iov_iter_init(&iter, WRITE, &iov, 1, count);
	ret = real_file->f_op->write_iter(&kiocb, &iter);
	if (ret == -EIOCBQUEUED)
		return -EOPNOTSUPP;
	if (pos)
		*pos = kiocb.ki_pos;
	return ret;
}

static int kasumi_virtual_release(struct inode *inode, struct file *file)
{
	struct kasumi_virtual_file *virtual = file ? file->private_data : NULL;
	struct file *real_file;
	struct file *mmap_file;

	(void)inode;
	if (!virtual)
		return 0;

	/* A VMA-held file reference delays this callback until every mapping has
	 * closed, so the identity list is still valid while /proc/maps is read. */
	WARN_ON_ONCE(virtual->mapping_count);
	mutex_lock(&virtual->mmap_lock);
	mmap_file = xchg(&virtual->mmap_file, NULL);
	mutex_unlock(&virtual->mmap_lock);
	if (mmap_file)
		fput(mmap_file);
	real_file = xchg(&virtual->real_file, NULL);
	if (real_file)
		fput(real_file);
	kasumi_virtual_drop_source(virtual);
	WRITE_ONCE(file->f_op, &kasumi_virtual_closed_fops);
	file->private_data = NULL;
	/* Transfer the anon_inode_getfile() fops reference to the static closed
	 * table.  __fput() drops it after this callback returns, so the embedded
	 * table can be reclaimed together with the virtual object below. */
	spin_lock(&kasumi_virtual_file_lock);
	if (virtual->tracked) {
		list_del_init(&virtual->node);
		virtual->tracked = false;
		atomic_dec(&kasumi_virtual_file_live_count);
	}
	spin_unlock(&kasumi_virtual_file_lock);
	kfree(virtual->source_name);
	kfree(virtual);
	return 0;
}

bool kasumi_virtual_file_getattr_fd(unsigned int fd, struct kstat *stat)
{
	struct kasumi_virtual_file *virtual;
	struct file *file;
	struct kstat source_stat;
	bool found = false;

	if (!stat)
		return false;
	file = fget_raw(fd);
	if (!file)
		return false;
	/* Every live virtual open owns a per-file copy of the operations table.
	 * The release callback is the stable discriminator; fget() prevents the
	 * object and its embedded fops table from disappearing during the copy. */
	if (file->f_op && file->f_op->release == kasumi_virtual_release) {
		virtual = file->private_data;
		if (virtual && READ_ONCE(virtual->visible_stat_valid)) {
			if (READ_ONCE(virtual->source_path_valid) &&
			    kasumi_vfs_getattr &&
			    kasumi_vfs_getattr_unprojected(
					       &virtual->source_path, &source_stat,
					       STATX_BASIC_STATS | STATX_BTIME,
					       AT_STATX_SYNC_AS_STAT) == 0)
				kasumi_project_visible_stat(
					stat, &source_stat, &virtual->visible_stat,
					virtual->preserve_visible_metadata,
					virtual->source_ino, virtual->source_dev);
			else
				*stat = virtual->visible_stat;
			found = true;
		}
	}
	fput(file);
	return found;
}

bool kasumi_virtual_file_get_source_fd(unsigned int fd, struct path *source)
{
	struct kasumi_virtual_file *virtual;
	struct file *file;
	bool found = false;

	if (!source)
		return false;
	file = fget_raw(fd);
	if (!file)
		return false;
	if (file->f_op && file->f_op->release == kasumi_virtual_release) {
		virtual = file->private_data;
		if (virtual && READ_ONCE(virtual->source_path_valid)) {
			*source = virtual->source_path;
			kasumi_path_get(source);
			found = true;
		}
	}
	fput(file);
	return found;
}

bool kasumi_virtual_file_get_visible_fd(unsigned int fd, char *visible_path,
					 size_t visible_path_size)
{
	struct kasumi_virtual_file *virtual;
	struct file *file;
	bool found = false;

	if (!visible_path || !visible_path_size ||
	    !kasumi_policy_current_is_view_target())
		return false;
	file = fget_raw(fd);
	if (!file)
		return false;
	/* The file reference keeps private_data alive while its per-open visible
	 * identity is copied.  Looking up by fd avoids aliasing two visible names
	 * that intentionally share one captured backing dentry. */
	if (file->f_op && file->f_op->release == kasumi_virtual_release) {
		virtual = file->private_data;
		if (virtual && virtual->source_name &&
		    strscpy(visible_path, virtual->source_name,
			    visible_path_size) >= 0)
			found = true;
	}
	fput(file);
	return found;
}

bool kasumi_virtual_file_get_target_fd(unsigned int fd,
				       unsigned long *target_ino,
				       unsigned long *target_dev)
{
	struct kasumi_virtual_file *virtual;
	struct file *file;
	bool found = false;

	if (!target_ino || !target_dev)
		return false;
	file = fget_raw(fd);
	if (!file)
		return false;
	if (file->f_op && file->f_op->release == kasumi_virtual_release) {
		virtual = file->private_data;
		if (virtual && virtual->target_ino) {
			*target_ino = virtual->target_ino;
			*target_dev = virtual->target_dev;
			found = true;
		}
	}
	fput(file);
	return found;
}

static void kasumi_virtual_exec_alias_free_rcu(struct rcu_head *rcu)
{
	struct kasumi_virtual_exec_alias *alias =
		container_of(rcu, struct kasumi_virtual_exec_alias, rcu);

	kfree(alias);
}

static void kasumi_virtual_exec_alias_put(
	struct kasumi_virtual_exec_alias *alias)
{
	if (alias && refcount_dec_and_test(&alias->refs))
		call_rcu(&alias->rcu, kasumi_virtual_exec_alias_free_rcu);
}

static int kasumi_virtual_exec_store_task(
	struct task_struct *task, struct kasumi_virtual_exec_alias *alias,
	gfp_t gfp)
{
	struct kasumi_virtual_exec_alias *old;

	if (!task || !alias) {
		kasumi_virtual_exec_alias_put(alias);
		return -EINVAL;
	}
	get_task_struct(task);
	old = xa_store(&kasumi_virtual_exec_aliases, (unsigned long)task,
		       alias, gfp);
	if (xa_is_err(old)) {
		int error = xa_err(old);

		put_task_struct(task);
		kasumi_virtual_exec_alias_put(alias);
		return error;
	}
	if (old) {
		/* The replaced entry already owned the task reference retained by
		 * this xarray slot. */
		put_task_struct(task);
		kasumi_virtual_exec_alias_put(old);
	}
	return 0;
}

int kasumi_virtual_exec_begin_current(
	const char *visible_path, unsigned long target_ino,
	unsigned long target_dev, struct kasumi_virtual_exec_binding *binding)
{
	struct kasumi_virtual_exec_alias *alias;
	struct kasumi_virtual_exec_alias *old;
	size_t length;

	if (!binding)
		return -EINVAL;
	memset(binding, 0, sizeof(*binding));
	if (!visible_path || !*visible_path)
		return -EINVAL;
	if (atomic_read(&kasumi_virtual_file_shutdown_state))
		return -ESHUTDOWN;
	length = strnlen(visible_path, KSM_MAX_LEN_PATHNAME);
	if (!length || length >= KSM_MAX_LEN_PATHNAME)
		return -ENAMETOOLONG;
	alias = kmalloc(sizeof(*alias) + length + 1, GFP_KERNEL);
	if (!alias)
		return -ENOMEM;
	refcount_set(&alias->refs, 1);
	alias->target_ino = target_ino;
	alias->target_dev = target_dev;
	alias->visible_ino = target_ino ?
		kasumi_vnode_source_ino((dev_t)target_dev, target_ino) : 0;
	alias->visible_dev = target_ino ? kasumi_vnode_device() : 0;
	memcpy(alias->path, visible_path, length + 1);

	get_task_struct(current);
	old = xa_store(&kasumi_virtual_exec_aliases,
		       (unsigned long)current, alias, GFP_KERNEL);
	if (xa_is_err(old)) {
		int error = xa_err(old);

		put_task_struct(current);
		kasumi_virtual_exec_alias_put(alias);
		return error;
	}
	if (old)
		put_task_struct(current);
	binding->previous = old;
	binding->installed = alias;
	return 0;
}

void kasumi_virtual_exec_finish_current(
	struct kasumi_virtual_exec_binding *binding, bool committed)
{
	struct kasumi_virtual_exec_alias *current_alias;
	struct kasumi_virtual_exec_alias *installed;
	struct kasumi_virtual_exec_alias *previous;

	if (!binding || !binding->installed)
		return;
	installed = binding->installed;
	previous = binding->previous;
	if (committed) {
		kasumi_virtual_exec_alias_put(previous);
		memset(binding, 0, sizeof(*binding));
		return;
	}

	current_alias = xa_cmpxchg(&kasumi_virtual_exec_aliases,
				   (unsigned long)current, installed,
				   previous, GFP_KERNEL);
	if (current_alias == installed) {
		if (!previous)
			put_task_struct(current);
		kasumi_virtual_exec_alias_put(installed);
	} else {
		kasumi_virtual_exec_alias_put(previous);
	}
	memset(binding, 0, sizeof(*binding));
}

int kasumi_virtual_exec_bind_current(const char *visible_path,
				     unsigned long target_ino,
				     unsigned long target_dev)
{
	struct kasumi_virtual_exec_binding binding;
	int ret;

	ret = kasumi_virtual_exec_begin_current(
		visible_path, target_ino, target_dev, &binding);
	if (!ret)
		kasumi_virtual_exec_finish_current(&binding, true);
	return ret;
}

void kasumi_virtual_exec_clear_current(void)
{
	kasumi_virtual_exec_task_exit(current);
}

bool kasumi_virtual_exec_get_current(char *visible_path,
				     size_t visible_path_size)
{
	struct kasumi_virtual_exec_alias *alias;
	bool found = false;

	if (!visible_path || !visible_path_size)
		return false;
	rcu_read_lock();
	alias = xa_load(&kasumi_virtual_exec_aliases,
			(unsigned long)current);
	if (alias && strscpy(visible_path, alias->path,
			     visible_path_size) >= 0)
		found = true;
	rcu_read_unlock();
	return found;
}

void kasumi_virtual_exec_task_fork(struct task_struct *parent,
				   struct task_struct *child)
{
	struct kasumi_virtual_exec_alias *alias;

	if (!parent || !child ||
	    atomic_read(&kasumi_virtual_file_shutdown_state))
		return;
	rcu_read_lock();
	alias = xa_load(&kasumi_virtual_exec_aliases,
			(unsigned long)parent);
	if (alias && !refcount_inc_not_zero(&alias->refs))
		alias = NULL;
	rcu_read_unlock();
	if (alias)
		(void)kasumi_virtual_exec_store_task(child, alias, GFP_ATOMIC);
}

void kasumi_virtual_exec_task_exit(struct task_struct *task)
{
	struct kasumi_virtual_exec_alias *alias;

	if (!task)
		return;
	alias = xa_erase(&kasumi_virtual_exec_aliases,
			 (unsigned long)task);
	if (!alias)
		return;
	kasumi_virtual_exec_alias_put(alias);
	put_task_struct(task);
}

static void kasumi_virtual_exec_aliases_shutdown(void)
{
	struct kasumi_virtual_exec_alias *alias;
	unsigned long index = 0;

	for (;;) {
		xa_lock(&kasumi_virtual_exec_aliases);
		alias = xa_find(&kasumi_virtual_exec_aliases, &index,
				ULONG_MAX, XA_PRESENT);
		if (alias)
			__xa_erase(&kasumi_virtual_exec_aliases, index);
		xa_unlock(&kasumi_virtual_exec_aliases);
		if (!alias)
			break;
		kasumi_virtual_exec_alias_put(alias);
		put_task_struct((struct task_struct *)index);
		if (index == ULONG_MAX)
			break;
		index++;
	}
	xa_destroy(&kasumi_virtual_exec_aliases);
}

bool kasumi_virtual_file_lookup_path(const struct path *path,
				     char *visible_path,
				     size_t visible_path_size)
{
	struct kasumi_virtual_file *virtual;
	bool found = false;

	if (!path || !path->dentry || !path->mnt || !visible_path ||
	    !visible_path_size || !kasumi_policy_current_is_view_target())
		return false;
	spin_lock(&kasumi_virtual_file_lock);
	list_for_each_entry(virtual, &kasumi_virtual_file_list, node) {
		if (virtual->path_dentry != path->dentry ||
		    virtual->path_mnt != path->mnt || !virtual->source_name)
			continue;
		if (strscpy(visible_path, virtual->source_name,
			    visible_path_size) >= 0)
			found = true;
		break;
	}
	spin_unlock(&kasumi_virtual_file_lock);
	return found;
}

bool kasumi_virtual_file_lookup_maps(unsigned long target_ino,
					     unsigned long target_dev,
					     unsigned long *spoofed_ino,
					     unsigned long *spoofed_dev,
					     char *spoofed_pathname,
					     size_t spoofed_pathname_size)
{
	struct kasumi_virtual_exec_alias *exec_alias;
	struct kasumi_virtual_file *virtual;
	pid_t tgid = task_tgid_vnr(current);
	bool found = false;

	if (!target_ino || !spoofed_ino || !spoofed_dev ||
	    !spoofed_pathname || !spoofed_pathname_size ||
	    !kasumi_policy_current_is_view_target())
		return false;
	rcu_read_lock();
	exec_alias = xa_load(&kasumi_virtual_exec_aliases,
			     (unsigned long)current);
	if (exec_alias && exec_alias->target_ino == target_ino &&
	    (!target_dev || exec_alias->target_dev == target_dev) &&
	    exec_alias->visible_ino && exec_alias->visible_dev &&
	    strscpy(spoofed_pathname, exec_alias->path,
		    spoofed_pathname_size) >= 0) {
		*spoofed_ino = exec_alias->visible_ino;
		*spoofed_dev = exec_alias->visible_dev;
		found = true;
	}
	rcu_read_unlock();
	if (found)
		return true;

	spin_lock(&kasumi_virtual_file_lock);
	list_for_each_entry(virtual, &kasumi_virtual_file_list, node) {
		struct kasumi_virtual_mapping *mapping;

		if (virtual->tgid != tgid || !virtual->source_name ||
		    !virtual->source_ino)
			continue;
		list_for_each_entry(mapping, &virtual->mappings, node) {
			if (mapping->map_ino != target_ino ||
			    (target_dev && mapping->map_dev != target_dev))
				continue;
			*spoofed_ino = virtual->source_ino;
			*spoofed_dev = virtual->source_dev;
			strscpy(spoofed_pathname, virtual->source_name,
				spoofed_pathname_size);
			found = true;
			break;
		}
		if (found)
			break;
	}
	spin_unlock(&kasumi_virtual_file_lock);
	return found;
}

static loff_t kasumi_virtual_llseek(struct file *file, loff_t offset,
					    int whence)
{
	struct kasumi_virtual_file *virtual = file ? file->private_data : NULL;
	struct file *real_file;
	loff_t ret;

	if (!virtual)
		return -ENODEV;
	mutex_lock(&virtual->io_lock);
	real_file = kasumi_virtual_real_file(file);
	if (!real_file)
		ret = -ENODEV;
	else {
		real_file->f_pos = file->f_pos;
		ret = vfs_llseek(real_file, offset, whence);
		file->f_pos = real_file->f_pos;
	}
	mutex_unlock(&virtual->io_lock);
	return ret;
}

static ssize_t KASUMI_NOCFI kasumi_virtual_read(
	struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct kasumi_virtual_file *virtual = file ? file->private_data : NULL;
	struct file *real_file;
	bool uses_file_pos = pos == &file->f_pos;
	ssize_t ret;

	if (!virtual)
		return -ENODEV;
	mutex_lock(&virtual->io_lock);
	real_file = kasumi_virtual_real_file(file);
	if (!real_file || !real_file->f_op ||
	    (!real_file->f_op->read && !real_file->f_op->read_iter))
		ret = -EINVAL;
	else {
		if (uses_file_pos)
			real_file->f_pos = file->f_pos;
		if (real_file->f_op->read)
			ret = real_file->f_op->read(real_file, buf, count, pos);
		else
			ret = kasumi_virtual_sync_read_iter(real_file, buf, count, pos);
		if (uses_file_pos && ret >= 0) {
			real_file->f_pos = *pos;
			file->f_pos = *pos;
		}
	}
	mutex_unlock(&virtual->io_lock);
	return ret;
}

static ssize_t KASUMI_NOCFI kasumi_virtual_write(
	struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	struct kasumi_virtual_file *virtual = file ? file->private_data : NULL;
	struct file *real_file;
	bool uses_file_pos = pos == &file->f_pos;
	ssize_t ret;

	if (!virtual)
		return -ENODEV;
	mutex_lock(&virtual->io_lock);
	real_file = kasumi_virtual_real_file(file);
	if (!real_file || !real_file->f_op ||
	    (!real_file->f_op->write && !real_file->f_op->write_iter))
		ret = -EINVAL;
	else {
		if (uses_file_pos)
			real_file->f_pos = file->f_pos;
		if (real_file->f_op->write)
			ret = real_file->f_op->write(real_file, buf, count, pos);
		else
			ret = kasumi_virtual_sync_write_iter(real_file, buf, count, pos);
		if (uses_file_pos && ret >= 0) {
			real_file->f_pos = *pos;
			file->f_pos = *pos;
		}
	}
	mutex_unlock(&virtual->io_lock);
	return ret;
}

static ssize_t KASUMI_NOCFI kasumi_virtual_read_iter(struct kiocb *iocb,
						      struct iov_iter *to)
{
	struct file *file = iocb ? iocb->ki_filp : NULL;
	struct kasumi_virtual_file *virtual = file ? file->private_data : NULL;
	struct file *real_file;
	struct file *saved_file;
	loff_t saved_pos;
	bool uses_file_pos;
	ssize_t ret;

	if (!iocb || !virtual)
		return -EINVAL;
	/* The wrapper cannot safely change ki_filp for an async request: lower
	 * layers may retain it until completion.  Keep this backend synchronous
	 * unless a real file ->read implementation is available. */
	if (!is_sync_kiocb(iocb))
		return -EOPNOTSUPP;
	mutex_lock(&virtual->io_lock);
	real_file = kasumi_virtual_real_file(file);
	if (!real_file || !real_file->f_op || !real_file->f_op->read_iter) {
		ret = -EINVAL;
		goto out_unlock;
	}
	saved_pos = real_file->f_pos;
	real_file->f_pos = file->f_pos;
	uses_file_pos = iocb->ki_pos == file->f_pos;
	saved_file = iocb->ki_filp;
	iocb->ki_filp = real_file;
	ret = real_file->f_op->read_iter(iocb, to);
	iocb->ki_filp = saved_file;
	if (uses_file_pos) {
		real_file->f_pos = iocb->ki_pos;
		file->f_pos = iocb->ki_pos;
	} else {
		real_file->f_pos = saved_pos;
	}
	out_unlock:
	mutex_unlock(&virtual->io_lock);
	return ret;
}

static ssize_t KASUMI_NOCFI kasumi_virtual_write_iter(
	struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb ? iocb->ki_filp : NULL;
	struct kasumi_virtual_file *virtual = file ? file->private_data : NULL;
	struct file *real_file;
	struct file *saved_file;
	loff_t saved_pos;
	bool uses_file_pos;
	ssize_t ret;

	if (!iocb || !virtual)
		return -EINVAL;
	if (!is_sync_kiocb(iocb))
		return -EOPNOTSUPP;
	mutex_lock(&virtual->io_lock);
	real_file = kasumi_virtual_real_file(file);
	if (!real_file || !real_file->f_op || !real_file->f_op->write_iter) {
		ret = -EINVAL;
		goto out_unlock;
	}
	saved_pos = real_file->f_pos;
	real_file->f_pos = file->f_pos;
	uses_file_pos = iocb->ki_pos == file->f_pos;
	saved_file = iocb->ki_filp;
	iocb->ki_filp = real_file;
	ret = real_file->f_op->write_iter(iocb, from);
	iocb->ki_filp = saved_file;
	if (uses_file_pos) {
		real_file->f_pos = iocb->ki_pos;
		file->f_pos = iocb->ki_pos;
	} else {
		real_file->f_pos = saved_pos;
	}
	out_unlock:
	mutex_unlock(&virtual->io_lock);
	return ret;
}

static int KASUMI_NOCFI kasumi_virtual_copy_buffered(struct file *input,
						struct file *output,
						loff_t input_pos,
						loff_t output_pos,
						size_t length)
{
	char *buffer;
	int ret = 0;

	if (!kasumi_kernel_read || !kasumi_kernel_write)
		return -EOPNOTSUPP;
	buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;
	while (length) {
		size_t chunk = min_t(size_t, length, PAGE_SIZE);
		ssize_t copied;
		ssize_t written;
		size_t done = 0;

		copied = kasumi_kernel_read(input, buffer, chunk, &input_pos);
		if (copied <= 0) {
			ret = copied < 0 ? (int)copied : -EIO;
			break;
		}
		while (done < copied) {
			written = kasumi_kernel_write(output, buffer + done,
						      copied - done, &output_pos);
			if (written <= 0) {
				ret = written < 0 ? (int)written : -EIO;
				break;
			}
			done += written;
		}
		if (ret)
			break;
		length -= copied;
	}
	kfree(buffer);
	return ret;
}

static int kasumi_virtual_copy_range(struct file *input, struct file *output,
					     loff_t input_pos, loff_t output_pos,
					     size_t length)
{
	if (kasumi_vfs_copy_file_range) {
		while (length) {
			ssize_t copied;

			copied = kasumi_copy_file_range(input, input_pos, output,
							output_pos, length, 0);
#ifdef COPY_FILE_SPLICE
			if (copied == -EXDEV)
				copied = kasumi_copy_file_range(input, input_pos, output,
								 output_pos, length,
								 COPY_FILE_SPLICE);
#endif
			if (copied == -EXDEV || copied == -EOPNOTSUPP ||
			    copied == -EINVAL)
				break;
			if (copied <= 0)
				return copied < 0 ? (int)copied : -EIO;
			input_pos += copied;
			output_pos += copied;
			length -= copied;
		}
		if (!length)
			return 0;
	}
	return kasumi_virtual_copy_buffered(input, output, input_pos,
						 output_pos, length);
}

static int KASUMI_NOCFI kasumi_virtual_prepare_shmem(
						struct kasumi_virtual_file *virtual)
{
	struct file *shmem_file;
	struct inode *real_inode;
	loff_t file_size;
	int ret;

	if (!virtual || !kasumi_shmem_file_setup || !kasumi_kernel_read ||
	    !kasumi_kernel_write)
		return -EOPNOTSUPP;

	mutex_lock(&virtual->mmap_lock);
	if (virtual->mmap_file) {
		mutex_unlock(&virtual->mmap_lock);
		return 0;
	}

	real_inode = file_inode(virtual->real_file);
	if (!real_inode) {
		ret = -ENODEV;
		goto out_unlock;
	}
	file_size = i_size_read(real_inode);
	if (file_size < 0 || (u64)file_size > (u64)SIZE_MAX) {
		ret = -EOVERFLOW;
		goto out_unlock;
	}

	shmem_file = kasumi_shmem_file_setup("kasumi_mmap", file_size, 0);
	if (IS_ERR(shmem_file)) {
		ret = PTR_ERR(shmem_file);
		goto out_unlock;
	}
	if (file_size) {
		ret = kasumi_virtual_copy_range(virtual->real_file, shmem_file,
						0, 0, (size_t)file_size);
		if (ret) {
			fput(shmem_file);
			goto out_unlock;
		}
	}
	virtual->mmap_file = shmem_file;
	mutex_unlock(&virtual->mmap_lock);
	return 0;

out_unlock:
	mutex_unlock(&virtual->mmap_lock);
	return ret;
}

static int KASUMI_NOCFI kasumi_virtual_mmap_shmem(
							     struct kasumi_virtual_file *virtual,
							     struct file *file,
							     struct vm_area_struct *vma)
{
	struct file *shmem_file;
	struct file *old_file;
	int ret;

	if (!virtual || !file || !vma ||
	    vma->vm_file != file)
		return -EOPNOTSUPP;
	/* A fixed snapshot cannot provide MAP_SHARED writeback.  Refuse that
	 * combination instead of silently turning writes into private memory. */
	if ((vma->vm_flags & (VM_SHARED | VM_WRITE)) ==
	    (VM_SHARED | VM_WRITE))
		return -EOPNOTSUPP;

	ret = kasumi_virtual_prepare_shmem(virtual);
	if (ret)
		return ret;
	mutex_lock(&virtual->mmap_lock);
	shmem_file = virtual->mmap_file;
	if (!shmem_file) {
		mutex_unlock(&virtual->mmap_lock);
		return -ENODEV;
	}
	get_file(shmem_file);
	mutex_unlock(&virtual->mmap_lock);

	old_file = vma->vm_file;
	vma->vm_file = shmem_file;
	ret = shmem_file->f_op && shmem_file->f_op->mmap ?
		shmem_file->f_op->mmap(shmem_file, vma) : -ENODEV;
	if (ret) {
		if (vma->vm_file == shmem_file) {
			vma->vm_file = old_file;
			fput(shmem_file);
		} else {
			/* A driver which replaces vm_file owns the old shmem
			 * reference, while the original virtual-file reference still
			 * belongs to this wrapper. */
			fput(old_file);
		}
		vma->vm_ops = NULL;
		return ret;
	}
	if (vma->vm_file == shmem_file) {
		/* Transfer the VMA's original virtual-file reference to the identity
		 * object.  If allocation fails, the mapping remains valid but maps
		 * projection is unavailable for this VMA. */
		if (kasumi_virtual_mapping_install(virtual, vma, old_file,
						   shmem_file) != 0)
			fput(old_file);
	} else {
		/* The target mmap hook replaced vm_file and is responsible for
		 * dropping shmem_file's reference.  Drop the wrapper reference
		 * which can no longer be owned by the VMA. */
		fput(old_file);
	}
	return 0;
}

static int KASUMI_NOCFI kasumi_virtual_mmap_real(
	struct kasumi_virtual_file *virtual, struct file *file,
	struct vm_area_struct *vma)
{
	struct file *real_file = READ_ONCE(virtual->real_file);
	struct file *old_file;
	int ret;

	if (!real_file || !real_file->f_op || !real_file->f_op->mmap ||
	    !vma || vma->vm_file != file)
		return -ENODEV;
	old_file = vma->vm_file;
	get_file(real_file);
	vma->vm_file = real_file;
	ret = real_file->f_op->mmap(real_file, vma);
	if (ret) {
		if (vma->vm_file == real_file) {
			fput(real_file);
			vma->vm_file = old_file;
		} else {
			/* A conforming mmap hook that changes vm_file has already
			 * released the old real-file reference.  The virtual-file
			 * reference still needs to be consumed here. */
			fput(old_file);
		}
		vma->vm_ops = NULL;
		return ret;
	}
	if (vma->vm_file == real_file) {
		if (kasumi_virtual_mapping_install(virtual, vma, old_file,
						   real_file) != 0)
			fput(old_file);
	} else {
		/* A driver which changes vm_file owns the replacement and has
		 * already released the real-file reference.  Only the original
		 * virtual-file reference remains ours. */
		fput(old_file);
	}
	return 0;
}

static int KASUMI_NOCFI kasumi_virtual_mmap(struct file *file,
						struct vm_area_struct *vma)
{
	struct kasumi_virtual_file *virtual = file ? file->private_data : NULL;

	if (!virtual)
		return -ENODEV;
	if (virtual->regular)
		return kasumi_virtual_mmap_shmem(virtual, file, vma);
	return kasumi_virtual_mmap_real(virtual, file, vma);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
static int KASUMI_NOCFI kasumi_virtual_mmap_prepare(struct vm_area_desc *desc)
{
	struct file *file;
	struct kasumi_virtual_file *virtual;
	struct file *real_file;
	int ret;

	if (!desc || !desc->file)
		return -EINVAL;
	file = desc->file;
	virtual = file->private_data;
	if (!virtual)
		return -ENODEV;

	/* A regular target still uses the snapshot address_space.  Select the
	 * shmem file before mmap_region() allocates the VMA; its own ->mmap hook
	 * then runs normally in __mmap_new_file_vma(). */
	if (virtual->regular) {
		struct kasumi_virtual_mapping *mapping;

		ret = kasumi_virtual_prepare_shmem(virtual);
		if (ret)
			return ret;
		mutex_lock(&virtual->mmap_lock);
		desc->file = virtual->mmap_file;
		mutex_unlock(&virtual->mmap_lock);
		if (!desc->file)
			return -ENODEV;

		/* The VMA will acquire the shmem reference after this callback.  Keep
		 * the original virtual file alive for maps projection and vm_ops close. */
		get_file(file);
		mapping = kasumi_virtual_mapping_create(virtual, file, desc->file,
							NULL);
		if (mapping)
			desc->vm_ops = &mapping->vm_ops;
		else
			fput(file);
		return 0;
	}

	real_file = kasumi_virtual_real_file(file);
	if (!real_file || !real_file->f_op)
		return -ENODEV;
	if (!real_file->f_op->mmap_prepare)
		return 0;

	/* The descriptor owns no file reference.  mmap_region() takes the VMA
	 * reference after this callback, while the virtual fd keeps real_file
	 * alive for the duration of the call. */
	desc->file = real_file;
	ret = real_file->f_op->mmap_prepare(desc);
	if (ret)
		return ret;
	if (desc->file) {
		struct kasumi_virtual_mapping *mapping;

		get_file(file);
		mapping = kasumi_virtual_mapping_create(virtual, file, desc->file,
							 desc->vm_ops);
		if (mapping)
			desc->vm_ops = &mapping->vm_ops;
		else
			fput(file);
	}
	return 0;
}
#endif

static unsigned long KASUMI_NOCFI kasumi_virtual_get_unmapped_area(
		struct file *file, unsigned long addr, unsigned long len,
		unsigned long pgoff, unsigned long flags)
{
	struct kasumi_virtual_file *virtual = file ? file->private_data : NULL;
	struct file *real_file;
	struct file *area_file;
	unsigned long ret;

	if (!virtual)
		return -EINVAL;
	if (virtual->regular) {
		if (kasumi_virtual_prepare_shmem(virtual))
			return -EOPNOTSUPP;
		mutex_lock(&virtual->mmap_lock);
		area_file = virtual->mmap_file;
		if (area_file)
			get_file(area_file);
		mutex_unlock(&virtual->mmap_lock);
		if (!area_file)
			return -ENODEV;
		if (area_file->f_op && area_file->f_op->get_unmapped_area)
			ret = area_file->f_op->get_unmapped_area(area_file, addr, len,
								pgoff, flags);
		else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
			if (kasumi_mm_get_unmapped_area_ptr)
				ret = kasumi_mm_get_unmapped_area_ptr(current->mm,
								      area_file, addr, len,
								      pgoff, flags);
			else
				ret = -ENOMEM;
#else
			if (current->mm && current->mm->get_unmapped_area)
				ret = current->mm->get_unmapped_area(area_file, addr, len,
								 pgoff, flags);
			else
				ret = -ENOMEM;
#endif
		fput(area_file);
		return ret;
	}
	real_file = kasumi_virtual_real_file(file);
	if (!real_file || !real_file->f_op)
		return -ENODEV;

	/* Driver mappings may require an alignment or aperture chosen by the
	 * target file's implementation.  Pass the real file so its private data,
	 * inode and mapping are exactly what the driver expects. */
	if (real_file->f_op->get_unmapped_area)
		return real_file->f_op->get_unmapped_area(real_file, addr, len,
							 pgoff, flags);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	if (kasumi_mm_get_unmapped_area_ptr)
		return kasumi_mm_get_unmapped_area_ptr(current->mm, real_file, addr, len,
							       pgoff, flags);
#else
	if (current->mm && current->mm->get_unmapped_area)
		return current->mm->get_unmapped_area(real_file, addr, len, pgoff,
							       flags);
#endif
	return -ENOMEM;
}

static long KASUMI_NOCFI kasumi_virtual_ioctl(struct file *file,
						      unsigned int cmd,
						      unsigned long arg)
{
	struct file *real_file = kasumi_virtual_real_file(file);

	if (!real_file || !real_file->f_op || !real_file->f_op->unlocked_ioctl)
		return -ENOTTY;
	return real_file->f_op->unlocked_ioctl(real_file, cmd, arg);
}

#ifdef CONFIG_COMPAT
static long KASUMI_NOCFI kasumi_virtual_compat_ioctl(struct file *file,
							      unsigned int cmd,
							      unsigned long arg)
{
	struct file *real_file = kasumi_virtual_real_file(file);

	if (!real_file || !real_file->f_op || !real_file->f_op->compat_ioctl)
		return -ENOTTY;
	return real_file->f_op->compat_ioctl(real_file, cmd, arg);
}
#endif

static __poll_t KASUMI_NOCFI kasumi_virtual_poll(struct file *file,
							 struct poll_table_struct *wait)
{
	struct file *real_file = kasumi_virtual_real_file(file);

	if (!real_file || !real_file->f_op || !real_file->f_op->poll)
		return EPOLLERR;
	return real_file->f_op->poll(real_file, wait);
}

static int KASUMI_NOCFI kasumi_virtual_fsync(struct file *file,
						      loff_t start, loff_t end,
						      int datasync)
{
	struct file *real_file = kasumi_virtual_real_file(file);

	if (!real_file || !real_file->f_op || !real_file->f_op->fsync)
		return -EINVAL;
	return real_file->f_op->fsync(real_file, start, end, datasync);
}

static int KASUMI_NOCFI kasumi_virtual_flush(struct file *file,
						     fl_owner_t id)
{
	struct file *real_file = kasumi_virtual_real_file(file);

	if (!real_file || !real_file->f_op || !real_file->f_op->flush)
		return 0;
	return real_file->f_op->flush(real_file, id);
}

static int KASUMI_NOCFI kasumi_virtual_fasync(int fd, struct file *file,
						      int on)
{
	struct file *real_file = kasumi_virtual_real_file(file);

	if (!real_file || !real_file->f_op || !real_file->f_op->fasync)
		return -EINVAL;
	return real_file->f_op->fasync(fd, real_file, on);
}

static ssize_t KASUMI_NOCFI kasumi_virtual_splice_read(
	struct file *file, loff_t *pos, struct pipe_inode_info *pipe, size_t len,
	unsigned int flags)
{
	struct file *real_file = kasumi_virtual_real_file(file);

	if (!real_file || !real_file->f_op || !real_file->f_op->splice_read)
		return -EINVAL;
	return real_file->f_op->splice_read(real_file, pos, pipe, len, flags);
}

static ssize_t KASUMI_NOCFI kasumi_virtual_splice_write(
	struct pipe_inode_info *pipe, struct file *file, loff_t *pos, size_t len,
	unsigned int flags)
{
	struct file *real_file = kasumi_virtual_real_file(file);

	if (!real_file || !real_file->f_op || !real_file->f_op->splice_write)
		return -EINVAL;
	return real_file->f_op->splice_write(pipe, real_file, pos, len, flags);
}

static KASUMI_FILLDIR_RET_TYPE KASUMI_NOCFI
kasumi_virtual_dir_actor(struct dir_context *ctx, const char *name,
			 int namlen, loff_t offset, u64 ino,
			 unsigned int d_type)
{
	struct kasumi_virtual_dir_context *directory =
		container_of(ctx, struct kasumi_virtual_dir_context, ctx);
	const char *visible_path;
	unsigned long visible_ino;
	int length;

	if (!directory->target || !directory->target->actor ||
	    !directory->virtual || !directory->virtual->source_name)
		return KASUMI_FILLDIR_CONTINUE;
	visible_path = directory->virtual->source_name;
	if (namlen == 1 && name[0] == '.') {
		visible_ino = kasumi_vnode_source_ino(
			directory->virtual->target_dev, ino);
	} else if (namlen == 2 && name[0] == '.' && name[1] == '.') {
		visible_ino = kasumi_vnode_source_ino(
			directory->virtual->target_dev, ino);
	} else {
		if (!strcmp(visible_path, "/"))
			length = scnprintf(directory->child_path,
					   sizeof(directory->child_path),
					   "/%.*s", namlen, name);
		else
			length = scnprintf(directory->child_path,
					   sizeof(directory->child_path),
					   "%s/%.*s", visible_path,
					   namlen, name);
		if (length <= 0 ||
		    length >= (int)sizeof(directory->child_path))
			return KASUMI_FILLDIR_CONTINUE;
		if (kasumi_should_hide(directory->child_path))
			return KASUMI_FILLDIR_CONTINUE;
		visible_ino = kasumi_vnode_source_ino(
			directory->virtual->target_dev, ino);
	}
	return directory->target->actor(directory->target, name, namlen,
					offset, visible_ino, d_type);
}

static int KASUMI_NOCFI
kasumi_virtual_iterate_common(struct file *file, struct dir_context *ctx,
			      bool shared)
{
	struct kasumi_virtual_file *virtual = file ? file->private_data : NULL;
	struct kasumi_virtual_dir_context *directory;
	struct file *real_file;
	int ret = -ENOTDIR;

	if (!virtual || !virtual->directory || !ctx || !ctx->actor)
		return -ENOTDIR;
	real_file = READ_ONCE(virtual->real_file);
	if (!real_file || !real_file->f_op)
		return -EBADF;
	directory = kzalloc(sizeof(*directory), GFP_KERNEL);
	if (!directory)
		return -ENOMEM;
	directory->ctx.actor = kasumi_virtual_dir_actor;
	directory->ctx.pos = ctx->pos;
	directory->target = ctx;
	directory->virtual = virtual;
	WRITE_ONCE(real_file->f_pos, READ_ONCE(file->f_pos));
	if (shared && real_file->f_op->iterate_shared)
		ret = real_file->f_op->iterate_shared(real_file, &directory->ctx);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
	else if (!shared && real_file->f_op->iterate)
		ret = real_file->f_op->iterate(real_file, &directory->ctx);
#endif
	if (ret >= 0)
		atomic64_inc(&kasumi_virtual_dir_iterated_count);
	ctx->pos = directory->ctx.pos;
	WRITE_ONCE(real_file->f_pos, directory->ctx.pos);
	kfree(directory);
	return ret;
}

static int kasumi_virtual_iterate_shared(struct file *file,
					 struct dir_context *ctx)
{
	return kasumi_virtual_iterate_common(file, ctx, true);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
static int kasumi_virtual_iterate(struct file *file, struct dir_context *ctx)
{
	return kasumi_virtual_iterate_common(file, ctx, false);
}
#endif

static const struct file_operations kasumi_virtual_fops = {
	.owner = THIS_MODULE,
	.llseek = kasumi_virtual_llseek,
	.read = kasumi_virtual_read,
	.write = kasumi_virtual_write,
	.read_iter = kasumi_virtual_read_iter,
	.write_iter = kasumi_virtual_write_iter,
	.iterate_shared = kasumi_virtual_iterate_shared,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
	.iterate = kasumi_virtual_iterate,
#endif
	.mmap = kasumi_virtual_mmap,
	.get_unmapped_area = kasumi_virtual_get_unmapped_area,
	.unlocked_ioctl = kasumi_virtual_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = kasumi_virtual_compat_ioctl,
#endif
	.poll = kasumi_virtual_poll,
	.flush = kasumi_virtual_flush,
	.fsync = kasumi_virtual_fsync,
	.fasync = kasumi_virtual_fasync,
	.splice_read = kasumi_virtual_splice_read,
	.splice_write = kasumi_virtual_splice_write,
	.release = kasumi_virtual_release,
};

static bool kasumi_virtual_flags_supported(int flags)
{
	int rejected = O_CREAT | O_EXCL | O_TRUNC;

	if (flags & O_PATH) {
		int allowed = O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC;

		return !(flags & ~allowed);
	}

#ifdef __O_TMPFILE
	/* O_TMPFILE also contains O_DIRECTORY, so testing the composite value as
	 * a bit mask rejects every ordinary directory open.  Reject only the
	 * private tmpfile selector bit here. */
	rejected |= __O_TMPFILE;
#endif
	return !(flags & rejected);
}

static int kasumi_virtual_open_path_only(const char *visible_path,
					 const struct path *source_path,
					 const struct kstat *source_stat,
					 unsigned long visible_ino,
					 unsigned long visible_dev,
					 bool preserve_visible_metadata,
					 int flags, bool *handled)
{
	struct kasumi_virtual_file *virtual;
	struct inode *source_inode;
	struct file *file;
	int fd;

	source_inode = source_path && source_path->dentry ?
		d_inode(source_path->dentry) : NULL;
	if (!source_inode)
		return 0;
	if ((flags & O_DIRECTORY) && !S_ISDIR(source_inode->i_mode)) {
		*handled = true;
		return -ENOTDIR;
	}
	virtual = kzalloc(sizeof(*virtual), GFP_KERNEL);
	if (!virtual) {
		*handled = true;
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&virtual->node);
	INIT_LIST_HEAD(&virtual->mappings);
	mutex_init(&virtual->io_lock);
	mutex_init(&virtual->mmap_lock);
	virtual->fops = kasumi_virtual_fops;
	virtual->regular = S_ISREG(source_inode->i_mode);
	virtual->directory = S_ISDIR(source_inode->i_mode);
	virtual->target_ino = source_inode->i_ino;
	virtual->target_dev = source_inode->i_sb ? source_inode->i_sb->s_dev : 0;
	virtual->source_ino = visible_ino ?: virtual->target_ino;
	virtual->source_dev = visible_dev ?: virtual->target_dev;
	if (source_stat) {
		virtual->visible_stat = *source_stat;
		virtual->visible_stat.ino = virtual->source_ino;
		virtual->visible_stat.dev = virtual->source_dev;
		virtual->visible_stat_valid = true;
	}
	virtual->preserve_visible_metadata = preserve_visible_metadata;
	virtual->tgid = task_tgid_vnr(current);
	kasumi_virtual_pin_source(virtual, source_path);
	virtual->source_name = kstrdup(visible_path, GFP_KERNEL);
	if (!virtual->source_name) {
		kasumi_virtual_drop_source(virtual);
		kfree(virtual);
		*handled = true;
		return -ENOMEM;
	}
	file = anon_inode_getfile("kasumi-path", &virtual->fops, virtual,
				  O_RDONLY);
	if (IS_ERR(file)) {
		fd = PTR_ERR(file);
		kasumi_virtual_drop_source(virtual);
		kfree(virtual->source_name);
		kfree(virtual);
		*handled = true;
		return fd;
	}
	if ((file->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
		i_readcount_dec(file_inode(file));
	WRITE_ONCE(file->f_mode, FMODE_PATH | FMODE_OPENED);
	WRITE_ONCE(file->f_flags, flags);
	if (!kasumi_virtual_adopt_path(file, source_path)) {
		fput(file);
		*handled = true;
		return -EIO;
	}
	virtual->path_dentry = file->f_path.dentry;
	virtual->path_mnt = file->f_path.mnt;
	if (!kasumi_virtual_track(virtual)) {
		fput(file);
		*handled = true;
		return -ESHUTDOWN;
	}
	fd = get_unused_fd_flags(flags & O_CLOEXEC);
	if (fd < 0) {
		fput(file);
		*handled = true;
		return fd;
	}
	fd_install(fd, file);
	*handled = true;
	atomic64_inc(&kasumi_virtual_file_opened_count);
	kasumi_log("virtual open: %s -> vnode fd=%d mode=O_PATH\n",
		   visible_path, fd);
	return fd;
}

static int KASUMI_NOCFI
kasumi_virtual_open_path(const char *visible_path,
			 const struct path *source_path,
			 const struct kstat *source_stat,
			 unsigned long visible_ino,
			 unsigned long visible_dev,
			 bool preserve_visible_metadata,
			 int flags, bool *handled)
{
	struct kasumi_virtual_file *virtual;
	struct inode *source_inode;
	struct file *real_file;
	struct file *file;
	bool regular;
	bool directory;
	bool anon_read_open;
	int fd;
	int ret;

	if (!visible_path || !source_path || !source_path->dentry ||
	    !source_path->mnt)
		return 0;
	source_inode = d_inode(source_path->dentry);
	/* Sockets cannot be opened as ordinary files. Their O_PATH form is handled
	 * separately without invoking the protocol-specific open path. */
	if (!source_inode ||
	    (!S_ISREG(source_inode->i_mode) && !S_ISDIR(source_inode->i_mode) &&
	     !S_ISCHR(source_inode->i_mode) && !S_ISFIFO(source_inode->i_mode) &&
	     !S_ISBLK(source_inode->i_mode)))
		return 0;
	if (S_ISREG(source_inode->i_mode) &&
	    (!kasumi_shmem_file_setup || !kasumi_kernel_read ||
	     !kasumi_kernel_write))
		return 0;
	regular = S_ISREG(source_inode->i_mode);
	directory = S_ISDIR(source_inode->i_mode);
	if (!source_inode->i_fop)
		return 0;

	real_file = kasumi_dentry_open(source_path, flags & ~O_CLOEXEC,
					       current_cred());
	if (IS_ERR(real_file)) {
		*handled = true;
		return PTR_ERR(real_file);
	}

	virtual = kzalloc(sizeof(*virtual), GFP_KERNEL);
	if (!virtual) {
		fput(real_file);
		*handled = true;
		return -ENOMEM;
	}
	if (S_ISCHR(source_inode->i_mode) && source_inode->i_cdev) {
		if (!kasumi_cdev_put_ptr) {
			fput(real_file);
			kfree(virtual);
			return 0;
		}
		if (!kasumi_virtual_cdev_get(source_inode->i_cdev)) {
			fput(real_file);
			kfree(virtual);
			return 0;
		}
		virtual->cdev = source_inode->i_cdev;
		virtual->extra_cdev_ref = true;
	}
	INIT_LIST_HEAD(&virtual->node);
	INIT_LIST_HEAD(&virtual->mappings);
	virtual->mapping_count = 0;
	mutex_init(&virtual->io_lock);
	mutex_init(&virtual->mmap_lock);
	virtual->fops = kasumi_virtual_fops;
	virtual->real_file = real_file;
	virtual->regular = regular;
	virtual->directory = directory;
	/* Keep the wrapper's dispatch shape aligned with the target.  In
	 * particular, a number of character drivers implement only ->read or
	 * ->write, and vfs_read/vfs_write prefer the iterator slots when present.
	 */
	if (!real_file->f_op->read_iter)
		virtual->fops.read_iter = NULL;
	if (!real_file->f_op->write_iter)
		virtual->fops.write_iter = NULL;
	if (!directory || !real_file->f_op->iterate_shared)
		virtual->fops.iterate_shared = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
	if (!directory || !real_file->f_op->iterate)
		virtual->fops.iterate = NULL;
#endif
	if (!regular) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
		virtual->fops.fop_flags = real_file->f_op->fop_flags;
#else
		virtual->fops.mmap_supported_flags =
			real_file->f_op->mmap_supported_flags;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
		if (real_file->f_op->mmap_prepare) {
			/* The 6.16 VFS treats ->mmap and ->mmap_prepare as mutually
			 * exclusive hooks.  The descriptor callback routes directly to
			 * real_file, so do not leave the legacy wrapper installed too. */
			virtual->fops.mmap = NULL;
			virtual->fops.mmap_prepare = kasumi_virtual_mmap_prepare;
		}
#endif
	}
	virtual->target_ino = source_inode->i_ino;
	virtual->target_dev = source_inode->i_sb ? source_inode->i_sb->s_dev : 0;
	virtual->source_ino = virtual->target_ino;
	virtual->source_dev = virtual->target_dev;
	if (source_stat) {
		virtual->visible_stat = *source_stat;
		virtual->visible_stat_valid = true;
	}
	if (visible_ino)
		virtual->source_ino = visible_ino;
	if (visible_dev)
		virtual->source_dev = visible_dev;
	if (virtual->visible_stat_valid) {
		virtual->visible_stat.ino = virtual->source_ino;
		virtual->visible_stat.dev = virtual->source_dev;
	}
	virtual->preserve_visible_metadata = preserve_visible_metadata;
	virtual->tgid = task_tgid_vnr(current);
	kasumi_virtual_pin_source(virtual, source_path);
	virtual->source_name = kstrdup(visible_path, GFP_KERNEL);
	if (!virtual->source_name) {
		ret = -ENOMEM;
		goto err_virtual;
	}
	file = anon_inode_getfile("kasumi-virtual", &virtual->fops,
					 virtual, flags & ~O_CLOEXEC);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto err_virtual;
	}
	anon_read_open =
		(file->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ;
	/* anon_inode_getfile() only derives OPEN_FMODE from access flags.  Copy
	 * the target capabilities so vfs_read/vfs_write and ioctl helpers retain
	 * FMODE_CAN_{READ,WRITE}, seek and pread/pwrite semantics.  The writer and
	 * unmount bits own target-side references; real_file already owns them, so
	 * leave those bits exclusively on the real file. */
	{
		fmode_t mode_copy = READ_ONCE(real_file->f_mode);

		mode_copy &= ~(FMODE_WRITER | FMODE_NEED_UNMOUNT);
		WRITE_ONCE(file->f_mode, mode_copy);
	}
	WRITE_ONCE(file->f_flags, READ_ONCE(real_file->f_flags));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	WRITE_ONCE(file->f_iocb_flags, READ_ONCE(real_file->f_iocb_flags));
#endif
	if (!virtual->regular)
		WRITE_ONCE(file->f_mapping, READ_ONCE(real_file->f_mapping));
	/* A char-device inode carries a cdev reference that __fput() drops.  The
	 * extra cdev reference acquired above makes the target inode safe to adopt;
	 * regular files likewise need the target inode because mmap_region() reads
	 * its size before entering our snapshot path.  mmap() and all driver
	 * callbacks receive real_file explicitly. */
	if (!kasumi_virtual_adopt_real_file(file, real_file, anon_read_open,
						true)) {
		if (virtual->extra_cdev_ref) {
			kasumi_cdev_put(virtual->cdev);
			virtual->extra_cdev_ref = false;
		}
		fput(file);
		*handled = true;
		return -EIO;
	}
	virtual->path_dentry = file->f_path.dentry;
	virtual->path_mnt = file->f_path.mnt;
	if (!kasumi_virtual_track(virtual)) {
		fput(file);
		*handled = true;
		return -ESHUTDOWN;
	}

	fd = get_unused_fd_flags(flags & O_CLOEXEC);
	if (fd < 0) {
		fput(file);
		*handled = true;
		return fd;
	}
	fd_install(fd, file);
	*handled = true;
	atomic64_inc(&kasumi_virtual_file_opened_count);
	kasumi_log("virtual open: %s -> captured-source fd=%d mode=%s\n",
		   visible_path, fd,
		   virtual->regular ? "shmem" :
		   virtual->directory ? "directory" : "target");
	return fd;

err_virtual:
	kasumi_virtual_drop_source(virtual);
	kfree(virtual->source_name);
	if (virtual->extra_cdev_ref)
		kasumi_cdev_put(virtual->cdev);
	fput(real_file);
	kfree(virtual);
	*handled = true;
	return ret;
}

int KASUMI_NOCFI kasumi_virtual_reopen_fd(const char *visible_path,
					  unsigned int source_fd, int flags,
					  bool *handled)
{
	struct kstat source_stat;
	struct path source_path;
	struct file *source_file;
	struct inode *source_inode;
	bool opened = false;
	int reopen_flags;
	int ret;

	if (!handled)
		return -EINVAL;
	*handled = false;
	if (!visible_path || !kasumi_vfs_getattr)
		return -EOPNOTSUPP;
	source_file = fget_raw(source_fd);
	if (!source_file)
		return -EBADF;
	source_path = source_file->f_path;
	kasumi_path_get(&source_path);
	source_inode = file_inode(source_file);
	fput(source_file);
	if (!source_inode) {
		kasumi_path_put(&source_path);
		return -ENOENT;
	}
	memset(&source_stat, 0, sizeof(source_stat));
	ret = kasumi_vfs_getattr_unprojected(&source_path, &source_stat,
				 STATX_BASIC_STATS | STATX_BTIME,
				 AT_STATX_SYNC_AS_STAT);
	if (ret) {
		kasumi_path_put(&source_path);
		return ret;
	}
	reopen_flags = flags & ~(O_CREAT | O_EXCL | O_TRUNC);
	ret = kasumi_virtual_open_path(
		visible_path, &source_path, &source_stat,
		kasumi_vnode_source_ino(
			source_inode->i_sb ? source_inode->i_sb->s_dev : 0,
			source_inode->i_ino),
		kasumi_vnode_device(), false, reopen_flags, &opened);
	kasumi_path_put(&source_path);
	*handled = opened;
	return opened ? ret : -EOPNOTSUPP;
}

static int KASUMI_NOCFI kasumi_virtual_open_entry_fd_flags_access(
	const char *visible_path, int flags, umode_t mode,
	unsigned int lookup_flags, int requested_access, bool *handled)
{
	struct kasumi_rule_source source = {};
	bool opened = false;
	int ret;

	(void)mode;
	if (!handled)
		return -EINVAL;
	*handled = false;
	if (!visible_path || !kasumi_path_get_ptr || !kasumi_path_put_ptr)
		return 0;
	if (!kasumi_rule_get_source_flags(visible_path, lookup_flags, &source)) {
		if (source.error) {
			*handled = true;
			return source.error;
		}
		return 0;
	}
	if (!source.stat_valid || (!(flags & O_PATH) &&
	    !S_ISREG(source.source_mode) && !S_ISDIR(source.source_mode) &&
	    !S_ISCHR(source.source_mode) && !S_ISFIFO(source.source_mode) &&
	    !S_ISBLK(source.source_mode) && !S_ISLNK(source.source_mode))) {
		*handled = true;
		kasumi_path_put(&source.path);
		return -EOPNOTSUPP;
	}
	*handled = true;
	if (S_ISLNK(source.source_mode) && !(flags & O_PATH)) {
		kasumi_path_put(&source.path);
		return -ELOOP;
	}
	if (!READ_ONCE(kasumi_virtual_files_param)) {
		kasumi_path_put(&source.path);
		return -EOPNOTSUPP;
	}
	if (atomic_read(&kasumi_virtual_file_shutdown_state)) {
		kasumi_path_put(&source.path);
		return -ESHUTDOWN;
	}
	if (!kasumi_dentry_open) {
		kasumi_path_put(&source.path);
		return -EOPNOTSUPP;
	}
	if ((flags & O_PATH) &&
	    (flags & ~(O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC))) {
		kasumi_path_put(&source.path);
		return -EINVAL;
	}
	if ((flags & O_DIRECTORY) && !S_ISDIR(source.source_mode)) {
		kasumi_path_put(&source.path);
		return -ENOTDIR;
	}
	if (!kasumi_virtual_flags_supported(flags)) {
		kasumi_path_put(&source.path);
		kasumi_log("virtual open: %s unsupported flags=0x%x\n",
			   visible_path, flags);
		return -EOPNOTSUPP;
	}
	if (!(flags & O_PATH)) {
		if (requested_access < 0) {
			switch (flags & O_ACCMODE) {
			case O_WRONLY:
				requested_access = MAY_WRITE;
				break;
			case O_RDWR:
				requested_access = MAY_READ | MAY_WRITE;
				break;
			case O_RDONLY:
				requested_access = MAY_READ;
				break;
			default:
				requested_access = MAY_READ | MAY_WRITE;
				break;
			}
		}
		ret = kasumi_visible_open_access(&source.stat,
						 requested_access);
		if (ret) {
			kasumi_path_put(&source.path);
			return ret;
		}
	}
	if (flags & O_PATH) {
		ret = kasumi_virtual_open_path_only(
			visible_path, &source.path, &source.stat,
			source.visible_ino, source.visible_dev,
			source.preserve_visible_metadata, flags, &opened);
		kasumi_path_put(&source.path);
		if (!opened)
			ret = -EOPNOTSUPP;
		return ret;
	}

	ret = kasumi_virtual_open_path(visible_path, &source.path, &source.stat,
				       source.visible_ino, source.visible_dev,
				       source.preserve_visible_metadata,
				       flags, &opened);
	kasumi_path_put(&source.path);
	if (!opened) {
		ret = -EOPNOTSUPP;
		kasumi_log("virtual open: %s captured type unsupported\n",
			   visible_path);
	}
	return ret;
}

int KASUMI_NOCFI kasumi_virtual_open_entry_fd_flags(
	const char *visible_path, int flags, umode_t mode,
	unsigned int lookup_flags, bool *handled)
{
	return kasumi_virtual_open_entry_fd_flags_access(
		visible_path, flags, mode, lookup_flags, -1, handled);
}

int kasumi_virtual_open_exec_fd(const char *visible_path, int flags,
				bool *handled)
{
	unsigned int lookup_flags =
		(flags & O_NOFOLLOW) ? 0 : LOOKUP_FOLLOW;

	return kasumi_virtual_open_entry_fd_flags_access(
		visible_path, flags, 0, lookup_flags, MAY_EXEC, handled);
}

int kasumi_virtual_open_entry_fd(const char *visible_path, int flags,
				 umode_t mode, bool *handled)
{
	unsigned int lookup_flags =
		(flags & O_NOFOLLOW) ? 0 : LOOKUP_FOLLOW;

	return kasumi_virtual_open_entry_fd_flags(visible_path, flags, mode,
						 lookup_flags, handled);
}

bool kasumi_virtual_entry_matches(const char *visible_path)
{
	struct kasumi_rule_source source = {};
	bool matched;

	if (!visible_path || !kasumi_path_get_ptr || !kasumi_path_put_ptr ||
	    !kasumi_rule_get_source(visible_path, &source))
		return false;
	matched = source.stat_valid &&
		(S_ISREG(source.source_mode) || S_ISDIR(source.source_mode) ||
		 S_ISCHR(source.source_mode));
	kasumi_path_put(&source.path);
	return matched;
}

void kasumi_virtual_file_stop_new(void)
{
	atomic_set(&kasumi_virtual_file_shutdown_state, 1);
}

unsigned int kasumi_virtual_file_live(void)
{
	return (unsigned int)atomic_read(&kasumi_virtual_file_live_count);
}

u64 kasumi_virtual_file_open_count(void)
{
	return (u64)atomic64_read(&kasumi_virtual_file_opened_count);
}

u64 kasumi_virtual_dir_iterate_count(void)
{
	return (u64)atomic64_read(&kasumi_virtual_dir_iterated_count);
}

void kasumi_virtual_file_shutdown(void)
{
	kasumi_virtual_file_stop_new();
	kasumi_virtual_exec_aliases_shutdown();
	WARN_ON_ONCE(atomic_read(&kasumi_virtual_file_live_count) ||
			     !list_empty(&kasumi_virtual_file_list));
}
