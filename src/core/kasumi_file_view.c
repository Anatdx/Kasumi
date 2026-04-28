/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - per-file virtual view identity tracking.
 *
 * This is intentionally a projection layer, not a fake file layer.  The real
 * struct file remains responsible for page cache, mmap faults, writeback, and
 * driver vm_ops; Kasumi records the virtual source identity opened through a
 * redirect so later read paths such as /proc/pid/maps can present that view.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/atomic.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/string.h>

#include "kasumi_base.h"
#include "kasumi_file_view.h"
#include "kasumi_runtime.h"

#define KASUMI_FILE_VIEW_HASH_BITS 10

#define KASUMI_FILE_VIEW_STATE_OPEN      0
#define KASUMI_FILE_VIEW_STATE_DRAINED   1
#define KASUMI_FILE_VIEW_STATE_RELEASING 2

struct kasumi_file_view {
	struct file *file;
	const struct file_operations *orig_fops;
	struct file_operations shadow_fops;
	char *src_path;
	char *target_path;
	unsigned long target_ino;
	unsigned long target_dev;
	unsigned long spoofed_ino;
	unsigned long spoofed_dev;
	pid_t tgid;
	struct hlist_node file_node;
	struct hlist_node ino_node;
	struct list_head list;
	atomic_t state;
	struct rcu_head rcu;
};

static DEFINE_HASHTABLE(kasumi_file_view_by_file, KASUMI_FILE_VIEW_HASH_BITS);
static DEFINE_HASHTABLE(kasumi_file_view_by_ino, KASUMI_FILE_VIEW_HASH_BITS);
static DEFINE_SPINLOCK(kasumi_file_view_lock);
static LIST_HEAD(kasumi_file_view_list);
DEFINE_STATIC_SRCU(kasumi_file_view_srcu);
static atomic_t kasumi_file_view_shutdown_state = ATOMIC_INIT(0);

static unsigned long kasumi_file_view_ino_key(unsigned long ino, unsigned long dev)
{
	return ino ^ (dev << 16) ^ (dev >> 16);
}

static struct kasumi_file_view *kasumi_file_view_lookup_file_locked(struct file *file)
{
	struct kasumi_file_view *view;

	hash_for_each_possible(kasumi_file_view_by_file, view, file_node,
			       (unsigned long)file) {
		if (view->file == file)
			return view;
	}
	return NULL;
}

static void kasumi_file_view_remove_locked(struct kasumi_file_view *view)
{
	if (!hlist_unhashed(&view->file_node))
		hlist_del_init_rcu(&view->file_node);
	if (!hlist_unhashed(&view->ino_node))
		hlist_del_init_rcu(&view->ino_node);
	if (!list_empty(&view->list))
		list_del_init(&view->list);
}

static void kasumi_file_view_free_rcu(struct rcu_head *rcu)
{
	struct kasumi_file_view *view =
		container_of(rcu, struct kasumi_file_view, rcu);

	kfree(view->src_path);
	kfree(view->target_path);
	kfree(view);
}

static void kasumi_file_view_fill_source_stat(struct kasumi_file_view *view,
					      const char *src_path)
{
	struct path src = {};
	struct inode *inode;

	view->spoofed_ino = view->target_ino;
	view->spoofed_dev = view->target_dev;

	if (!src_path || !kasumi_kern_path)
		return;
	if (kasumi_kern_path(src_path, LOOKUP_FOLLOW, &src) != 0)
		return;
	if (!src.dentry)
		goto out;

	inode = d_inode(src.dentry);
	if (!inode || !inode->i_sb)
		goto out;

	view->spoofed_ino = inode->i_ino;
	view->spoofed_dev = inode->i_sb->s_dev;

out:
	if (src.dentry && src.mnt)
		path_put(&src);
}

static int kasumi_file_view_release(struct inode *inode, struct file *file)
{
	struct kasumi_file_view *view =
		container_of(file->f_op, struct kasumi_file_view, shadow_fops);
	int prev;
	bool owned;
	int ret = 0;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&kasumi_file_view_srcu);

	prev = atomic_cmpxchg(&view->state, KASUMI_FILE_VIEW_STATE_OPEN,
			      KASUMI_FILE_VIEW_STATE_RELEASING);
	owned = prev == KASUMI_FILE_VIEW_STATE_OPEN;
	if (owned) {
		spin_lock(&kasumi_file_view_lock);
		kasumi_file_view_remove_locked(view);
		WRITE_ONCE(file->f_op, view->orig_fops);
		spin_unlock(&kasumi_file_view_lock);
	}

	if (view->orig_fops->release)
		ret = view->orig_fops->release(inode, file);

	srcu_read_unlock(&kasumi_file_view_srcu, srcu_idx);

	if (owned)
		call_rcu(&view->rcu, kasumi_file_view_free_rcu);

	return ret;
}

int kasumi_file_view_bind_fd(int fd, const char *src_path, const char *target_path)
{
	struct kasumi_file_view *view;
	struct file *file;
	struct inode *inode;
	const struct file_operations *new_fops;
	unsigned long ino_key;
	int ret = 0;

	if (atomic_read(&kasumi_file_view_shutdown_state))
		return -ESHUTDOWN;
	if (!src_path || !target_path)
		return -EINVAL;

	file = fget(fd);
	if (!file)
		return -EBADF;
	if (!file->f_op) {
		ret = -EINVAL;
		goto out;
	}
	if (file->f_op->release == kasumi_file_view_release)
		goto out;

	inode = file_inode(file);
	if (!inode || !inode->i_sb) {
		ret = -EINVAL;
		goto out;
	}

	view = kzalloc(sizeof(*view), GFP_KERNEL);
	if (!view) {
		ret = -ENOMEM;
		goto out;
	}

	view->src_path = kstrdup(src_path, GFP_KERNEL);
	view->target_path = kstrdup(target_path, GFP_KERNEL);
	if (!view->src_path || !view->target_path) {
		ret = -ENOMEM;
		goto err_free;
	}

	view->file = file;
	view->orig_fops = file->f_op;
	view->shadow_fops = *file->f_op;
	view->shadow_fops.owner = NULL;
	view->shadow_fops.release = kasumi_file_view_release;
	view->target_ino = inode->i_ino;
	view->target_dev = inode->i_sb->s_dev;
	view->tgid = task_tgid_vnr(current);
	kasumi_file_view_fill_source_stat(view, src_path);
	INIT_HLIST_NODE(&view->file_node);
	INIT_HLIST_NODE(&view->ino_node);
	INIT_LIST_HEAD(&view->list);
	atomic_set(&view->state, KASUMI_FILE_VIEW_STATE_OPEN);

	spin_lock(&kasumi_file_view_lock);
	if (atomic_read(&kasumi_file_view_shutdown_state)) {
		spin_unlock(&kasumi_file_view_lock);
		ret = -ESHUTDOWN;
		goto err_free;
	}
	if (kasumi_file_view_lookup_file_locked(file)) {
		spin_unlock(&kasumi_file_view_lock);
		goto err_free_success;
	}
	if (READ_ONCE(file->f_op) != view->orig_fops) {
		spin_unlock(&kasumi_file_view_lock);
		ret = -EAGAIN;
		goto err_free;
	}

	new_fops = fops_get(&view->shadow_fops);
	if (!new_fops) {
		spin_unlock(&kasumi_file_view_lock);
		ret = -ENOENT;
		goto err_free;
	}

	ino_key = kasumi_file_view_ino_key(view->target_ino, view->target_dev);
	hash_add_rcu(kasumi_file_view_by_file, &view->file_node,
		     (unsigned long)file);
	hash_add_rcu(kasumi_file_view_by_ino, &view->ino_node, ino_key);
	list_add(&view->list, &kasumi_file_view_list);
	WRITE_ONCE(file->f_op, new_fops);
	spin_unlock(&kasumi_file_view_lock);

	kasumi_log("file_view: fd=%d %s -> %s real=%lu/%lu spoof=%lu/%lu\n",
		   fd, src_path, target_path, view->target_dev, view->target_ino,
		   view->spoofed_dev, view->spoofed_ino);

out:
	fput(file);
	return ret;

err_free_success:
	ret = 0;
err_free:
	kfree(view->src_path);
	kfree(view->target_path);
	kfree(view);
	goto out;
}

bool kasumi_file_view_lookup_maps(unsigned long target_ino, unsigned long target_dev,
				  unsigned long *spoofed_ino,
				  unsigned long *spoofed_dev,
				  char *spoofed_pathname,
				  size_t spoofed_pathname_size)
{
	struct kasumi_file_view *view;
	unsigned long key;
	pid_t tgid = task_tgid_vnr(current);
	bool found = false;

	if (!target_ino || !spoofed_ino || !spoofed_dev ||
	    !spoofed_pathname || spoofed_pathname_size == 0)
		return false;

	key = kasumi_file_view_ino_key(target_ino, target_dev);

	rcu_read_lock();
	hash_for_each_possible_rcu(kasumi_file_view_by_ino, view, ino_node, key) {
		if (view->target_ino != target_ino)
			continue;
		if (target_dev && view->target_dev != target_dev)
			continue;
		if (view->tgid != tgid)
			continue;
		*spoofed_ino = view->spoofed_ino;
		*spoofed_dev = view->spoofed_dev;
		strscpy(spoofed_pathname, view->src_path, spoofed_pathname_size);
		found = true;
		break;
	}
	rcu_read_unlock();

	return found;
}

static void kasumi_file_view_drain(bool shutdown)
{
	struct kasumi_file_view *view, *tmp;
	LIST_HEAD(victims);

	if (shutdown)
		atomic_set(&kasumi_file_view_shutdown_state, 1);

	spin_lock(&kasumi_file_view_lock);
	list_for_each_entry_safe(view, tmp, &kasumi_file_view_list, list) {
		if (atomic_cmpxchg(&view->state, KASUMI_FILE_VIEW_STATE_OPEN,
				    KASUMI_FILE_VIEW_STATE_DRAINED) !=
		    KASUMI_FILE_VIEW_STATE_OPEN)
			continue;
		kasumi_file_view_remove_locked(view);
		WRITE_ONCE(view->file->f_op, view->orig_fops);
		list_add(&view->list, &victims);
	}
	spin_unlock(&kasumi_file_view_lock);

	synchronize_srcu(&kasumi_file_view_srcu);

	list_for_each_entry_safe(view, tmp, &victims, list) {
		list_del_init(&view->list);
		call_rcu(&view->rcu, kasumi_file_view_free_rcu);
	}
}

void kasumi_file_view_clear(void)
{
	kasumi_file_view_drain(false);
}

void kasumi_file_view_shutdown(void)
{
	kasumi_file_view_drain(true);
	synchronize_rcu();
	rcu_barrier();
}
