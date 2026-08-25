/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - shared runtime state, rule stores, and common cleanup helpers.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && !defined(arch_ftrace_get_regs)
#define arch_ftrace_get_regs(fregs) (NULL)
#endif
#include <linux/kprobes.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/jhash.h>
#include <linux/kdev_t.h>
#include <linux/hashtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/sched/task.h>
#include <linux/fs_struct.h>
#include <linux/dirent.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/anon_inodes.h>
#include <linux/fcntl.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#include <linux/seq_file.h>
#include <uapi/linux/magic.h>

#include "kasumi_runtime.h"
#include "kasumi_store.h"
#include "kasumi_path_policy.h"
#include "kasumi_task_marker.h"
#include "kasumi_tracepoint_hooks.h"
#include "kasumi_fop_override.h"

bool kasumi_enabled;
atomic_t kasumi_rule_count = ATOMIC_INIT(0);
atomic_t kasumi_hide_count = ATOMIC_INIT(0);
atomic_t kasumi_tsr_path_count = ATOMIC_INIT(0);
struct kasumi_hook_stats kasumi_hook_stats;

#define KASUMI_INTERNAL_VFS_HASH_BITS 5

struct kasumi_internal_vfs_guard {
	struct task_struct *task;
	struct hlist_node node;
};

static DEFINE_HASHTABLE(kasumi_internal_vfs_tasks,
			KASUMI_INTERNAL_VFS_HASH_BITS);
static DEFINE_SPINLOCK(kasumi_internal_vfs_lock);

bool kasumi_vfs_internal_current(void)
{
	struct kasumi_internal_vfs_guard *guard;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(&kasumi_internal_vfs_lock, flags);
	hash_for_each_possible(kasumi_internal_vfs_tasks, guard, node,
			       (unsigned long)current) {
		if (guard->task == current) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&kasumi_internal_vfs_lock, flags);
	return found;
}

int KASUMI_NOCFI kasumi_vfs_getattr_unprojected(
	const struct path *path, struct kstat *stat, u32 request_mask,
	unsigned int query_flags)
{
	struct kasumi_internal_vfs_guard guard = { .task = current };
	unsigned long flags;
	int ret;

	if (!kasumi_vfs_getattr)
		return -EOPNOTSUPP;
	/* Internal source inspection must not be fed back through Kasumi's own
	 * legacy kstat projection.  A stack-backed, lock-protected task marker is
	 * safe across sleeping filesystem getattr implementations and nests. */
	spin_lock_irqsave(&kasumi_internal_vfs_lock, flags);
	hash_add(kasumi_internal_vfs_tasks, &guard.node,
		 (unsigned long)current);
	spin_unlock_irqrestore(&kasumi_internal_vfs_lock, flags);
	ret = kasumi_vfs_getattr(path, stat, request_mask, query_flags);
	spin_lock_irqsave(&kasumi_internal_vfs_lock, flags);
	hash_del(&guard.node);
	spin_unlock_irqrestore(&kasumi_internal_vfs_lock, flags);
	return ret;
}

/* Metadata-only device namespace for virtual nodes.  No real superblock is
 * registered: pathname hooks, virtual descriptors and proc projections all
 * publish this identity from the rule snapshot. */
#define KASUMI_VNODE_MINOR 0x4b5
static atomic64_t kasumi_vnode_allocated_count = ATOMIC64_INIT(0);
static atomic_t kasumi_vnode_live_count = ATOMIC_INIT(0);

unsigned long kasumi_vnode_path_ino(const char *path)
{
	u64 ino;
	size_t len;

	if (!path || !*path)
		return 1;
	len = strlen(path);
	ino = ((u64)jhash(path, (u32)len, 0x4b617375) << 32) |
		jhash(path, (u32)len, 0x6d695646);
	ino |= 1ULL << 63;
	return (unsigned long)ino;
}

unsigned long kasumi_vnode_source_ino(dev_t source_dev, u64 source_ino)
{
	u64 dev = (u64)source_dev;
	u32 words[4] = {
		(u32)dev,
		(u32)(dev >> 32),
		(u32)source_ino,
		(u32)(source_ino >> 32),
	};
	u64 ino;

	ino = ((u64)jhash2(words, ARRAY_SIZE(words), 0x4b617375) << 32) |
		jhash2(words, ARRAY_SIZE(words), 0x6d695646);
	ino |= 1ULL << 63;
	return (unsigned long)ino;
}

dev_t kasumi_vnode_device(void)
{
	return MKDEV(0, KASUMI_VNODE_MINOR);
}

u64 kasumi_vnode_allocated(void)
{
	return (u64)atomic64_read(&kasumi_vnode_allocated_count);
}

unsigned int kasumi_vnode_live(void)
{
	return (unsigned int)atomic_read(&kasumi_vnode_live_count);
}

struct kasumi_percpu *kasumi_percpu_base;
char *kasumi_iterate_buf_base;

atomic_long_t kasumi_ioctl_tgid = ATOMIC_LONG_INIT(0);
atomic_long_t kasumi_xattr_source_tgid = ATOMIC_LONG_INIT(0);

struct kmem_cache *kasumi_filldir_cache;

unsigned long (*kasumi_kallsyms_lookup_name)(const char *name);

DEFINE_HASHTABLE(kasumi_paths, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_targets, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_hide_paths, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_inject_dirs, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_xattr_sbs, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_merge_dirs, KASUMI_HASH_BITS);

DEFINE_HASHTABLE(kasumi_spoof_kstat_path, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_spoof_kstat_ino, KASUMI_HASH_BITS);
atomic_t kasumi_spoof_kstat_count = ATOMIC_INIT(0);

DEFINE_MUTEX(kasumi_config_mutex);
LIST_HEAD(kasumi_maps_rules);
DEFINE_MUTEX(kasumi_maps_mutex);

kasumi_ksu_uid_should_umount_fn kasumi_ksu_uid_should_umount_ptr;

bool kasumi_debug_enabled;
bool kasumi_stealth_enabled;

struct kasumi_cmdline_rcu __rcu *kasumi_spoof_cmdline_ptr;
bool kasumi_cmdline_spoof_active;

pid_t kasumi_daemon_pid;

int kasumi_cmdline_kprobe_registered;
int kasumi_getxattr_kprobe_registered;
int kasumi_mount_hide_vfsmnt_registered;
int kasumi_mount_hide_mountinfo_registered;
int kasumi_proc_proxy_registered;
int kasumi_proc_ns_readlink_registered;
int kasumi_feature_enabled_mask;
int kasumi_mount_hide_mode = KSM_MOUNT_HIDE_MODE_NORMAL;
int kasumi_statfs_kretprobe_registered;
int kasumi_reboot_kprobe_registered;
bool kasumi_vfs_use_ftrace;

DECLARE_BITMAP(kasumi_path_bloom, KASUMI_BLOOM_SIZE);
DECLARE_BITMAP(kasumi_hide_bloom, KASUMI_BLOOM_SIZE);

dev_t kasumi_system_dev;

int (*kasumi_kern_path)(const char *, unsigned int, struct path *);
int (*kasumi_vfs_getattr)(const struct path *, struct kstat *, u32, unsigned int);
struct file *(*kasumi_dentry_open)(const struct path *, int, const struct cred *);
char *(*kasumi_d_absolute_path)(const struct path *, char *, int);
char *(*kasumi_dentry_path_raw)(const struct dentry *, char *, int);
char *(*kasumi_d_path)(const struct path *, char *, int);
struct dentry *(*kasumi_d_hash_and_lookup)(struct dentry *, const struct qstr *);
void *kasumi_vfs_getxattr_addr;
void *kasumi_vfs_listxattr_addr;
void *kasumi_vfs_setxattr_addr;
void *kasumi_vfs_removexattr_addr;
void *kasumi_mnt_want_write_addr;
void *kasumi_mnt_drop_write_addr;
int (*kasumi_vfs_path_lookup)(struct dentry *, struct vfsmount *,
			      const char *, unsigned int, struct path *);
const char *(*kasumi_vfs_get_link)(struct dentry *, struct delayed_call *);
void (*kasumi_path_get_ptr)(const struct path *);
void (*kasumi_path_put_ptr)(const struct path *);
void (*kasumi_free_inode_nonrcu_ptr)(struct inode *);
struct file *(*kasumi_filp_open)(const char *, int, umode_t);
int (*kasumi_filp_close)(struct file *, fl_owner_t);
ssize_t (*kasumi_kernel_read)(struct file *, void *, size_t, loff_t *);
ssize_t (*kasumi_kernel_write)(struct file *, const void *, size_t, loff_t *);
void (*kasumi_cdev_put_ptr)(struct cdev *);
struct file *(*kasumi_shmem_file_setup)(const char *, loff_t, unsigned long);
ssize_t (*kasumi_vfs_copy_file_range)(struct file *, loff_t,
					      struct file *, loff_t,
					      size_t, unsigned int);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
unsigned long (*kasumi_mm_get_unmapped_area_ptr)(struct mm_struct *,
							 struct file *, unsigned long,
							 unsigned long, unsigned long,
							 unsigned long);
#endif
char *(*kasumi_strndup_user)(const char __user *, long);
void (*kasumi_ihold)(struct inode *);
long (*kasumi_strncpy_from_user_nofault)(char *dst, const void __user *src, long count);
long (*kasumi_copy_from_user_nofault)(void *dst, const void __user *src, size_t size);
long (*kasumi_copy_to_user_nofault)(void __user *dst, const void *src, size_t size);
int (*kasumi_task_work_add_ptr)(struct task_struct *task,
				struct callback_head *work,
				enum task_work_notify_mode notify);
struct llist_node *(*kasumi_llist_del_first_ptr)(struct llist_head *head);
ssize_t (*kasumi_seq_read_iter_ptr)(struct kiocb *iocb,
				    struct iov_iter *iter);
void (*kasumi_call_srcu_ptr)(struct srcu_struct *ssp, struct rcu_head *rhp,
			     rcu_callback_t func);
void (*kasumi_srcu_barrier_ptr)(struct srcu_struct *ssp);
void (*kasumi_synchronize_rcu_tasks_ptr)(void);
int (*kasumi_module_refcount_ptr)(struct module *module);

/* Avoid a load-time dependency on a GKI-trimmed export. */
noinline KASUMI_NOCFI struct llist_node *
kasumi_llist_del_first(struct llist_head *head)
{
	return kasumi_llist_del_first_ptr(head);
}

noinline KASUMI_NOCFI ssize_t kasumi_seq_read_iter(
	struct kiocb *iocb, struct iov_iter *iter)
{
	if (!kasumi_seq_read_iter_ptr)
		return -EOPNOTSUPP;
	return kasumi_seq_read_iter_ptr(iocb, iter);
}

noinline KASUMI_NOCFI void kasumi_synchronize_rcu_tasks(void)
{
	kasumi_synchronize_rcu_tasks_ptr();
}

noinline KASUMI_NOCFI int kasumi_module_refcount(struct module *module)
{
	return kasumi_module_refcount_ptr(module);
}

noinline KASUMI_NOCFI ssize_t kasumi_copy_file_range(
	struct file *file_in, loff_t pos_in, struct file *file_out,
	loff_t pos_out, size_t len, unsigned int flags)
{
	if (!kasumi_vfs_copy_file_range)
		return -EOPNOTSUPP;
	return kasumi_vfs_copy_file_range(file_in, pos_in, file_out, pos_out,
					  len, flags);
}

noinline KASUMI_NOCFI void kasumi_cdev_put(struct cdev *cdev)
{
	if (kasumi_cdev_put_ptr && cdev)
		kasumi_cdev_put_ptr(cdev);
}

bool kasumi_valid_kernel_addr(unsigned long addr)
{
	if (!addr)
		return false;
	if (IS_ERR_VALUE(addr))
		return false;
#if defined(CONFIG_64BIT)
	return (addr & (1UL << 63)) != 0;
#else
	return addr >= PAGE_OFFSET;
#endif
}

KASUMI_NOCFI unsigned long kasumi_lookup_name(const char *name)
{
	if (kasumi_kallsyms_lookup_name) {
		unsigned long addr = kasumi_kallsyms_lookup_name(name);

		if (addr && !IS_ERR_VALUE(addr))
			return addr;
	}

	{
		struct kprobe kp = { .symbol_name = name };
		unsigned long addr;
		int ret;

		ret = register_kprobe(&kp);
		if (ret < 0) {
			pr_alert("Kasumi: kprobe %s failed: %d\n", name, ret);
			return 0;
		}
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
		if (!addr || IS_ERR_VALUE(addr)) {
			pr_alert("Kasumi: symbol %s returned invalid addr 0x%lx\n", name, addr);
			return 0;
		}
		return addr;
	}
}

/*
 * Resolve a kernel symbol that Kasumi will CALL through a function pointer.
 *
 * On old jump-table CFI kernels (android12-5.10 .. android14-5.15) the only
 * valid indirect-call target for an address-taken function is its
 * "<name>.cfi_jt" thunk; calling the raw function body faults under strict
 * (non-permissive) CFI. Prefer the thunk; fall back to the raw symbol for
 * kCFI kernels (6.1+, where the raw addr is callable) and for functions with
 * no thunk (the raw addr is then the canonical entry).
 *
 * CAVEAT: depends on the ".cfi_jt" locals being present in kallsyms
 * (CONFIG_KALLSYMS_ALL). Not robust where they are stripped AND the target is
 * a non-exported, address-taken function: there is then no thunk to resolve
 * and no direct call available. For EXPORTED symbols prefer a direct call.
 */
KASUMI_NOCFI unsigned long kasumi_lookup_callable(const char *name)
{
	if (kasumi_kallsyms_lookup_name) {
		char jt[256];
		unsigned long addr;

		if (snprintf(jt, sizeof(jt), "%s.cfi_jt", name) < (int)sizeof(jt)) {
			addr = kasumi_kallsyms_lookup_name(jt);
			if (addr && !IS_ERR_VALUE(addr))
				return addr;
		}
	}
	return kasumi_lookup_name(name);
}

KASUMI_NOCFI unsigned long kasumi_lookup_name_quiet(const char *name)
{
	if (kasumi_kallsyms_lookup_name) {
		unsigned long addr = kasumi_kallsyms_lookup_name(name);

		if (addr && !IS_ERR_VALUE(addr))
			return addr;
	}

	{
		struct kprobe kp = { .symbol_name = name };
		unsigned long addr;
		int ret;

		ret = register_kprobe(&kp);
		if (ret < 0)
			return 0;
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
		if (!addr || IS_ERR_VALUE(addr))
			return 0;
		return addr;
	}
}

/* Quiet variant of kasumi_lookup_callable (no error log on miss). See kasumi_lookup_callable. */
KASUMI_NOCFI unsigned long kasumi_lookup_callable_quiet(const char *name)
{
	if (kasumi_kallsyms_lookup_name) {
		char jt[256];
		unsigned long addr;

		if (snprintf(jt, sizeof(jt), "%s.cfi_jt", name) < (int)sizeof(jt)) {
			addr = kasumi_kallsyms_lookup_name(jt);
			if (addr && !IS_ERR_VALUE(addr))
				return addr;
		}
	}
	return kasumi_lookup_name_quiet(name);
}

void kasumi_resolve_kallsyms_lookup(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	int ret;

	pr_alert("Kasumi: resolving kallsyms_lookup_name...\n");
	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_alert("Kasumi: kprobe kallsyms_lookup_name failed: %d, using per-symbol kprobe\n",
			 ret);
		return;
	}
	if (!kasumi_valid_kernel_addr((unsigned long)kp.addr)) {
		pr_alert("Kasumi: kallsyms_lookup_name returned invalid address: 0x%lx\n",
			 (unsigned long)kp.addr);
		unregister_kprobe(&kp);
		return;
	}
	kasumi_kallsyms_lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);
	pr_alert("Kasumi: kallsyms_lookup_name resolved @ 0x%lx\n",
		 (unsigned long)kasumi_kallsyms_lookup_name);
}

int KASUMI_NOCFI kasumi_entry_capture_source(struct kasumi_entry *entry,
					     const char *source_path)
{
	struct path nofollow_path;
	struct inode *nofollow_inode;
	struct kstat visible_kstat;
	struct path visible_path;
	struct inode *visible_inode;
	struct inode *inode;
	struct path path;
	int ret;

	if (!entry || !source_path || !*source_path)
		return -EINVAL;
	if (entry->source_path_valid)
		return -EALREADY;
	if (!kasumi_kern_path || !kasumi_path_get_ptr || !kasumi_path_put_ptr)
		return -EOPNOTSUPP;

	ret = kasumi_kern_path(source_path, LOOKUP_FOLLOW, &path);
	if (ret)
		return ret;
	inode = d_inode(path.dentry);
	if (!inode) {
		kasumi_path_put(&path);
		return -ENOENT;
	}

	entry->source_path = path;
	kasumi_path_get(&entry->source_path);
	if (kasumi_d_absolute_path) {
		char *buffer = kmalloc(KSM_MAX_LEN_PATHNAME, GFP_KERNEL);

		if (buffer) {
			char *canonical = kasumi_d_absolute_path(
				&path, buffer, KSM_MAX_LEN_PATHNAME);

			if (!IS_ERR_OR_NULL(canonical) && canonical[0] == '/')
				entry->source_canonical = kstrdup(canonical,
								   GFP_KERNEL);
			kfree(buffer);
		}
	}
	entry->source_inode = inode;
	entry->source_ino = inode->i_ino;
	entry->source_dev = inode->i_sb ? inode->i_sb->s_dev : 0;
	entry->source_mode = inode->i_mode;
	entry->source_uid = inode->i_uid;
	entry->source_gid = inode->i_gid;
	entry->source_size = i_size_read(inode);
	memset(&entry->source_stat, 0, sizeof(entry->source_stat));
	if (kasumi_vfs_getattr &&
	    kasumi_vfs_getattr_unprojected(&path, &entry->source_stat,
			       STATX_BASIC_STATS | STATX_BTIME,
			       AT_STATX_SYNC_AS_STAT) == 0) {
		entry->source_stat_valid = true;
	} else {
		entry->source_stat.result_mask =
			STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_UID |
			STATX_GID | STATX_INO | STATX_SIZE | STATX_BLOCKS;
		entry->source_stat.dev = entry->source_dev;
		entry->source_stat.ino = entry->source_ino;
		entry->source_stat.mode = entry->source_mode;
		entry->source_stat.nlink = inode->i_nlink;
		entry->source_stat.uid = entry->source_uid;
		entry->source_stat.gid = entry->source_gid;
		entry->source_stat.rdev = inode->i_rdev;
		entry->source_stat.size = entry->source_size;
		entry->source_stat.blocks = inode->i_blocks;
		entry->source_stat.blksize = 1U << inode->i_blkbits;
		entry->source_stat_valid = true;
	}
	entry->visible_stat = entry->source_stat;
	entry->visible_stat_valid = entry->source_stat_valid;

	/* Preserve inode identity across rename and hard links without publishing
	 * the captured filesystem's raw dev/ino pair. */
	entry->visible_ino = kasumi_vnode_source_ino(entry->source_dev,
						    entry->source_ino);
	entry->visible_dev = kasumi_vnode_device();
	if (entry->src &&
	    kasumi_kern_path(entry->src, LOOKUP_FOLLOW, &visible_path) == 0) {
		visible_inode = d_inode(visible_path.dentry);
		if (visible_inode) {
			entry->preserve_visible_metadata = true;
			memset(&visible_kstat, 0, sizeof(visible_kstat));
			if (kasumi_vfs_getattr &&
			    kasumi_vfs_getattr_unprojected(&visible_path,
						     &visible_kstat,
					       STATX_BASIC_STATS | STATX_BTIME,
					       AT_STATX_SYNC_AS_STAT) == 0) {
				entry->visible_stat = visible_kstat;
				/* The virtual node lives at the visible path, but its data
				 * and file kind come from the captured source. Keep visible
				 * ownership, permissions and timestamps while publishing the
				 * source type, size and backing allocation semantics. */
				entry->visible_stat.mode =
					(entry->source_stat.mode & S_IFMT) |
					(visible_kstat.mode & ~S_IFMT);
				entry->visible_stat.rdev = entry->source_stat.rdev;
				entry->visible_stat.size = entry->source_stat.size;
				entry->visible_stat.blocks = entry->source_stat.blocks;
				entry->visible_stat.blksize = entry->source_stat.blksize;
				entry->visible_stat.result_mask |=
					entry->source_stat.result_mask &
					(STATX_TYPE | STATX_MODE | STATX_SIZE |
					 STATX_BLOCKS);
				entry->visible_stat_valid = true;
			} else {
				entry->visible_stat.mode =
					(entry->source_stat.mode & S_IFMT) |
					(visible_inode->i_mode & ~S_IFMT);
				entry->visible_stat.nlink = visible_inode->i_nlink;
				entry->visible_stat.uid = visible_inode->i_uid;
				entry->visible_stat.gid = visible_inode->i_gid;
			}
		}
		kasumi_path_put(&visible_path);
	}
	entry->visible_stat.ino = entry->visible_ino;
	entry->visible_stat.dev = entry->visible_dev;
	if (kasumi_kern_path(source_path, 0, &nofollow_path) == 0) {
		nofollow_inode = d_inode(nofollow_path.dentry);
		if (nofollow_inode && S_ISLNK(nofollow_inode->i_mode)) {
			entry->source_nofollow_path = nofollow_path;
			kasumi_path_get(&entry->source_nofollow_path);
			entry->source_nofollow_mode = nofollow_inode->i_mode;
			memset(&entry->source_nofollow_stat, 0,
			       sizeof(entry->source_nofollow_stat));
			if (kasumi_vfs_getattr &&
			    kasumi_vfs_getattr_unprojected(&nofollow_path,
					       &entry->source_nofollow_stat,
					       STATX_BASIC_STATS | STATX_BTIME,
					       AT_STATX_SYNC_AS_STAT) == 0) {
				entry->source_nofollow_stat_valid = true;
			} else {
				entry->source_nofollow_stat.result_mask =
					STATX_TYPE | STATX_MODE | STATX_NLINK |
					STATX_UID | STATX_GID | STATX_INO |
					STATX_SIZE | STATX_BLOCKS;
				entry->source_nofollow_stat.dev =
					nofollow_inode->i_sb ?
					nofollow_inode->i_sb->s_dev : 0;
				entry->source_nofollow_stat.ino =
					nofollow_inode->i_ino;
				entry->source_nofollow_stat.mode =
					nofollow_inode->i_mode;
				entry->source_nofollow_stat.nlink =
					nofollow_inode->i_nlink;
				entry->source_nofollow_stat.uid =
					nofollow_inode->i_uid;
				entry->source_nofollow_stat.gid =
					nofollow_inode->i_gid;
				entry->source_nofollow_stat.size =
					i_size_read(nofollow_inode);
				entry->source_nofollow_stat.blocks =
					nofollow_inode->i_blocks;
				entry->source_nofollow_stat.blksize =
					1U << nofollow_inode->i_blkbits;
				entry->source_nofollow_stat_valid = true;
			}
			entry->nofollow_visible_ino = kasumi_vnode_source_ino(
				nofollow_inode->i_sb ? nofollow_inode->i_sb->s_dev : 0,
				nofollow_inode->i_ino);
			entry->nofollow_visible_dev = kasumi_vnode_device();
			entry->source_nofollow_stat.ino =
				entry->nofollow_visible_ino;
			entry->source_nofollow_stat.dev =
				entry->nofollow_visible_dev;
			entry->source_nofollow_path_valid = true;
		}
		kasumi_path_put(&nofollow_path);
	}
	entry->source_path_valid = true;
	atomic64_inc(&kasumi_vnode_allocated_count);
	atomic_inc(&kasumi_vnode_live_count);
	kasumi_path_put(&path);
	return 0;
}

void KASUMI_NOCFI kasumi_entry_release_source(struct kasumi_entry *entry)
{
	if (!entry || !entry->source_path_valid)
		return;

	entry->source_path_valid = false;
	atomic_dec(&kasumi_vnode_live_count);
	kasumi_path_put(&entry->source_path);
	memset(&entry->source_path, 0, sizeof(entry->source_path));
	if (entry->source_nofollow_path_valid) {
		entry->source_nofollow_path_valid = false;
		kasumi_path_put(&entry->source_nofollow_path);
		memset(&entry->source_nofollow_path, 0,
		       sizeof(entry->source_nofollow_path));
	}
	entry->source_inode = NULL;
}

void kasumi_entry_free_rcu(struct rcu_head *head)
{
	struct kasumi_entry *e = container_of(head, struct kasumi_entry, rcu);

	kasumi_entry_release_source(e);
	kfree(e->src);
	kfree(e->target);
	kfree(e->source_canonical);
	kfree(e);
}

void kasumi_hide_entry_free_rcu(struct rcu_head *head)
{
	struct kasumi_hide_entry *e = container_of(head, struct kasumi_hide_entry, rcu);

	kfree(e->path);
	kfree(e);
}

void kasumi_inject_entry_free_rcu(struct rcu_head *head)
{
	struct kasumi_inject_entry *e = container_of(head, struct kasumi_inject_entry, rcu);

	kfree(e->dir);
	kfree(e);
}

void kasumi_xattr_sb_entry_free_rcu(struct rcu_head *head)
{
	struct kasumi_xattr_sb_entry *e = container_of(head, struct kasumi_xattr_sb_entry, rcu);

	kfree(e);
}

void kasumi_merge_entry_free_rcu(struct rcu_head *head)
{
	struct kasumi_merge_entry *e = container_of(head, struct kasumi_merge_entry, rcu);

	if (e->target_dentry)
		dput(e->target_dentry);
	kfree(e->src);
	kfree(e->target);
	kfree(e->resolved_src);
	kfree(e);
}

void kasumi_spoof_kstat_entry_free_rcu(struct rcu_head *head)
{
	struct kasumi_spoof_kstat_entry *e =
		container_of(head, struct kasumi_spoof_kstat_entry, rcu);

	kfree(e->target_pathname);
	kfree(e);
}

struct kasumi_spoof_kstat_entry *kasumi_spoof_kstat_lookup_by_path(const char *path_str)
{
	struct kasumi_spoof_kstat_entry *e;
	u32 hash;

	if (!path_str || !*path_str)
		return NULL;
	hash = full_name_hash(NULL, path_str, strlen(path_str));
	hlist_for_each_entry_rcu(e,
		&kasumi_spoof_kstat_path[hash_min(hash, KASUMI_HASH_BITS)], path_node) {
		if (e->path_hash == hash && e->target_pathname &&
		    strcmp(e->target_pathname, path_str) == 0)
			return e;
	}
	return NULL;
}

struct kasumi_spoof_kstat_entry *kasumi_spoof_kstat_lookup_by_ino(unsigned long ino,
								unsigned long dev)
{
	struct kasumi_spoof_kstat_entry *e;

	if (!ino)
		return NULL;
	hlist_for_each_entry_rcu(e,
		&kasumi_spoof_kstat_ino[hash_min(ino, KASUMI_HASH_BITS)], ino_node) {
		if (e->target_ino == ino &&
		    (e->target_dev == 0 || dev == 0 || e->target_dev == dev))
			return e;
	}
	return NULL;
}

void kasumi_mark_inode_hidden(struct inode *inode)
{
	if (inode && inode->i_mapping)
		set_bit(AS_FLAGS_KASUMI_HIDE, &inode->i_mapping->flags);
}

bool kasumi_is_inode_hidden_bit(struct inode *inode)
{
	if (!inode || !inode->i_mapping)
		return false;
	return test_bit(AS_FLAGS_KASUMI_HIDE, &inode->i_mapping->flags);
}

void kasumi_mark_dir_has_inject(const char *path_str)
{
	struct path p;

	if (!path_str || !kasumi_kern_path)
		return;
	if (kasumi_kern_path(path_str, LOOKUP_FOLLOW, &p) != 0)
		return;
	if (p.dentry && d_inode(p.dentry) && d_inode(p.dentry)->i_mapping) {
		struct inode *inode = d_inode(p.dentry);

		set_bit(AS_FLAGS_KASUMI_DIR_HAS_INJECT, &inode->i_mapping->flags);
		(void)kasumi_fop_install(inode);
	}
	kasumi_path_put(&p);
}

void kasumi_clear_inode_flags_for_path(const char *path_str, unsigned int bit)
{
	struct path p;

	if (!path_str || !kasumi_kern_path)
		return;
	if (kasumi_kern_path(path_str, LOOKUP_FOLLOW, &p) != 0)
		return;
	if (p.dentry && d_inode(p.dentry) && d_inode(p.dentry)->i_mapping)
		clear_bit(bit, &d_inode(p.dentry)->i_mapping->flags);
	kasumi_path_put(&p);
}

void kasumi_cleanup_locked(void)
{
	struct kasumi_entry *entry;
	struct kasumi_hide_entry *hide_entry;
	struct kasumi_inject_entry *inject_entry;
	struct kasumi_xattr_sb_entry *sb_entry;
	struct kasumi_merge_entry *merge_entry;
	struct hlist_node *tmp;
	int bkt;

	/* Pair with policy readers before cleanup withdraws provider state. */
	smp_store_release(&kasumi_enabled, false);
	kasumi_task_marker_set_enabled(false);
	(void)kasumi_tracepoint_hooks_set_enabled(false);
	kasumi_stealth_enabled = false;
	kasumi_feature_enabled_mask = 0;
	kasumi_mount_hide_mode = KSM_MOUNT_HIDE_MODE_NORMAL;
	/* Stop provider calls and release any external module reference. */
	kasumi_policy_disable_provider_locked();

	hash_for_each_safe(kasumi_paths, bkt, tmp, entry, node) {
		kasumi_clear_inode_flags_for_path(entry->src, AS_FLAGS_KASUMI_HIDE);
		kasumi_clear_inode_flags_for_path(entry->target, AS_FLAGS_KASUMI_SPOOF_KSTAT);
		hlist_del_rcu(&entry->node);
		hlist_del_rcu(&entry->target_node);
		call_rcu(&entry->rcu, kasumi_entry_free_rcu);
	}
	hash_for_each_safe(kasumi_hide_paths, bkt, tmp, hide_entry, node) {
		kasumi_clear_inode_flags_for_path(hide_entry->path, AS_FLAGS_KASUMI_HIDE);
		hlist_del_rcu(&hide_entry->node);
		call_rcu(&hide_entry->rcu, kasumi_hide_entry_free_rcu);
	}
	hash_for_each_safe(kasumi_inject_dirs, bkt, tmp, inject_entry, node) {
		kasumi_clear_inode_flags_for_path(inject_entry->dir, AS_FLAGS_KASUMI_DIR_HAS_INJECT);
		hlist_del_rcu(&inject_entry->node);
		call_rcu(&inject_entry->rcu, kasumi_inject_entry_free_rcu);
	}
	hash_for_each_safe(kasumi_xattr_sbs, bkt, tmp, sb_entry, node) {
		hlist_del_rcu(&sb_entry->node);
		call_rcu(&sb_entry->rcu, kasumi_xattr_sb_entry_free_rcu);
	}
	hash_for_each_safe(kasumi_merge_dirs, bkt, tmp, merge_entry, node) {
		hlist_del_rcu(&merge_entry->node);
		call_rcu(&merge_entry->rcu, kasumi_merge_entry_free_rcu);
	}
	{
		struct kasumi_spoof_kstat_entry *sk_entry;

		hash_for_each_safe(kasumi_spoof_kstat_path, bkt, tmp, sk_entry, path_node) {
			kasumi_clear_inode_flags_for_path(sk_entry->target_pathname,
							AS_FLAGS_KASUMI_SPOOF_KSTAT);
			hlist_del_rcu(&sk_entry->path_node);
			if (sk_entry->target_ino)
				hlist_del_rcu(&sk_entry->ino_node);
			call_rcu(&sk_entry->rcu, kasumi_spoof_kstat_entry_free_rcu);
		}
		hash_for_each_safe(kasumi_spoof_kstat_ino, bkt, tmp, sk_entry, ino_node) {
			hlist_del_rcu(&sk_entry->ino_node);
			call_rcu(&sk_entry->rcu, kasumi_spoof_kstat_entry_free_rcu);
		}
		atomic_set(&kasumi_spoof_kstat_count, 0);
	}

	bitmap_zero(kasumi_path_bloom, KASUMI_BLOOM_SIZE);
	bitmap_zero(kasumi_hide_bloom, KASUMI_BLOOM_SIZE);
	atomic_set(&kasumi_rule_count, 0);
	atomic_set(&kasumi_hide_count, 0);
	atomic_set(&kasumi_tsr_path_count, 0);
}
