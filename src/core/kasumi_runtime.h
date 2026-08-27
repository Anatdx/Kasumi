/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - runtime globals, resolved kernel symbols, and feature flags.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_RUNTIME_H
#define _KASUMI_RUNTIME_H

#include "kasumi_base.h"

#include <linux/anon_inodes.h>
#include <linux/bitmap.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/kprobes.h>
#include <linux/limits.h>
#include <linux/llist.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/smp.h>
#include <linux/srcu.h>
#include <linux/stat.h>
#include <linux/task_work.h>
#include <linux/vmalloc.h>

#include "kasumi_base.h"
#include "kasumi_types.h"

extern bool kasumi_enabled;
extern atomic_t kasumi_rule_count;
extern atomic_t kasumi_hide_count;
extern atomic_t kasumi_spoof_kstat_count;

struct kasumi_hook_stats {
	atomic64_t vfs_getattr_entries;
	atomic64_t vfs_getattr_spoofs;
	atomic64_t iop_getattr_entries;
	atomic64_t iop_getattr_spoofs;
	atomic64_t d_path_entries;
	atomic64_t d_path_rewrites;
	atomic64_t dop_dname_entries;
	atomic64_t xattr_sid_overrides;
	atomic64_t iterate_entries;
	atomic64_t iterate_wrapped;
	atomic64_t iterate_fop_entries;
	atomic64_t iterate_fop_wrapped;
	atomic64_t sop_destroy_inode;
	atomic64_t filldir_hidden;
	atomic64_t filldir_injected;
	atomic64_t getxattr_entries;
	atomic64_t getxattr_spoofs;
	atomic64_t selinuxfs_access_queries;
	atomic64_t selinuxfs_access_spoofs;
	atomic64_t selinuxfs_access_seqno_spoofs;
	atomic64_t selinuxfs_context_queries;
	atomic64_t selinuxfs_context_spoofs;
	atomic64_t selinuxfs_status_spoofs;
};

extern struct kasumi_hook_stats kasumi_hook_stats;

struct kasumi_percpu {
	int iterate_did_swap;
	int in_populate_inject;
};

extern struct kasumi_percpu *kasumi_percpu_base;

static inline struct kasumi_percpu *kasumi_this_cpu(void)
{
	return kasumi_percpu_base + smp_processor_id();
}

extern char *kasumi_iterate_buf_base;
extern atomic_long_t kasumi_ioctl_tgid;
extern atomic_long_t kasumi_xattr_source_tgid;
extern struct kmem_cache *kasumi_filldir_cache;
extern unsigned long (*kasumi_kallsyms_lookup_name)(const char *name);

bool kasumi_valid_kernel_addr(unsigned long addr);
unsigned long kasumi_lookup_name(const char *name);
unsigned long kasumi_lookup_name_quiet(const char *name);
unsigned long kasumi_lookup_callable(const char *name);
unsigned long kasumi_lookup_callable_quiet(const char *name);
void kasumi_resolve_kallsyms_lookup(void);
dev_t kasumi_vnode_device(void);
unsigned long kasumi_vnode_path_ino(const char *path);
unsigned long kasumi_vnode_source_ino(dev_t source_dev, u64 source_ino);
unsigned long kasumi_vnode_vpath_ino(const char *vpath);
unsigned long kasumi_vnode_ino_alloc(dev_t src_dev, u64 src_ino);
dev_t kasumi_vnode_visible_dev(const char *visible_path);
u64 kasumi_vnode_allocated(void);
unsigned int kasumi_vnode_live(void);

typedef bool (*kasumi_ksu_uid_should_umount_fn)(uid_t uid);

extern kasumi_ksu_uid_should_umount_fn kasumi_ksu_uid_should_umount_ptr;

extern bool kasumi_stealth_enabled;

extern pid_t kasumi_daemon_pid;

extern int kasumi_getxattr_kprobe_registered;
extern int kasumi_mount_hide_vfsmnt_registered;
extern int kasumi_mount_hide_mountinfo_registered;
extern int kasumi_proc_proxy_registered;
extern int kasumi_proc_ns_readlink_registered;
extern int kasumi_feature_enabled_mask;
extern int kasumi_mount_hide_mode;
extern int kasumi_statfs_kretprobe_registered;
extern int kasumi_fscap_kretprobe_registered;
extern int kasumi_fscaps_enabled;
extern int kasumi_device_sources_enabled;
extern int kasumi_reboot_kprobe_registered;
extern bool kasumi_vfs_use_ftrace;
extern dev_t kasumi_system_dev;

extern int (*kasumi_kern_path)(const char *, unsigned int, struct path *);
extern int (*kasumi_vfs_getattr)(const struct path *, struct kstat *, u32, unsigned int);
/* notify_change first arg (idmap/userns) varies across kernel versions. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
extern int (*kasumi_notify_change)(struct mnt_idmap *, struct dentry *,
				   struct iattr *, struct inode **);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
extern int (*kasumi_notify_change)(struct user_namespace *, struct dentry *,
				   struct iattr *, struct inode **);
#else
extern int (*kasumi_notify_change)(struct dentry *, struct iattr *,
				   struct inode **);
#endif
int kasumi_vfs_getattr_unprojected(const struct path *path,
				   struct kstat *stat, u32 request_mask,
				   unsigned int query_flags);
bool kasumi_vfs_internal_current(void);
/*
 * Resolved get_vfs_caps_from_disk (security/commoncap.c).  Its leading
 * idmap/user_namespace argument varies by version exactly like notify_change;
 * absent (NULL) simply disables source-file-capability forwarding.  Use the
 * kasumi_source_vfs_caps() wrapper, which supplies the source mount's idmap.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
extern int (*kasumi_get_vfs_caps_from_disk)(struct mnt_idmap *,
					    const struct dentry *,
					    struct cpu_vfs_cap_data *);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
extern int (*kasumi_get_vfs_caps_from_disk)(struct user_namespace *,
					    const struct dentry *,
					    struct cpu_vfs_cap_data *);
#else
extern int (*kasumi_get_vfs_caps_from_disk)(const struct dentry *,
					    struct cpu_vfs_cap_data *);
#endif
int kasumi_source_vfs_caps(const struct path *src,
			   struct cpu_vfs_cap_data *out);
extern struct file *(*kasumi_dentry_open)(const struct path *, int, const struct cred *);
/* Data-plane delegates for a char/blk/fifo source wrapper's special fops.
 * Stable signatures across all supported KMIs; NULL disables special read/write
 * (the op returns -EINVAL). */
extern ssize_t (*kasumi_vfs_read)(struct file *, char __user *, size_t, loff_t *);
extern ssize_t (*kasumi_vfs_write)(struct file *, const char __user *, size_t,
				   loff_t *);
extern char *(*kasumi_d_absolute_path)(const struct path *, char *, int);
extern char *(*kasumi_dentry_path_raw)(const struct dentry *, char *, int);
extern char *(*kasumi_d_path)(const struct path *, char *, int);
extern struct dentry *(*kasumi_d_hash_and_lookup)(struct dentry *, const struct qstr *);
extern void *kasumi_vfs_getxattr_addr;
extern void *kasumi_vfs_listxattr_addr;
extern void *kasumi_vfs_setxattr_addr;
extern void *kasumi_vfs_removexattr_addr;
extern void *kasumi_mnt_want_write_addr;
extern void *kasumi_mnt_drop_write_addr;
extern int (*kasumi_vfs_path_lookup)(struct dentry *, struct vfsmount *,
				     const char *, unsigned int, struct path *);
extern const char *(*kasumi_vfs_get_link)(struct dentry *,
					  struct delayed_call *);
/*
 * Directory-mutation delegates (Final Phase 1b): a directory-source vnode's
 * i_op create family forwards to these against the pinned source dir.  Their
 * leading idmap/user_namespace argument varies by version exactly like
 * notify_change; vfs_link takes the idmap as its SECOND argument.  Any may be
 * NULL (resolved quietly) — the vnode op returns -EOPNOTSUPP then.
 * lookup_one_len manufactures the source-side child dentry (caller holds the
 * source dir i_rwsem); its signature is stable across all supported KMIs.
 */
extern struct dentry *(*kasumi_lookup_one_len)(const char *, struct dentry *, int);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
extern int (*kasumi_vfs_create)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, bool);
extern int (*kasumi_vfs_mkdir)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t);
extern int (*kasumi_vfs_mknod)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, dev_t);
extern int (*kasumi_vfs_symlink)(struct mnt_idmap *, struct inode *, struct dentry *, const char *);
extern int (*kasumi_vfs_unlink)(struct mnt_idmap *, struct inode *, struct dentry *, struct inode **);
extern int (*kasumi_vfs_rmdir)(struct mnt_idmap *, struct inode *, struct dentry *);
extern int (*kasumi_vfs_link)(struct dentry *, struct mnt_idmap *, struct inode *, struct dentry *, struct inode **);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
extern int (*kasumi_vfs_create)(struct user_namespace *, struct inode *, struct dentry *, umode_t, bool);
extern int (*kasumi_vfs_mkdir)(struct user_namespace *, struct inode *, struct dentry *, umode_t);
extern int (*kasumi_vfs_mknod)(struct user_namespace *, struct inode *, struct dentry *, umode_t, dev_t);
extern int (*kasumi_vfs_symlink)(struct user_namespace *, struct inode *, struct dentry *, const char *);
extern int (*kasumi_vfs_unlink)(struct user_namespace *, struct inode *, struct dentry *, struct inode **);
extern int (*kasumi_vfs_rmdir)(struct user_namespace *, struct inode *, struct dentry *);
extern int (*kasumi_vfs_link)(struct dentry *, struct user_namespace *, struct inode *, struct dentry *, struct inode **);
#else
extern int (*kasumi_vfs_create)(struct inode *, struct dentry *, umode_t, bool);
extern int (*kasumi_vfs_mkdir)(struct inode *, struct dentry *, umode_t);
extern int (*kasumi_vfs_mknod)(struct inode *, struct dentry *, umode_t, dev_t);
extern int (*kasumi_vfs_symlink)(struct inode *, struct dentry *, const char *);
extern int (*kasumi_vfs_unlink)(struct inode *, struct dentry *, struct inode **);
extern int (*kasumi_vfs_rmdir)(struct inode *, struct dentry *);
extern int (*kasumi_vfs_link)(struct dentry *, struct inode *, struct dentry *, struct inode **);
#endif
/*
 * vfs_rename took a flat argument list before 5.12 and a struct renamedata (from
 * the kernel's fs.h; the idmap/userns member differs by era but is set by name)
 * from 5.12 on.  Only the pointer shape is version-guarded here (Final 1c).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
extern int (*kasumi_vfs_rename)(struct renamedata *);
#else
extern int (*kasumi_vfs_rename)(struct inode *, struct dentry *, struct inode *, struct dentry *, struct inode **, unsigned int);
#endif
/* Public LSM secctx round-trip: copy a source inode's security context onto a
 * synthetic vnode's in-core SID without touching SELinux blob internals.  Both
 * may be NULL when the LSM/symbols are unavailable — callers must check. */
extern int (*kasumi_security_inode_getsecctx)(struct inode *, void **, u32 *);
extern int (*kasumi_security_inode_notifysecctx)(struct inode *, void *, u32);
extern void (*kasumi_security_release_secctx)(char *, u32);
extern void (*kasumi_path_get_ptr)(const struct path *);
extern void (*kasumi_path_put_ptr)(const struct path *);
extern void (*kasumi_free_inode_nonrcu_ptr)(struct inode *);
extern struct file *(*kasumi_filp_open)(const char *, int, umode_t);
extern int (*kasumi_filp_close)(struct file *, fl_owner_t);
extern char *(*kasumi_strndup_user)(const char __user *, long);
extern void (*kasumi_ihold)(struct inode *);
extern long (*kasumi_strncpy_from_user_nofault)(char *dst, const void __user *src, long count);
extern long (*kasumi_copy_from_user_nofault)(void *dst, const void __user *src, size_t size);
extern long (*kasumi_copy_to_user_nofault)(void __user *dst, const void *src, size_t size);
extern int (*kasumi_task_work_add_ptr)(struct task_struct *task,
				       struct callback_head *work,
				       enum task_work_notify_mode notify);
extern struct llist_node *(*kasumi_llist_del_first_ptr)(
	struct llist_head *head);
struct llist_node *kasumi_llist_del_first(struct llist_head *head);
extern ssize_t (*kasumi_seq_read_iter_ptr)(struct kiocb *iocb,
					   struct iov_iter *iter);
ssize_t kasumi_seq_read_iter(struct kiocb *iocb, struct iov_iter *iter);
extern void (*kasumi_call_srcu_ptr)(struct srcu_struct *ssp, struct rcu_head *rhp,
				    rcu_callback_t func);
extern void (*kasumi_srcu_barrier_ptr)(struct srcu_struct *ssp);
extern void (*kasumi_synchronize_rcu_tasks_ptr)(void);
void kasumi_synchronize_rcu_tasks(void);
extern int (*kasumi_module_refcount_ptr)(struct module *module);
int kasumi_module_refcount(struct module *module);

/* KASUMI_NOCFI: these call kallsyms-resolved pointers (path_get/path_put).
 * Whether a kernel build emits a .cfi_jt thunk for those symbols varies per
 * build (e.g. present on some Qualcomm 5.15, absent on some Meizu), so
 * kasumi_lookup_callable may hand back the RAW body address. Calling it from
 * CFI-instrumented code is a fatal CFI violation; disable the check here. */
static inline KASUMI_NOCFI void kasumi_path_put(const struct path *path)
{
	if (kasumi_path_put_ptr)
		kasumi_path_put_ptr(path);
}

static inline KASUMI_NOCFI void kasumi_path_get(const struct path *path)
{
	if (kasumi_path_get_ptr)
		kasumi_path_get_ptr(path);
}

#endif /* _KASUMI_RUNTIME_H */
