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
extern atomic_t kasumi_tsr_path_count;
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

typedef bool (*kasumi_ksu_uid_should_umount_fn)(uid_t uid);

extern kasumi_ksu_uid_should_umount_fn kasumi_ksu_uid_should_umount_ptr;

extern bool kasumi_stealth_enabled;
extern char kasumi_mirror_path_buf[PATH_MAX];
extern char kasumi_mirror_name_buf[NAME_MAX];
extern char *kasumi_current_mirror_path;
extern char *kasumi_current_mirror_name;

struct kasumi_cmdline_rcu {
	struct rcu_head rcu;
	char cmdline[KSM_FAKE_CMDLINE_SIZE];
};

extern struct kasumi_cmdline_rcu __rcu *kasumi_spoof_cmdline_ptr;
extern bool kasumi_cmdline_spoof_active;
extern pid_t kasumi_daemon_pid;

extern int kasumi_cmdline_kprobe_registered;
extern int kasumi_getxattr_kprobe_registered;
extern int kasumi_mount_hide_vfsmnt_registered;
extern int kasumi_mount_hide_mountinfo_registered;
extern int kasumi_proc_proxy_registered;
extern int kasumi_proc_ns_readlink_registered;
extern int kasumi_feature_enabled_mask;
extern int kasumi_mount_hide_mode;
extern int kasumi_statfs_kretprobe_registered;
extern int kasumi_reboot_kprobe_registered;
extern bool kasumi_vfs_use_ftrace;
extern dev_t kasumi_system_dev;

extern int (*kasumi_kern_path)(const char *, unsigned int, struct path *);
extern int (*kasumi_vfs_getattr)(const struct path *, struct kstat *, u32, unsigned int);
extern struct file *(*kasumi_dentry_open)(const struct path *, int, const struct cred *);
extern char *(*kasumi_d_absolute_path)(const struct path *, char *, int);
extern char *(*kasumi_dentry_path_raw)(const struct dentry *, char *, int);
extern char *(*kasumi_d_path)(const struct path *, char *, int);
extern struct dentry *(*kasumi_d_hash_and_lookup)(struct dentry *, const struct qstr *);
extern void *kasumi_vfs_getxattr_addr;
extern void (*kasumi_path_get_ptr)(const struct path *);
extern void (*kasumi_path_put_ptr)(const struct path *);
extern void (*kasumi_free_inode_nonrcu_ptr)(struct inode *);
extern struct file *(*kasumi_filp_open)(const char *, int, umode_t);
extern int (*kasumi_filp_close)(struct file *, fl_owner_t);
extern ssize_t (*kasumi_kernel_read)(struct file *, void *, size_t, loff_t *);
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
