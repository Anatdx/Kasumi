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
#include <linux/utsname.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#include <linux/seq_file.h>
#include <uapi/linux/magic.h>

#include "kasumi_runtime.h"
#include "kasumi_store.h"
#include "kasumi_file_view.h"
#include "kasumi_dop_override.h"
#include "kasumi_xattr_sid_override.h"
#include "kasumi_fop_override.h"

bool kasumi_enabled;
atomic_t kasumi_rule_count = ATOMIC_INIT(0);
atomic_t kasumi_hide_count = ATOMIC_INIT(0);
struct kasumi_hook_stats kasumi_hook_stats;

struct kasumi_percpu *kasumi_percpu_base;
char *kasumi_getname_buf_base;
char *kasumi_iterate_buf_base;

atomic_long_t kasumi_ioctl_tgid = ATOMIC_LONG_INIT(0);
atomic_long_t kasumi_xattr_source_tgid = ATOMIC_LONG_INIT(0);

struct kmem_cache *kasumi_filldir_cache;

unsigned long (*kasumi_kallsyms_lookup_name)(const char *name);

DEFINE_HASHTABLE(kasumi_paths, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_targets, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_hide_paths, KASUMI_HASH_BITS);
DEFINE_XARRAY(kasumi_allow_uids_xa);
DEFINE_HASHTABLE(kasumi_inject_dirs, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_xattr_sbs, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_merge_dirs, KASUMI_HASH_BITS);

DEFINE_HASHTABLE(kasumi_spoof_kstat_path, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_spoof_kstat_ino, KASUMI_HASH_BITS);
atomic_t kasumi_spoof_kstat_count = ATOMIC_INIT(0);

DEFINE_MUTEX(kasumi_config_mutex);
LIST_HEAD(kasumi_maps_rules);
DEFINE_MUTEX(kasumi_maps_mutex);

bool kasumi_allowlist_loaded;
kasumi_ksu_is_allow_uid_fn kasumi_ksu_is_allow_uid_ptr;
kasumi_ksu_uid_should_umount_fn kasumi_ksu_uid_should_umount_ptr;

bool kasumi_debug_enabled;
bool kasumi_stealth_enabled = true;

char kasumi_mirror_path_buf[PATH_MAX] = KASUMI_DEFAULT_MIRROR_PATH;
char kasumi_mirror_name_buf[NAME_MAX] = KASUMI_DEFAULT_MIRROR_NAME;
char *kasumi_current_mirror_path = kasumi_mirror_path_buf;
char *kasumi_current_mirror_name = kasumi_mirror_name_buf;

struct kasumi_cmdline_rcu __rcu *kasumi_spoof_cmdline_ptr;
bool kasumi_cmdline_spoof_active;

pid_t kasumi_daemon_pid;

int kasumi_cmdline_kprobe_registered;
int kasumi_cmdline_kretprobe_registered;
int kasumi_getxattr_kprobe_registered;
int kasumi_mount_hide_vfsmnt_registered;
int kasumi_mount_hide_mountinfo_registered;
int kasumi_mount_hide_vfs_read_registered;
int kasumi_mount_hide_read_fallback_registered;
int kasumi_mount_hide_pread_fallback_registered;
int kasumi_maps_seq_read_registered;
int kasumi_proc_proxy_registered;
int kasumi_feature_enabled_mask = 0xFFFFFFFF;
int kasumi_statfs_kretprobe_registered;
int kasumi_statfs_tracepoint_registered;
int kasumi_ni_kprobe_registered;
int kasumi_reboot_kprobe_registered;
int kasumi_syscall_nr_param = 142;
bool kasumi_getname_kprobe_registered;
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
void (*kasumi_path_get_ptr)(const struct path *);
void (*kasumi_path_put_ptr)(const struct path *);
void (*kasumi_free_inode_nonrcu_ptr)(struct inode *);
struct file *(*kasumi_filp_open)(const char *, int, umode_t);
int (*kasumi_filp_close)(struct file *, fl_owner_t);
ssize_t (*kasumi_kernel_read)(struct file *, void *, size_t, loff_t *);
char *(*kasumi_strndup_user)(const char __user *, long);
struct filename *(*kasumi_getname_kernel)(const char *);
void (*kasumi_ihold)(struct inode *);
long (*kasumi_strncpy_from_user_nofault)(char *dst, const void __user *src, long count);
long (*kasumi_copy_from_user_nofault)(void *dst, const void __user *src, size_t size);
long (*kasumi_copy_to_user_nofault)(void __user *dst, const void *src, size_t size);
void (*kasumi_call_srcu_ptr)(struct srcu_struct *ssp, struct rcu_head *rhp,
			     rcu_callback_t func);
void (*kasumi_srcu_barrier_ptr)(struct srcu_struct *ssp);
kasumi_ksu_get_allow_list_fn kasumi_ksu_get_allow_list_ptr;

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

int kasumi_clone_source_inode_attrs(struct inode *target_inode, struct inode *source_inode)
{
	umode_t mode;

	if (!target_inode || !source_inode)
		return -EINVAL;

	mode = (READ_ONCE(target_inode->i_mode) & S_IFMT) |
	       (READ_ONCE(source_inode->i_mode) & 07777);
	inode_lock(target_inode);
	WRITE_ONCE(target_inode->i_mode, mode);
	target_inode->i_uid = source_inode->i_uid;
	target_inode->i_gid = source_inode->i_gid;
	inode_unlock(target_inode);
	return 0;
}

KASUMI_NOCFI int kasumi_clone_source_attrs_from_path(struct inode *target_inode, const char *source_path)
{
	struct path source = {};
	int ret;

	if (!target_inode || !source_path || !kasumi_kern_path)
		return -EINVAL;

	atomic_long_set(&kasumi_xattr_source_tgid, (long)task_tgid_vnr(current));
	ret = kasumi_kern_path(source_path, LOOKUP_FOLLOW, &source);
	atomic_long_set(&kasumi_xattr_source_tgid, 0);
	if (ret)
		return ret;
	if (!source.dentry || !d_inode(source.dentry)) {
		kasumi_path_put(&source);
		return -ENOENT;
	}

	ret = kasumi_clone_source_inode_attrs(target_inode, d_inode(source.dentry));
	kasumi_path_put(&source);
	return ret;
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

void kasumi_entry_free_rcu(struct rcu_head *head)
{
	struct kasumi_entry *e = container_of(head, struct kasumi_entry, rcu);

	kfree(e->src);
	kfree(e->target);
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

	kasumi_enabled = false;
	kasumi_file_view_clear();

	hash_for_each_safe(kasumi_paths, bkt, tmp, entry, node) {
		kasumi_clear_inode_flags_for_path(entry->src, AS_FLAGS_KASUMI_HIDE);
		kasumi_clear_inode_flags_for_path(entry->target, AS_FLAGS_KASUMI_SPOOF_KSTAT);
		(void)kasumi_dop_uninstall_path(entry->target);
		(void)kasumi_xattr_sid_uninstall_path_ancestors(entry->target);
		hlist_del_rcu(&entry->node);
		hlist_del_rcu(&entry->target_node);
		call_rcu(&entry->rcu, kasumi_entry_free_rcu);
	}
	hash_for_each_safe(kasumi_hide_paths, bkt, tmp, hide_entry, node) {
		kasumi_clear_inode_flags_for_path(hide_entry->path, AS_FLAGS_KASUMI_HIDE);
		hlist_del_rcu(&hide_entry->node);
		call_rcu(&hide_entry->rcu, kasumi_hide_entry_free_rcu);
	}
	xa_destroy(&kasumi_allow_uids_xa);
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
	kasumi_allowlist_loaded = false;
}
