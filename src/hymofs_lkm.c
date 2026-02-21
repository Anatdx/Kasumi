// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
/*
 * HymoFS LKM - Loadable Kernel Module for filesystem path manipulation.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * All hooks use kprobes (no ftrace, no sys_call_table patch).
 * GET_FD: kprobe+kretprobe on ni_syscall. VFS: kprobe pre_handlers on
 *   getname_flags, vfs_getattr, d_path, iterate_dir.
 * Works on CONFIG_STRICT_KERNEL_RWX kernels. Syscall nr passed at insmod (hymo_syscall_nr=).
 *
 * Author: Anatdx
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
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
#include <linux/version.h>
#include <linux/utsname.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#ifndef HYMOFS_USE_SYSCALL_TRACEPOINT
#define HYMOFS_USE_SYSCALL_TRACEPOINT 1
#endif
#if HYMOFS_USE_SYSCALL_TRACEPOINT && defined(CONFIG_HAVE_SYSCALL_TRACEPOINTS)
#include <asm/unistd.h>
#include <linux/sched/task_stack.h>
#include <trace/events/syscalls.h>
#define HYMOFS_TP_AVAILABLE 1
#else
#define HYMOFS_TP_AVAILABLE 0
#endif

#include "hymofs_lkm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anatdx");
MODULE_DESCRIPTION("HymoFS LKM");
#ifndef HYMOFS_VERSION
#define HYMOFS_VERSION "0.1.0-dev"
#endif
MODULE_VERSION(HYMOFS_VERSION);

/*
 * Set to 1 to register VFS kprobes (path/stat/dir hooks). Set to 0 for GET_FD only
 * if the LKM causes bootloop on your kernel.
 * Build with -DHYMOFS_VFS_KPROBES=0 to disable if needed.
 */
#ifndef HYMOFS_VFS_KPROBES
#define HYMOFS_VFS_KPROBES 1
#endif

/*
 * Use sys_enter tracepoint for path redirect (default). Falls back to getname_flags
 * kprobe if tracepoint registration fails or CONFIG_HAVE_SYSCALL_TRACEPOINTS is off.
 * Build with -DHYMOFS_USE_SYSCALL_TRACEPOINT=0 to force getname_flags kprobe.
 */

/*
 * NOTE: We do NOT use MODULE_IMPORT_NS() for VFS symbols.
 * Instead, ALL VFS symbols (kern_path, kernel_read, filp_open, ihold,
 * strndup_user, getname_kernel) are resolved dynamically via kprobe
 * in hymofs_lkm_init(). This avoids GKI namespace protection entirely.
 */

/* ======================================================================
 * Part 1: Ftrace Hook Infrastructure
 * ====================================================================== */

static bool hymofs_enabled;
static atomic_t hymo_rule_count = ATOMIC_INIT(0);
static atomic_t hymo_hide_count = ATOMIC_INIT(0);

/* Per-CPU buffer and reent guard for getname_flags pre-handler. */
static DEFINE_PER_CPU(unsigned int, hymo_kprobe_reent);
static DEFINE_PER_CPU(char[HYMO_PATH_BUF], hymo_getname_path_buf);

/* When non-zero, current->tgid is in hymofs ioctl (path resolution). Skip VFS hooks
 * for that task to avoid re-entrancy / deadlock (e.g. metamount shell + hymod mount).
 */
static atomic_long_t hymo_ioctl_tgid = ATOMIC_LONG_INIT(0);
/* When set, getname_flags skips redirect (used when resolving source path for xattr) */
static atomic_long_t hymo_xattr_source_tgid = ATOMIC_LONG_INIT(0);

/* (d_path per-CPU vars removed: now uses kretprobe ri->data) */
/* Per-CPU for iterate_dir: swap ctx so kernel runs our filldir filter. */
static DEFINE_PER_CPU(struct hymofs_filldir_wrapper, hymo_iterate_wrapper);
static DEFINE_PER_CPU(int, hymo_iterate_did_swap);
/* When set, we're inside hymofs_populate_injected_list; skip ctx swap in iterate_dir pre. */
static DEFINE_PER_CPU(int, hymo_in_populate_inject);
/* Per-CPU path buffer for iterate_dir inject/merge path lookup. */
static DEFINE_PER_CPU(char[HYMO_ITERATE_PATH_BUF], hymo_iterate_dir_path);

/* Offset base for injected entries (filldir pos); must not collide with real inode offsets. */
#define HYMO_MAGIC_POS 0x1000000000000000ULL

/* ======================================================================
 * Part 2: Symbol Resolution via kallsyms + kprobes (no kernel export needed)
 * ====================================================================== */

/* Resolved once at init via kprobe; then we use it for all lookups. */
static unsigned long (*hymofs_kallsyms_lookup_name)(const char *name);

/*
 * Resolve kernel symbol by name. We do NOT rely on the kernel exporting
 * anything: first try to get kallsyms_lookup_name itself via kprobe, then
 * use it for fast lookup; else fall back to per-symbol kprobe resolution.
 */
static HYMO_NOCFI unsigned long hymofs_lookup_name(const char *name)
{
	if (hymofs_kallsyms_lookup_name) {
		unsigned long addr = hymofs_kallsyms_lookup_name(name);
		if (addr)
			return addr;
	}
	/* Fallback: kprobe on the target symbol gives us its address */
	{
		struct kprobe kp = { .symbol_name = name };
		unsigned long addr;

		if (register_kprobe(&kp) < 0)
			return 0;
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
		return addr;
	}
}

/* Call once at init to steal kallsyms_lookup_name via kprobe. */
static void hymofs_resolve_kallsyms_lookup(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

	if (register_kprobe(&kp) < 0)
		return;
	hymofs_kallsyms_lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);
	pr_info("hymofs: using kallsyms_lookup_name for symbol resolution\n");
}

/* Constants & data structures are in hymofs_lkm.h */

/* ======================================================================
 * Part 5: Global State
 * ====================================================================== */

static DEFINE_HASHTABLE(hymo_paths, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_targets, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_hide_paths, HYMO_HASH_BITS);
static DEFINE_XARRAY(hymo_allow_uids_xa);
static DEFINE_HASHTABLE(hymo_inject_dirs, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_xattr_sbs, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_merge_dirs, HYMO_HASH_BITS);

static DEFINE_SPINLOCK(hymo_cfg_lock);
static DEFINE_SPINLOCK(hymo_rules_lock);
static DEFINE_SPINLOCK(hymo_hide_lock);
static DEFINE_SPINLOCK(hymo_allow_uids_lock);
static DEFINE_SPINLOCK(hymo_xattr_sbs_lock);
static DEFINE_SPINLOCK(hymo_merge_lock);
static DEFINE_SPINLOCK(hymo_inject_lock);

static bool hymo_allowlist_loaded;
static DEFINE_MUTEX(hymo_allowlist_lock);

/* hymofs_enabled declared above (used by hooks) */
bool hymo_debug_enabled;
static bool hymo_stealth_enabled = true;

static char hymo_mirror_path_buf[PATH_MAX] = HYMO_DEFAULT_MIRROR_PATH;
static char hymo_mirror_name_buf[NAME_MAX] = HYMO_DEFAULT_MIRROR_NAME;
static char *hymo_current_mirror_path = hymo_mirror_path_buf;
static char *hymo_current_mirror_name = hymo_mirror_name_buf;

/* uname spoofing: storage and lock */
static struct hymo_spoof_uname hymo_spoof_uname_store;
static DEFINE_SPINLOCK(hymo_uname_lock);
static bool hymo_uname_spoof_active;

static pid_t hymo_daemon_pid;
static DEFINE_SPINLOCK(hymo_daemon_lock);

static DECLARE_BITMAP(hymo_path_bloom, HYMO_BLOOM_SIZE);
static DECLARE_BITMAP(hymo_hide_bloom, HYMO_BLOOM_SIZE);
/* hymo_rule_count and hymo_hide_count declared above */

/* /system partition device number for stat spoofing on redirected files */
static dev_t hymo_system_dev;

/* VFS symbols resolved at init; forward-declared for use in merge/inject before init. */
static int (*hymo_kern_path_ptr)(const char *, unsigned int, struct path *);
static int (*hymo_vfs_getattr_ptr)(const struct path *, struct kstat *, u32, unsigned int);
static struct file *(*hymo_dentry_open_ptr)(const struct path *, int, const struct cred *);
static char *(*hymo_d_absolute_path_ptr)(const struct path *, char *, int);
static char *(*hymo_dentry_path_raw_ptr)(const struct dentry *, char *, int);
static struct dentry *(*hymo_d_hash_and_lookup_ptr)(struct dentry *, struct qstr *);

/* CFI-safe wrappers for dynamically resolved function pointers.
 * These wrappers are marked with HYMO_NOCFI to bypass CFI checks
 * when calling through function pointers.
 */
static HYMO_NOCFI int hymo_kern_path(const char *name, unsigned int flags, struct path *path)
{
	if (!hymo_kern_path_ptr)
		return -ENOENT;
	return hymo_kern_path_ptr(name, flags, path);
}

static HYMO_NOCFI int hymo_vfs_getattr(const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags)
{
	if (!hymo_vfs_getattr_ptr)
		return -ENOENT;
	return hymo_vfs_getattr_ptr(path, stat, request_mask, query_flags);
}

static HYMO_NOCFI struct file *hymo_dentry_open(const struct path *path, int flags, const struct cred *cred)
{
	if (!hymo_dentry_open_ptr)
		return ERR_PTR(-ENOENT);
	return hymo_dentry_open_ptr(path, flags, cred);
}

static HYMO_NOCFI char *hymo_d_absolute_path(const struct path *path, char *buf, int buflen)
{
	if (!hymo_d_absolute_path_ptr)
		return ERR_PTR(-ENOENT);
	return hymo_d_absolute_path_ptr(path, buf, buflen);
}

static HYMO_NOCFI char *hymo_dentry_path_raw(const struct dentry *dentry, char *buf, int buflen)
{
	if (!hymo_dentry_path_raw_ptr)
		return ERR_PTR(-ENOENT);
	return hymo_dentry_path_raw_ptr(dentry, buf, buflen);
}

static HYMO_NOCFI struct dentry *hymo_d_hash_and_lookup(struct dentry *dir, struct qstr *name)
{
	if (!hymo_d_hash_and_lookup_ptr)
		return NULL;
	return hymo_d_hash_and_lookup_ptr(dir, name);
}

/* Additional VFS symbols resolved at init for ioctl/allowlist path resolution */
static struct file *(*hymo_filp_open_ptr)(const char *, int, umode_t);
static int (*hymo_filp_close_ptr)(struct file *, fl_owner_t);
static ssize_t (*hymo_kernel_read_ptr)(struct file *, void *, size_t, loff_t *);
static char *(*hymo_strndup_user_ptr)(const char __user *, long);
static struct filename *(*hymo_getname_kernel_ptr)(const char *);
static void (*hymo_ihold_ptr)(struct inode *);

/* CFI-safe wrappers for additional VFS symbols */
static HYMO_NOCFI struct file *hymo_filp_open(const char *filename, int flags, umode_t mode)
{
	if (!hymo_filp_open_ptr)
		return ERR_PTR(-ENOENT);
	return hymo_filp_open_ptr(filename, flags, mode);
}

static HYMO_NOCFI int hymo_filp_close(struct file *filp, fl_owner_t id)
{
	if (!hymo_filp_close_ptr)
		return -ENOENT;
	return hymo_filp_close_ptr(filp, id);
}

static HYMO_NOCFI ssize_t hymo_kernel_read(struct file *file, void *buf, size_t count, loff_t *pos)
{
	if (!hymo_kernel_read_ptr)
		return -EINVAL;
	return hymo_kernel_read_ptr(file, buf, count, pos);
}

static HYMO_NOCFI char *hymo_strndup_user(const char __user *s, long n)
{
	if (!hymo_strndup_user_ptr)
		return ERR_PTR(-ENOENT);
	return hymo_strndup_user_ptr(s, n);
}

static HYMO_NOCFI struct filename *hymo_getname_kernel(const char *filename)
{
	if (!hymo_getname_kernel_ptr)
		return ERR_PTR(-ENOENT);
	return hymo_getname_kernel_ptr(filename);
}

static HYMO_NOCFI void hymo_ihold(struct inode *inode)
{
	if (hymo_ihold_ptr)
		hymo_ihold_ptr(inode);
}

/* User access function resolved dynamically */
static long (*hymo_strncpy_from_user_nofault_ptr)(char *dst, const void __user *src, long count);

static HYMO_NOCFI long hymo_strncpy_from_user_nofault(char *dst, const void __user *src, long count)
{
	if (!hymo_strncpy_from_user_nofault_ptr)
		return -EFAULT;
	return hymo_strncpy_from_user_nofault_ptr(dst, src, count);
}

/* vfs_getxattr addr for resolving source path's SELinux context (set when xattr kretprobe registered) */
static void *hymo_vfs_getxattr_addr;

/* hymo_log macro is in hymofs_lkm.h */

/* ======================================================================
 * Part 6: RCU Free Callbacks
 * ====================================================================== */

static void hymo_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_entry *e = container_of(head, struct hymo_entry, rcu);
	kfree(e->src);
	kfree(e->target);
	kfree(e);
}

static void hymo_hide_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_hide_entry *e = container_of(head, struct hymo_hide_entry, rcu);
	kfree(e->path);
	kfree(e);
}

static void hymo_inject_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_inject_entry *e = container_of(head, struct hymo_inject_entry, rcu);
	kfree(e->dir);
	kfree(e);
}

static void hymo_xattr_sb_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_xattr_sb_entry *e = container_of(head, struct hymo_xattr_sb_entry, rcu);
	kfree(e);
}

static void hymo_merge_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_merge_entry *e = container_of(head, struct hymo_merge_entry, rcu);
	if (e->target_dentry)
		dput(e->target_dentry);
	kfree(e->src);
	kfree(e->target);
	kfree(e->resolved_src);
	kfree(e);
}

/* ======================================================================
 * Part 7: Inode Marking
 * ====================================================================== */

static inline void hymofs_mark_inode_hidden(struct inode *inode)
{
	if (inode && inode->i_mapping)
		set_bit(AS_FLAGS_HYMO_HIDE, &inode->i_mapping->flags);
}

static inline bool hymofs_is_inode_hidden_bit(struct inode *inode)
{
	if (!inode || !inode->i_mapping)
		return false;
	return test_bit(AS_FLAGS_HYMO_HIDE, &inode->i_mapping->flags);
}

/* Mark directory inode as having inject/merge rules (fast path for iterate_dir).
 * Call from process context only; kern_path can sleep. */
static void hymofs_mark_dir_has_inject(const char *path_str)
{
	struct path p;

	if (!path_str || !hymo_kern_path_ptr)
		return;
	if (hymo_kern_path(path_str, LOOKUP_FOLLOW, &p) != 0)
		return;
	if (p.dentry && d_inode(p.dentry) && d_inode(p.dentry)->i_mapping)
		set_bit(AS_FLAGS_HYMO_DIR_HAS_INJECT, &d_inode(p.dentry)->i_mapping->flags);
	path_put(&p);
}

/* ======================================================================
 * Part 9: Cleanup
 * ====================================================================== */

static void hymo_cleanup_locked(void)
{
	struct hymo_entry *entry;
	struct hymo_hide_entry *hide_entry;
	struct hymo_inject_entry *inject_entry;
	struct hymo_xattr_sb_entry *sb_entry;
	struct hymo_merge_entry *merge_entry;
	struct hlist_node *tmp;
	int bkt;

	hash_for_each_safe(hymo_paths, bkt, tmp, entry, node) {
		hlist_del_rcu(&entry->node);
		hlist_del_rcu(&entry->target_node);
		call_rcu(&entry->rcu, hymo_entry_free_rcu);
	}
	hash_for_each_safe(hymo_hide_paths, bkt, tmp, hide_entry, node) {
		hlist_del_rcu(&hide_entry->node);
		call_rcu(&hide_entry->rcu, hymo_hide_entry_free_rcu);
	}
	xa_destroy(&hymo_allow_uids_xa);
	hash_for_each_safe(hymo_inject_dirs, bkt, tmp, inject_entry, node) {
		hlist_del_rcu(&inject_entry->node);
		call_rcu(&inject_entry->rcu, hymo_inject_entry_free_rcu);
	}
	hash_for_each_safe(hymo_xattr_sbs, bkt, tmp, sb_entry, node) {
		hlist_del_rcu(&sb_entry->node);
		call_rcu(&sb_entry->rcu, hymo_xattr_sb_entry_free_rcu);
	}
	hash_for_each_safe(hymo_merge_dirs, bkt, tmp, merge_entry, node) {
		hlist_del_rcu(&merge_entry->node);
		call_rcu(&merge_entry->rcu, hymo_merge_entry_free_rcu);
	}

	bitmap_zero(hymo_path_bloom, HYMO_BLOOM_SIZE);
	bitmap_zero(hymo_hide_bloom, HYMO_BLOOM_SIZE);
	atomic_set(&hymo_rule_count, 0);
	atomic_set(&hymo_hide_count, 0);
	hymo_allowlist_loaded = false;
}

/* ======================================================================
 * Part 10: Inject Rule Helper
 * ====================================================================== */

static void hymofs_add_inject_rule(char *dir)
{
	struct hymo_inject_entry *ie;
	u32 hash;
	bool found = false;

	if (!dir)
		return;

	hash = full_name_hash(NULL, dir, strlen(dir));
	spin_lock(&hymo_inject_lock);
	hlist_for_each_entry(ie, &hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (strcmp(ie->dir, dir) == 0) {
			found = true;
			break;
		}
	}
	if (!found) {
		ie = kmalloc(sizeof(*ie), GFP_ATOMIC);
		if (ie) {
			ie->dir = dir;
			hlist_add_head_rcu(&ie->node,
				&hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)]);
			atomic_inc(&hymo_rule_count);
		} else {
			kfree(dir);
		}
	} else {
		kfree(dir);
	}
	spin_unlock(&hymo_inject_lock);
}

/* ======================================================================
 * Part 10b: Inject - populate list for merge/add rule dirs
 * ====================================================================== */

struct hymo_merge_ctx {
	struct dir_context ctx;
	struct list_head *head;
	const char *dir_path;
};

static HYMO_NOCFI HYMO_FILLDIR_RET_TYPE hymo_merge_filldir(struct dir_context *ctx, const char *name,
					int namlen, loff_t offset, u64 ino,
					unsigned int d_type)
{
	struct hymo_merge_ctx *mctx = container_of(ctx, struct hymo_merge_ctx, ctx);
	struct hymo_name_list *item;

	if (namlen == 1 && name[0] == '.')
		return HYMO_FILLDIR_CONTINUE;
	if (namlen == 2 && name[0] == '.' && name[1] == '.')
		return HYMO_FILLDIR_CONTINUE;
	if (namlen == 8 && strncmp(name, ".replace", 8) == 0)
		return HYMO_FILLDIR_CONTINUE;

	/* Skip whiteout (char dev 0:0) */
	if (d_type == DT_CHR && mctx->dir_path && hymo_vfs_getattr_ptr) {
		char *path = kasprintf(GFP_KERNEL, "%s/%.*s", mctx->dir_path, namlen, name);
		if (path) {
			struct path p;
			if (hymo_kern_path(path, LOOKUP_FOLLOW, &p) == 0) {
				struct kstat stat;
				if (hymo_vfs_getattr(&p, &stat, STATX_TYPE, AT_STATX_SYNC_AS_STAT) == 0 &&
				    S_ISCHR(stat.mode) && stat.rdev == 0) {
					path_put(&p);
					kfree(path);
					return HYMO_FILLDIR_CONTINUE;
				}
				path_put(&p);
			}
			kfree(path);
		}
	}

	/* Skip duplicates */
	{
		struct hymo_name_list *pos;
		list_for_each_entry(pos, mctx->head, list) {
			if ((size_t)namlen == strlen(pos->name) &&
			    strncmp(pos->name, name, namlen) == 0)
				return HYMO_FILLDIR_CONTINUE;
		}
	}

	item = kmalloc(sizeof(*item), GFP_KERNEL);
	if (item) {
		item->name = kstrndup(name, namlen, GFP_KERNEL);
		item->type = (unsigned char)d_type;
		if (item->name)
			list_add(&item->list, mctx->head);
		else
			kfree(item);
	}
	return HYMO_FILLDIR_CONTINUE;
}

static HYMO_NOCFI void hymofs_populate_injected_list(const char *dir_path, struct dentry *parent,
					  struct list_head *head)
{
	struct hymo_entry *entry;
	struct hymo_inject_entry *inject_entry;
	struct hymo_merge_entry *merge_entry;
	struct hymo_name_list *item;
	struct hymo_merge_target_node *target_node, *tmp_node;
	struct list_head merge_targets;
	const char *match_src = NULL;
	size_t match_src_len = 0;
	u32 hash;
	int bkt;
	bool should_inject = false;
	size_t dir_len;
	/* d_path-resolved form of dir_path for matching rules stored via d_path.
	 * iterate_dir gives us d_absolute_path output, but ADD_RULE/ADD_MERGE_RULE
	 * store paths using d_path. These can differ (e.g. /product/overlay vs
	 * /system/product/overlay) due to bind mounts / symlinks. */
	char *dpath_buf = NULL;
	const char *dpath_dir = NULL;
	size_t dpath_dir_len = 0;
	u32 dpath_hash = 0;

	if (unlikely(!hymofs_enabled || !dir_path))
		return;

	INIT_LIST_HEAD(&merge_targets);
	dir_len = strlen(dir_path);
	hash = full_name_hash(NULL, dir_path, dir_len);

	/* Resolve the d_path form of this directory. We're in filldir callback
	 * (process context), so d_path is safe to call. Our d_path kretprobe
	 * won't interfere since this directory is not a redirect target. */
	if (parent) {
		if (hymo_kern_path_ptr) {
			struct path resolved;
			if (hymo_kern_path(dir_path, LOOKUP_FOLLOW, &resolved) == 0) {
				dpath_buf = kmalloc(PATH_MAX, GFP_KERNEL);
				if (dpath_buf) {
					char *p = d_path(&resolved, dpath_buf, PATH_MAX);
					if (!IS_ERR(p) && p[0] == '/' &&
					    strcmp(p, dir_path) != 0) {
						dpath_dir = p;
						dpath_dir_len = strlen(p);
						dpath_hash = full_name_hash(NULL, p, dpath_dir_len);
					}
				}
				path_put(&resolved);
			}
		}
	}

	rcu_read_lock();

	/* Try both d_absolute_path form and d_path form for inject_dirs */
	hlist_for_each_entry_rcu(inject_entry,
		&hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (strcmp(inject_entry->dir, dir_path) == 0) {
			should_inject = true;
			break;
		}
	}
	if (!should_inject && dpath_dir) {
		hlist_for_each_entry_rcu(inject_entry,
			&hymo_inject_dirs[hash_min(dpath_hash, HYMO_HASH_BITS)], node) {
			if (strcmp(inject_entry->dir, dpath_dir) == 0) {
				should_inject = true;
				break;
			}
		}
	}

	/* Scan all merge entries to match both src and resolved_src against
	 * both path forms. */
	hash_for_each_rcu(hymo_merge_dirs, bkt, merge_entry, node) {
		if (strcmp(merge_entry->src, dir_path) == 0 ||
		    (merge_entry->resolved_src &&
		     strcmp(merge_entry->resolved_src, dir_path) == 0) ||
		    (dpath_dir && strcmp(merge_entry->src, dpath_dir) == 0) ||
		    (dpath_dir && merge_entry->resolved_src &&
		     strcmp(merge_entry->resolved_src, dpath_dir) == 0)) {
			if (!match_src) {
				match_src = merge_entry->src;
				match_src_len = strlen(match_src);
			}
			target_node = kmalloc(sizeof(*target_node), GFP_ATOMIC);
			if (target_node) {
				target_node->target = kstrdup(merge_entry->target, GFP_ATOMIC);
				target_node->target_dentry = NULL;
				if (target_node->target)
					list_add_tail(&target_node->list, &merge_targets);
				else
					kfree(target_node);
			}
			should_inject = true;
		}
	}

	if (should_inject) {
		/* Use original src path for hymo_paths prefix scan.
		 * Prefer match_src (from merge rule), then dpath_dir (d_path form
		 * matching ADD_RULE entries), then dir_path as fallback. */
		const char *pfx = match_src ? match_src :
				  dpath_dir ? dpath_dir : dir_path;
		size_t pfx_len = match_src ? match_src_len :
				 dpath_dir ? dpath_dir_len : dir_len;

		hash_for_each_rcu(hymo_paths, bkt, entry, node) {
			if (strncmp(entry->src, pfx, pfx_len) != 0)
				continue;
			{
				char *name = NULL;
				if (pfx_len == 1 && pfx[0] == '/')
					name = (char *)entry->src + 1;
				else if (entry->src[pfx_len] == '/')
					name = (char *)entry->src + pfx_len + 1;

				if (name && *name && !strchr(name, '/')) {
					struct hymo_name_list *pos;
					list_for_each_entry(pos, head, list) {
						if (strcmp(pos->name, name) == 0)
							goto next_entry;
					}
					item = kmalloc(sizeof(*item), GFP_ATOMIC);
					if (item) {
						item->name = kstrdup(name, GFP_ATOMIC);
						item->type = entry->type;
						if (item->name)
							list_add(&item->list, head);
						else
							kfree(item);
					}
				}
			}
next_entry:
			;
		}
	}
	rcu_read_unlock();

	list_for_each_entry_safe(target_node, tmp_node, &merge_targets, list) {
		if (target_node->target && hymo_kern_path_ptr && hymo_dentry_open_ptr) {
			struct path path;
			if (hymo_kern_path(target_node->target, LOOKUP_FOLLOW, &path) == 0) {
				const struct cred *cred = get_task_cred(&init_task);
				struct file *f = hymo_dentry_open(&path, O_RDONLY | O_DIRECTORY,
								cred);
				if (!IS_ERR(f)) {
					struct hymo_merge_ctx mctx = {
						.ctx.actor = hymo_merge_filldir,
						.head = head,
						.dir_path = target_node->target,
					};
					this_cpu_write(hymo_in_populate_inject, 1);
					iterate_dir(f, &mctx.ctx);
					this_cpu_write(hymo_in_populate_inject, 0);
					fput(f);
				}
				put_cred(cred);
				path_put(&path);
			}
			kfree(target_node->target);
		}
		list_del(&target_node->list);
		kfree(target_node);
	}
	kfree(dpath_buf);
}

/* ======================================================================
 * Part 10c: Materialize merge rule into individual hymo_paths entries
 *
 * Called from HYMO_IOC_ADD_MERGE_RULE ioctl (process context, can sleep).
 * Recursively scans the merge target directory and creates exact-match
 * redirect rules so getname_flags works without blind trie redirect.
 * ====================================================================== */

static void hymofs_materialize_merge(const char *src_prefix,
				     const char *target_dir, int depth);

static void hymofs_add_path_entry(const char *src, const char *tgt,
				  unsigned char type)
{
	struct hymo_entry *e;
	u32 hash = full_name_hash(NULL, src, strlen(src));
	bool found = false;

	spin_lock(&hymo_rules_lock);
	hlist_for_each_entry(e, &hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (e->src_hash == hash && strcmp(e->src, src) == 0) {
			found = true;
			break;
		}
	}
	if (!found) {
		e = kmalloc(sizeof(*e), GFP_ATOMIC);
		if (e) {
			e->src = kstrdup(src, GFP_ATOMIC);
			e->target = kstrdup(tgt, GFP_ATOMIC);
			e->type = type;
			e->src_hash = hash;
			if (e->src && e->target) {
				unsigned long h1, h2;

				hlist_add_head_rcu(&e->node,
					&hymo_paths[hash_min(hash, HYMO_HASH_BITS)]);
				hlist_add_head_rcu(&e->target_node,
					&hymo_targets[hash_min(
						full_name_hash(NULL, e->target,
							strlen(e->target)),
						HYMO_HASH_BITS)]);
				h1 = jhash(src, strlen(src), 0) & (HYMO_BLOOM_SIZE - 1);
				h2 = jhash(src, strlen(src), 1) & (HYMO_BLOOM_SIZE - 1);
				set_bit(h1, hymo_path_bloom);
				set_bit(h2, hymo_path_bloom);
				atomic_inc(&hymo_rule_count);
			} else {
				kfree(e->src);
				kfree(e->target);
				kfree(e);
			}
		}
	}
	spin_unlock(&hymo_rules_lock);
}

struct hymo_mat_ctx {
	struct dir_context ctx;
	const char *src_prefix;
	const char *target_dir;
	int depth;
};

static HYMO_NOCFI HYMO_FILLDIR_RET_TYPE
hymo_mat_filldir(struct dir_context *ctx, const char *name,
		 int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	struct hymo_mat_ctx *mc = container_of(ctx, struct hymo_mat_ctx, ctx);
	char *src_path, *tgt_path, *inj_dir;

	(void)offset; (void)ino;

	if (namlen <= 2 && name[0] == '.') {
		if (namlen == 1 || (namlen == 2 && name[1] == '.'))
			return HYMO_FILLDIR_CONTINUE;
	}
	if (namlen == 8 && memcmp(name, ".replace", 8) == 0)
		return HYMO_FILLDIR_CONTINUE;

	src_path = kasprintf(GFP_KERNEL, "%s/%.*s", mc->src_prefix, namlen, name);
	tgt_path = kasprintf(GFP_KERNEL, "%s/%.*s", mc->target_dir, namlen, name);
	if (!src_path || !tgt_path) {
		kfree(src_path);
		kfree(tgt_path);
		return HYMO_FILLDIR_CONTINUE;
	}

	hymofs_add_path_entry(src_path, tgt_path, d_type);

	inj_dir = kstrdup(mc->src_prefix, GFP_KERNEL);
	if (inj_dir)
		hymofs_add_inject_rule(inj_dir);
	hymofs_mark_dir_has_inject(mc->src_prefix);

	if (d_type == DT_DIR && mc->depth < 8)
		hymofs_materialize_merge(src_path, tgt_path, mc->depth + 1);

	kfree(src_path);
	kfree(tgt_path);
	return HYMO_FILLDIR_CONTINUE;
}

static HYMO_NOCFI void hymofs_materialize_merge(const char *src_prefix,
						const char *target_dir,
						int depth)
{
	struct path path;
	struct file *f;
	struct hymo_mat_ctx mctx;

	if (!hymo_kern_path_ptr || !hymo_dentry_open_ptr || depth > 8)
		return;
	if (hymo_kern_path(target_dir, LOOKUP_FOLLOW, &path) != 0)
		return;

	f = hymo_dentry_open(&path, O_RDONLY | O_DIRECTORY, current_cred());
	if (IS_ERR(f)) {
		path_put(&path);
		return;
	}

	mctx.ctx.actor = hymo_mat_filldir;
	mctx.ctx.pos = 0;
	mctx.src_prefix = src_prefix;
	mctx.target_dir = target_dir;
	mctx.depth = depth;

	iterate_dir(f, &mctx.ctx);

	fput(f);
	path_put(&path);
}

/* ======================================================================
 * Part 11: Core Logic - Privileged Check / Allowlist
 * ====================================================================== */

static inline bool hymo_is_privileged_process(void)
{
	pid_t pid = task_tgid_vnr(current);

	if (unlikely(uid_eq(current_uid(), GLOBAL_ROOT_UID)))
		return true;
	if (hymo_daemon_pid > 0 && pid == hymo_daemon_pid)
		return true;
	return false;
}

static bool hymo_uid_in_allowlist(uid_t uid)
{
	void *p;

	rcu_read_lock();
	p = xa_load(&hymo_allow_uids_xa, uid);
	rcu_read_unlock();
	return p != NULL;
}

static bool hymo_should_apply_hide_rules(void)
{
	if (!hymo_allowlist_loaded)
		return true;
	if (xa_empty(&hymo_allow_uids_xa))
		return true;
	return !hymo_uid_in_allowlist(__kuid_val(current_uid()));
}

/* Simplified KSU allowlist reload */
static bool hymo_should_umount_profile(const struct hymo_app_profile *p)
{
	if (p->allow_su)
		return false;
	if (p->nrp_config.use_default)
		return true;
	return p->nrp_config.profile.umount_modules;
}

static void hymo_add_allow_uid(uid_t uid)
{
	spin_lock(&hymo_allow_uids_lock);
	xa_store(&hymo_allow_uids_xa, uid, HYMO_UID_ALLOW_MARKER, GFP_KERNEL);
	spin_unlock(&hymo_allow_uids_lock);
}

/*
 * GKI kernels protect many VFS symbols behind namespaces or don't export
 * them at all. We resolve ALL problematic VFS symbols via kprobe at init
 * time, so the module has zero direct VFS symbol dependencies.
 * CFI-safe wrappers are defined earlier in the file.
 */

static HYMO_NOCFI bool hymo_reload_ksu_allowlist(void)
{
	struct file *fp;
	loff_t off = 0;
	u32 magic = 0, version = 0;
	ssize_t ret;
	struct hymo_app_profile profile;
	int count = 0;

	/* VFS symbols not available on this kernel - skip allowlist */
	if (!hymo_filp_open_ptr || !hymo_kernel_read_ptr)
		return false;

	if (!mutex_trylock(&hymo_allowlist_lock))
		return false;

	fp = hymo_filp_open(HYMO_KSU_ALLOWLIST_PATH, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		spin_lock(&hymo_allow_uids_lock);
		xa_destroy(&hymo_allow_uids_xa);
		hymo_allowlist_loaded = false;
		spin_unlock(&hymo_allow_uids_lock);
		mutex_unlock(&hymo_allowlist_lock);
		return false;
	}

	ret = hymo_kernel_read(fp, &magic, sizeof(magic), &off);
	if (ret != sizeof(magic) || magic != HYMO_KSU_ALLOWLIST_MAGIC)
		goto bad;
	ret = hymo_kernel_read(fp, &version, sizeof(version), &off);
	if (ret != sizeof(version))
		goto bad;

	spin_lock(&hymo_allow_uids_lock);
	xa_destroy(&hymo_allow_uids_xa);
	hymo_allowlist_loaded = true;
	spin_unlock(&hymo_allow_uids_lock);

	while (hymo_kernel_read(fp, &profile, sizeof(profile), &off) == sizeof(profile)) {
		if (!hymo_should_umount_profile(&profile) && profile.current_uid > 0) {
			hymo_add_allow_uid((uid_t)profile.current_uid);
			if (++count >= HYMO_ALLOWLIST_UID_MAX)
				break;
		}
	}

	if (hymo_filp_close_ptr)
		hymo_filp_close(fp, NULL);
	else
		fput(fp);
	mutex_unlock(&hymo_allowlist_lock);
	return true;

bad:
	if (hymo_filp_close_ptr)
		hymo_filp_close(fp, NULL);
	else
		fput(fp);
	spin_lock(&hymo_allow_uids_lock);
	xa_destroy(&hymo_allow_uids_xa);
	hymo_allowlist_loaded = false;
	spin_unlock(&hymo_allow_uids_lock);
	mutex_unlock(&hymo_allowlist_lock);
	return false;
}

/* ======================================================================
 * Part 12: Forward Redirect (resolve_target)
 * ====================================================================== */

static char * __maybe_unused hymofs_resolve_target(const char *pathname)
{
	struct hymo_entry *entry;
	u32 hash;
	char *target = NULL;
	size_t path_len;
	pid_t pid;

	if (unlikely(!hymofs_enabled || !pathname))
		return NULL;

	pid = task_tgid_vnr(current);
	if (hymo_daemon_pid > 0 && pid == hymo_daemon_pid)
		return NULL;

	path_len = strlen(pathname);
	hash = full_name_hash(NULL, pathname, path_len);

	rcu_read_lock();

	/* Bloom filter fast-path for exact match rules */
	if (atomic_read(&hymo_rule_count) != 0) {
		unsigned long bh1 = jhash(pathname, (u32)path_len, 0) & (HYMO_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)path_len, 1) & (HYMO_BLOOM_SIZE - 1);

		if (test_bit(bh1, hymo_path_bloom) && test_bit(bh2, hymo_path_bloom)) {
			hlist_for_each_entry_rcu(entry,
				&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
				if (entry->src_hash == hash &&
				    strcmp(entry->src, pathname) == 0) {
					target = kstrdup(entry->target, GFP_ATOMIC);
					rcu_read_unlock();
					return target;
				}
			}
		}
	}

	/*
	 * Merge trie is NOT consulted here for path redirect. Merge rules
	 * only affect directory listing (inject via iterate_dir). Individual
	 * file redirects are materialized into hymo_paths at ADD_MERGE_RULE
	 * time, so the bloom+hash exact match above handles them.
	 *
	 * The KPM version validated merge targets with kern_path() before
	 * redirecting. In LKM kprobe context we cannot sleep, so blind
	 * merge-trie redirect would send EVERY path under the merge prefix
	 * to the module dir — including original system files that don't
	 * exist there — breaking PMS and causing bootloop.
	 */

	rcu_read_unlock();
	return target;
}

/* ======================================================================
 * Part 14: Hide Logic
 * ====================================================================== */

static bool __maybe_unused hymofs_should_hide(const char *pathname)
{
	struct hymo_hide_entry *he;
	u32 hash;
	size_t len;

	if (unlikely(!hymofs_enabled || !pathname || !*pathname))
		return false;
	if (unlikely(hymo_is_privileged_process()))
		return false;

	len = strlen(pathname);

	/* Stealth: always hide the mirror device */
	if (likely(hymo_stealth_enabled)) {
		size_t name_len = strlen(hymo_current_mirror_name);
		size_t path_len = strlen(hymo_current_mirror_path);

		if ((len == name_len && strcmp(pathname, hymo_current_mirror_name) == 0) ||
		    (len == path_len && strcmp(pathname, hymo_current_mirror_path) == 0))
			return true;
	}

	if (!hymo_should_apply_hide_rules())
		return false;

	/* Bloom fast-path */
	if (atomic_read(&hymo_hide_count) == 0)
		return false;

	{
		unsigned long bh1 = jhash(pathname, (u32)len, 0) & (HYMO_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)len, 1) & (HYMO_BLOOM_SIZE - 1);

		if (!test_bit(bh1, hymo_hide_bloom) || !test_bit(bh2, hymo_hide_bloom))
			return false;
	}

	hash = full_name_hash(NULL, pathname, len);
	rcu_read_lock();
	hlist_for_each_entry_rcu(he,
		&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (he->path_hash == hash && strcmp(he->path, pathname) == 0) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

static bool __maybe_unused hymofs_should_replace(const char *pathname)
{
	struct hymo_entry *entry;
	u32 hash;
	size_t path_len;
	pid_t pid;

	if (unlikely(!hymofs_enabled || !pathname))
		return false;

	pid = task_tgid_vnr(current);
	if (hymo_daemon_pid > 0 && pid == hymo_daemon_pid)
		return false;
	if (atomic_read(&hymo_rule_count) == 0)
		return false;

	path_len = strlen(pathname);
	{
		unsigned long bh1 = jhash(pathname, (u32)path_len, 0) & (HYMO_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)path_len, 1) & (HYMO_BLOOM_SIZE - 1);

		if (!test_bit(bh1, hymo_path_bloom) || !test_bit(bh2, hymo_path_bloom))
			return false;
	}

	hash = full_name_hash(NULL, pathname, path_len);
	rcu_read_lock();
	hlist_for_each_entry_rcu(entry,
		&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (entry->src_hash == hash && strcmp(entry->src, pathname) == 0) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

/* ======================================================================
 * Part 15: Dispatch Handler (ioctl only; all commands use HYMO_IOC_* from hymo_magic.h)
 * GET_FD is syscall-only -> hymofs_get_anon_fd()
 * ====================================================================== */

static int hymo_dispatch_cmd(unsigned int cmd, void __user *arg)
{
	struct hymo_syscall_arg req;
	struct hymo_entry *entry;
	struct hymo_hide_entry *hide_entry;
	struct hymo_inject_entry *inject_entry;
	char *src = NULL, *target = NULL;
	u32 hash;
	bool found = false;
	int ret = 0;

	if (cmd == HYMO_IOC_CLEAR_ALL) {
		spin_lock(&hymo_cfg_lock);
		spin_lock(&hymo_rules_lock);
		spin_lock(&hymo_hide_lock);
		spin_lock(&hymo_allow_uids_lock);
		spin_lock(&hymo_xattr_sbs_lock);
		spin_lock(&hymo_merge_lock);
		spin_lock(&hymo_inject_lock);
		hymo_cleanup_locked();
		strscpy(hymo_mirror_path_buf, HYMO_DEFAULT_MIRROR_PATH, PATH_MAX);
		strscpy(hymo_mirror_name_buf, HYMO_DEFAULT_MIRROR_NAME, NAME_MAX);
		hymo_current_mirror_path = hymo_mirror_path_buf;
		hymo_current_mirror_name = hymo_mirror_name_buf;
		spin_unlock(&hymo_inject_lock);
		spin_unlock(&hymo_merge_lock);
		spin_unlock(&hymo_xattr_sbs_lock);
		spin_unlock(&hymo_allow_uids_lock);
		spin_unlock(&hymo_hide_lock);
		spin_unlock(&hymo_rules_lock);
		spin_unlock(&hymo_cfg_lock);
		rcu_barrier();
		return 0;
	}

	if (cmd == HYMO_IOC_GET_VERSION) {
		int ver = HYMO_PROTOCOL_VERSION;
		if (copy_to_user(arg, &ver, sizeof(ver)))
			return -EFAULT;
		return 0;
	}

	if (cmd == HYMO_IOC_SET_DEBUG) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		hymo_debug_enabled = !!val;
		return 0;
	}

	if (cmd == HYMO_IOC_SET_STEALTH) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		hymo_stealth_enabled = !!val;
		return 0;
	}

	if (cmd == HYMO_IOC_SET_ENABLED) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		spin_lock(&hymo_cfg_lock);
		hymofs_enabled = !!val;
		spin_unlock(&hymo_cfg_lock);
		if (hymofs_enabled)
			hymo_reload_ksu_allowlist();
		return 0;
	}

	if (cmd == HYMO_IOC_REORDER_MNT_ID) {
		/* struct mnt_namespace/mount not exposed to LKM; only KPM (built-in) supports this */
		return -EOPNOTSUPP;
	}

	if (cmd == HYMO_IOC_LIST_RULES) {
		struct hymo_syscall_list_arg list_arg;
		struct hymo_xattr_sb_entry *sb_entry;
		struct hymo_merge_entry *merge_entry;
		char *kbuf;
		size_t buf_size, written = 0;
		int bkt;

		if (copy_from_user(&list_arg, arg, sizeof(list_arg)))
			return -EFAULT;

		buf_size = list_arg.size;
		if (buf_size > 64 * 1024)
			buf_size = 64 * 1024;

		kbuf = kzalloc(buf_size, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;

		rcu_read_lock();
		written += scnprintf(kbuf + written, buf_size - written,
				     "HymoFS Protocol: %d\n", HYMO_PROTOCOL_VERSION);
		written += scnprintf(kbuf + written, buf_size - written,
				     "HymoFS Enabled: %d\n", hymofs_enabled ? 1 : 0);
		hash_for_each_rcu(hymo_paths, bkt, entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "add %s %s %d\n", entry->src,
					     entry->target, entry->type);
		}
		hash_for_each_rcu(hymo_hide_paths, bkt, hide_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "hide %s\n", hide_entry->path);
		}
		hash_for_each_rcu(hymo_inject_dirs, bkt, inject_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "inject %s\n", inject_entry->dir);
		}
		hash_for_each_rcu(hymo_merge_dirs, bkt, merge_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "merge %s %s\n", merge_entry->src,
					     merge_entry->target);
		}
		hash_for_each_rcu(hymo_merge_dirs, bkt, merge_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "merge %s %s\n", merge_entry->src,
					     merge_entry->target);
		}
		hash_for_each_rcu(hymo_xattr_sbs, bkt, sb_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "hide_xattr_sb %p\n", sb_entry->sb);
		}
		rcu_read_unlock();

		if (copy_to_user(list_arg.buf, kbuf, written)) {
			kfree(kbuf);
			return -EFAULT;
		}
		list_arg.size = written;
		if (copy_to_user(arg, &list_arg, sizeof(list_arg))) {
			kfree(kbuf);
			return -EFAULT;
		}
		kfree(kbuf);
		return 0;
	}

	if (cmd == HYMO_IOC_SET_MIRROR_PATH) {
		char *new_path, *new_name, *slash;
		size_t len;

		if (copy_from_user(&req, arg, sizeof(req)))
			return -EFAULT;
		if (!req.src)
			return -EINVAL;
		new_path = hymo_strndup_user(req.src, PATH_MAX);
		if (IS_ERR(new_path))
			return PTR_ERR(new_path);

		len = strlen(new_path);
		if (len > 1 && new_path[len - 1] == '/')
			new_path[len - 1] = '\0';

		slash = strrchr(new_path, '/');
		new_name = kstrdup(slash ? slash + 1 : new_path, GFP_KERNEL);
		if (!new_name) {
			kfree(new_path);
			return -ENOMEM;
		}

		spin_lock(&hymo_cfg_lock);
		strscpy(hymo_mirror_path_buf, new_path, PATH_MAX);
		strscpy(hymo_mirror_name_buf, new_name, NAME_MAX);
		hymo_current_mirror_path = hymo_mirror_path_buf;
		hymo_current_mirror_name = hymo_mirror_name_buf;
		spin_unlock(&hymo_cfg_lock);

		kfree(new_path);
		kfree(new_name);
		return 0;
	}

	if (cmd == HYMO_IOC_SET_UNAME) {
		struct hymo_spoof_uname u;
		if (copy_from_user(&u, arg, sizeof(u)))
			return -EFAULT;
		spin_lock(&hymo_uname_lock);
		memcpy(&hymo_spoof_uname_store, &u, sizeof(hymo_spoof_uname_store));
		hymo_uname_spoof_active = (u.sysname[0] || u.nodename[0] || u.release[0] ||
					   u.version[0] || u.machine[0] || u.domainname[0]);
		spin_unlock(&hymo_uname_lock);
		return 0;
	}

	/* Commands that use hymo_syscall_arg */
	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	if (req.src) {
		src = hymo_strndup_user(req.src, PAGE_SIZE);
		if (IS_ERR(src))
			return PTR_ERR(src);
	}
	if (req.target) {
		target = hymo_strndup_user(req.target, PAGE_SIZE);
		if (IS_ERR(target)) {
			kfree(src);
			return PTR_ERR(target);
		}
	}

	switch (cmd) {
	case HYMO_IOC_ADD_MERGE_RULE: {
		struct hymo_merge_entry *me;
		char *mat_src = NULL, *mat_tgt = NULL;

		if (!src || !target) { ret = -EINVAL; break; }

		/* Resolve symlinks: d_absolute_path in iterate_dir returns
		 * canonical paths (e.g. /product/overlay), while userspace sends
		 * symlink paths (e.g. /system/product/overlay). Store the
		 * canonical form as resolved_src for iterate_dir matching. */
		{
			char *resolved_src = NULL;
			struct dentry *tgt_dentry = NULL;
			struct path mpath;

			if (hymo_kern_path(src, LOOKUP_FOLLOW, &mpath) == 0) {
				char *rbuf = kmalloc(PATH_MAX, GFP_KERNEL);
				if (rbuf) {
					char *res = d_path(&mpath, rbuf, PATH_MAX);
					if (!IS_ERR(res) && res[0] == '/' &&
					    strcmp(res, src) != 0)
						resolved_src = kstrdup(res, GFP_KERNEL);
					kfree(rbuf);
				}
				path_put(&mpath);
			}
			if (hymo_kern_path(target, LOOKUP_FOLLOW, &mpath) == 0) {
				tgt_dentry = dget(mpath.dentry);
				path_put(&mpath);
			}

			hash = full_name_hash(NULL, src, strlen(src));
			spin_lock(&hymo_merge_lock);
			spin_lock(&hymo_inject_lock);

			hlist_for_each_entry(me,
				&hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
				if (strcmp(me->src, src) == 0 &&
				    strcmp(me->target, target) == 0) {
					found = true;
					break;
				}
			}
			if (!found) {
				me = kmalloc(sizeof(*me), GFP_ATOMIC);
				if (me) {
					mat_src = kstrdup(src, GFP_ATOMIC);
					mat_tgt = kstrdup(target, GFP_ATOMIC);
					me->src = src;
					me->target = target;
					me->resolved_src = resolved_src;
					me->target_dentry = tgt_dentry;
					resolved_src = NULL;
					tgt_dentry = NULL;
					hlist_add_head_rcu(&me->node,
						&hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)]);
					src = NULL;
					target = NULL;
				} else {
					ret = -ENOMEM;
				}
			} else {
				ret = -EEXIST;
			}
			spin_unlock(&hymo_inject_lock);
			spin_unlock(&hymo_merge_lock);
			if (!found && !ret) {
				hymofs_add_inject_rule(kstrdup(me->src, GFP_KERNEL));
				if (me->resolved_src)
					hymofs_add_inject_rule(kstrdup(me->resolved_src, GFP_KERNEL));
				hymofs_mark_dir_has_inject(me->src);
				if (me->resolved_src)
					hymofs_mark_dir_has_inject(me->resolved_src);
				if (mat_src && mat_tgt)
					hymofs_materialize_merge(mat_src, mat_tgt, 0);
			}
			kfree(resolved_src);
			if (tgt_dentry)
				dput(tgt_dentry);
			kfree(mat_src);
			kfree(mat_tgt);
		}
		spin_lock(&hymo_cfg_lock);
		hymofs_enabled = true;
		spin_unlock(&hymo_cfg_lock);
		break;
	}

	case HYMO_IOC_ADD_RULE: {
		char *parent_dir = NULL;
		char *resolved_src = NULL;
		struct path path;
		struct inode *src_inode = NULL;
		struct inode *parent_inode = NULL;
		char *tmp_buf;

		if (!src || !target) { ret = -EINVAL; break; }

		tmp_buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!tmp_buf) { ret = -ENOMEM; break; }

		/* Try to resolve full path */
		if (hymo_kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
			char *res = d_path(&path, tmp_buf, PATH_MAX);
			if (!IS_ERR(res)) {
				resolved_src = kstrdup(res, GFP_KERNEL);
				{
					char *ls = strrchr(res, '/');
					if (ls) {
						if (ls == res)
							parent_dir = kstrdup("/", GFP_KERNEL);
						else {
							size_t l = ls - res;
							parent_dir = kmalloc(l + 1, GFP_KERNEL);
							if (parent_dir) {
								memcpy(parent_dir, res, l);
								parent_dir[l] = '\0';
							}
						}
					}
				}
			}
			if (d_inode(path.dentry)) {
				src_inode = d_inode(path.dentry);
				hymo_ihold(src_inode);
			}
			if (path.dentry->d_parent && d_inode(path.dentry->d_parent)) {
				parent_inode = d_inode(path.dentry->d_parent);
				hymo_ihold(parent_inode);
			}
			path_put(&path);
		} else {
			char *ls = strrchr(src, '/');
			if (ls && ls != src) {
				size_t l = ls - src;
				char *p_str = kmalloc(l + 1, GFP_KERNEL);
				if (p_str) {
					memcpy(p_str, src, l);
					p_str[l] = '\0';
					if (hymo_kern_path(p_str, LOOKUP_FOLLOW, &path) == 0) {
						char *res = d_path(&path, tmp_buf, PATH_MAX);
						if (!IS_ERR(res)) {
							size_t rl = strlen(res);
							size_t nl = strlen(ls);
							resolved_src = kmalloc(rl + nl + 1, GFP_KERNEL);
							if (resolved_src) {
								strcpy(resolved_src, res);
								strcat(resolved_src, ls);
							}
							parent_dir = kstrdup(res, GFP_KERNEL);
						}
						path_put(&path);
					}
					kfree(p_str);
				}
			}
		}
		kfree(tmp_buf);

		if (resolved_src) {
			kfree(src);
			src = resolved_src;
		}

		hash = full_name_hash(NULL, src, strlen(src));
		spin_lock(&hymo_rules_lock);

		hlist_for_each_entry(entry,
			&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (entry->src_hash == hash && strcmp(entry->src, src) == 0) {
				char *old_t = entry->target;
				char *new_t = kstrdup(target, GFP_ATOMIC);
				if (new_t) {
					hlist_del_rcu(&entry->target_node);
					rcu_assign_pointer(entry->target, new_t);
					entry->type = req.type;
					hlist_add_head_rcu(&entry->target_node,
						&hymo_targets[hash_min(
							full_name_hash(NULL, new_t, strlen(new_t)),
							HYMO_HASH_BITS)]);
					kfree(old_t);
				}
				found = true;
				break;
			}
		}
		if (!found) {
			entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
			if (entry) {
				entry->src = kstrdup(src, GFP_ATOMIC);
				entry->target = kstrdup(target, GFP_ATOMIC);
				entry->type = req.type;
				entry->src_hash = hash;
				if (entry->src && entry->target) {
					unsigned long h1, h2;
					hlist_add_head_rcu(&entry->node,
						&hymo_paths[hash_min(hash, HYMO_HASH_BITS)]);
					hlist_add_head_rcu(&entry->target_node,
						&hymo_targets[hash_min(
							full_name_hash(NULL, entry->target,
								strlen(entry->target)),
							HYMO_HASH_BITS)]);
					h1 = jhash(src, strlen(src), 0) & (HYMO_BLOOM_SIZE - 1);
					h2 = jhash(src, strlen(src), 1) & (HYMO_BLOOM_SIZE - 1);
					set_bit(h1, hymo_path_bloom);
					set_bit(h2, hymo_path_bloom);
					atomic_inc(&hymo_rule_count);
				} else {
					kfree(entry->src);
					kfree(entry->target);
					kfree(entry);
				}
			}
		}
		spin_unlock(&hymo_rules_lock);

		if (parent_dir) {
			hymofs_add_inject_rule(parent_dir);
			hymofs_mark_dir_has_inject(parent_dir);
		}

		/* Inode marking: hide source in dir listing; mark parent for fast filldir skip. */
		if (src_inode) {
			hymofs_mark_inode_hidden(src_inode);
			iput(src_inode);
		}
		if (parent_inode) {
			if (parent_inode->i_mapping)
				set_bit(AS_FLAGS_HYMO_DIR_HAS_HIDDEN,
					&parent_inode->i_mapping->flags);
			iput(parent_inode);
		}

		spin_lock(&hymo_cfg_lock);
		hymofs_enabled = true;
		spin_unlock(&hymo_cfg_lock);
		break;
	}

	case HYMO_IOC_HIDE_RULE: {
		char *resolved_src = NULL;
		struct path path;
		struct inode *target_inode = NULL;
		struct inode *parent_inode = NULL;
		char *tmp_buf;

		if (!src) { ret = -EINVAL; break; }

		tmp_buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!tmp_buf) { ret = -ENOMEM; break; }

		if (hymo_kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
			char *res = d_path(&path, tmp_buf, PATH_MAX);
			if (!IS_ERR(res))
				resolved_src = kstrdup(res, GFP_KERNEL);
			if (d_inode(path.dentry)) {
				target_inode = d_inode(path.dentry);
				hymo_ihold(target_inode);
			}
			if (path.dentry->d_parent && d_inode(path.dentry->d_parent)) {
				parent_inode = d_inode(path.dentry->d_parent);
				hymo_ihold(parent_inode);
			}
			path_put(&path);
		}
		kfree(tmp_buf);

		if (resolved_src) {
			kfree(src);
			src = resolved_src;
		}

		if (target_inode) {
			hymofs_mark_inode_hidden(target_inode);
			iput(target_inode);
		}
		if (parent_inode) {
			if (parent_inode->i_mapping)
				set_bit(AS_FLAGS_HYMO_DIR_HAS_HIDDEN,
					&parent_inode->i_mapping->flags);
			iput(parent_inode);
		}

		hash = full_name_hash(NULL, src, strlen(src));
		spin_lock(&hymo_hide_lock);
		hlist_for_each_entry(hide_entry,
			&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (hide_entry->path_hash == hash &&
			    strcmp(hide_entry->path, src) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			hide_entry = kmalloc(sizeof(*hide_entry), GFP_ATOMIC);
			if (hide_entry) {
				hide_entry->path = kstrdup(src, GFP_ATOMIC);
				hide_entry->path_hash = hash;
				if (hide_entry->path) {
					unsigned long h1 = jhash(src, strlen(src), 0) & (HYMO_BLOOM_SIZE - 1);
					unsigned long h2 = jhash(src, strlen(src), 1) & (HYMO_BLOOM_SIZE - 1);
					set_bit(h1, hymo_hide_bloom);
					set_bit(h2, hymo_hide_bloom);
					atomic_inc(&hymo_hide_count);
					hlist_add_head_rcu(&hide_entry->node,
						&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)]);
				} else {
					kfree(hide_entry);
				}
			}
		}
		spin_unlock(&hymo_hide_lock);

		spin_lock(&hymo_cfg_lock);
		hymofs_enabled = true;
		spin_unlock(&hymo_cfg_lock);
		break;
	}

	case HYMO_IOC_HIDE_OVERLAY_XATTRS: {
		struct path path;
		struct hymo_xattr_sb_entry *sb_entry;
		bool xfound = false;

		if (!src) { ret = -EINVAL; break; }

		if (hymo_kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
			struct super_block *sb = path.dentry->d_sb;

			spin_lock(&hymo_xattr_sbs_lock);
			hlist_for_each_entry(sb_entry,
				&hymo_xattr_sbs[hash_min((unsigned long)sb, HYMO_HASH_BITS)], node) {
				if (sb_entry->sb == sb) {
					xfound = true;
					break;
				}
			}
			if (!xfound) {
				sb_entry = kmalloc(sizeof(*sb_entry), GFP_ATOMIC);
				if (sb_entry) {
					sb_entry->sb = sb;
					hlist_add_head_rcu(&sb_entry->node,
						&hymo_xattr_sbs[hash_min((unsigned long)sb,
							HYMO_HASH_BITS)]);
				}
			}
			spin_unlock(&hymo_xattr_sbs_lock);
			spin_lock(&hymo_cfg_lock);
			hymofs_enabled = true;
			spin_unlock(&hymo_cfg_lock);
			path_put(&path);
		} else {
			ret = -ENOENT;
		}
		break;
	}

	case HYMO_IOC_DEL_RULE:
		if (!src) { ret = -EINVAL; break; }
		hash = full_name_hash(NULL, src, strlen(src));
		spin_lock(&hymo_rules_lock);
		spin_lock(&hymo_hide_lock);
		spin_lock(&hymo_inject_lock);

		hlist_for_each_entry(entry,
			&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (entry->src_hash == hash && strcmp(entry->src, src) == 0) {
				hlist_del_rcu(&entry->node);
				hlist_del_rcu(&entry->target_node);
				atomic_dec(&hymo_rule_count);
				call_rcu(&entry->rcu, hymo_entry_free_rcu);
				goto del_done;
			}
		}
		hlist_for_each_entry(hide_entry,
			&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (hide_entry->path_hash == hash &&
			    strcmp(hide_entry->path, src) == 0) {
				hlist_del_rcu(&hide_entry->node);
				atomic_dec(&hymo_hide_count);
				call_rcu(&hide_entry->rcu, hymo_hide_entry_free_rcu);
				goto del_done;
			}
		}
		hlist_for_each_entry(inject_entry,
			&hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (strcmp(inject_entry->dir, src) == 0) {
				hlist_del_rcu(&inject_entry->node);
				atomic_dec(&hymo_rule_count);
				call_rcu(&inject_entry->rcu, hymo_inject_entry_free_rcu);
				goto del_done;
			}
		}
del_done:
		spin_unlock(&hymo_inject_lock);
		spin_unlock(&hymo_hide_lock);
		spin_unlock(&hymo_rules_lock);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	kfree(src);
	kfree(target);
	return ret;
}

/* ======================================================================
 * Part 16: Ioctl Handler
 * ====================================================================== */

static HYMO_NOCFI long hymofs_dev_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	long ret;

	atomic_long_set(&hymo_ioctl_tgid, (long)task_tgid_vnr(current));
	switch (cmd) {
	case HYMO_IOC_GET_VERSION:
	case HYMO_IOC_SET_ENABLED:
	case HYMO_IOC_ADD_RULE:
	case HYMO_IOC_DEL_RULE:
	case HYMO_IOC_HIDE_RULE:
	case HYMO_IOC_CLEAR_ALL:
	case HYMO_IOC_LIST_RULES:
	case HYMO_IOC_SET_DEBUG:
	case HYMO_IOC_REORDER_MNT_ID:
	case HYMO_IOC_SET_STEALTH:
	case HYMO_IOC_HIDE_OVERLAY_XATTRS:
	case HYMO_IOC_ADD_MERGE_RULE:
	case HYMO_IOC_SET_MIRROR_PATH:
	case HYMO_IOC_SET_UNAME:
		ret = hymo_dispatch_cmd(cmd, (void __user *)arg);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	atomic_long_set(&hymo_ioctl_tgid, 0);
	return ret;
}

/* ======================================================================
 * Part 17: Anonymous fd (no device node; syscall returns this fd)
 * ====================================================================== */

static const struct file_operations hymo_anon_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = hymofs_dev_ioctl,
	.compat_ioctl   = hymofs_dev_ioctl,
	.llseek         = noop_llseek,
};

/**
 * hymofs_get_anon_fd - Create and return anonymous fd for HymoFS.
 * Returns fd on success, negative errno on failure.
 */
int hymofs_get_anon_fd(void)
{
	int fd;
	pid_t pid;

	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return -EPERM;
	fd = anon_inode_getfd("hymo", &hymo_anon_fops, NULL, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fd;
	pid = task_tgid_vnr(current);
	spin_lock(&hymo_daemon_lock);
	hymo_daemon_pid = pid;
	spin_unlock(&hymo_daemon_lock);
	return fd;
}
EXPORT_SYMBOL_GPL(hymofs_get_anon_fd);

/* GET_FD via kprobe on ni_syscall (unused nr) or __arm64_sys_reboot (142). Default 142 = SYS_reboot for 5.10 compat. */
static int hymo_syscall_nr_param = 142;
module_param_named(hymo_syscall_nr, hymo_syscall_nr_param, int, 0600);
MODULE_PARM_DESC(hymo_syscall_nr, "For ni_syscall path: unused syscall nr (e.g. 448). Primary path is SYS_reboot(142) via __arm64_sys_reboot kprobe.");

/* Per-CPU: when set, kretprobe will replace return value with this fd. */
static DEFINE_PER_CPU(int, hymo_override_fd);
static DEFINE_PER_CPU(int, hymo_override_active);

static int hymo_ni_syscall_pre(struct kprobe *p, struct pt_regs *regs)
{
#if defined(__aarch64__)
	unsigned long nr = regs->regs[8];
	unsigned long a0 = regs->regs[0];
	unsigned long a1 = regs->regs[1];
	unsigned long a2 = regs->regs[2];
#elif defined(__x86_64__)
	unsigned long nr = regs->orig_ax;
	unsigned long a0 = regs->di;
	unsigned long a1 = regs->si;
	unsigned long a2 = regs->dx;
#else
	unsigned long nr = 0, a0 = 0, a1 = 0, a2 = 0;
#endif
	if (nr != (unsigned long)hymo_syscall_nr_param)
		return 0;
	if (a0 != HYMO_MAGIC1 || a1 != HYMO_MAGIC2 || a2 != (unsigned long)HYMO_CMD_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;
	{
		int fd = hymofs_get_anon_fd();
		if (fd < 0)
			return 0;
		this_cpu_write(hymo_override_fd, fd);
		this_cpu_write(hymo_override_active, 1);
	}
	return 0;
}

/*
 * kretprobe handler: replace function return value (x0) with our fd.
 *
 * On aarch64 >= 4.16 the call chain is:
 *   invoke_syscall() {
 *       ret = __arm64_sys_reboot(regs);  // <-- kretprobe fires here
 *       regs->regs[0] = ret;             // stores ret into user pt_regs
 *   }
 * So we MUST modify the kretprobe's own regs->regs[0] (= function return value x0).
 * invoke_syscall will then copy our fd into the user's pt_regs.
 * Writing to real_regs directly would be overwritten by invoke_syscall.
 */
static int hymo_ni_syscall_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!this_cpu_read(hymo_override_active))
		return 0;
#if defined(__aarch64__)
	regs->regs[0] = this_cpu_read(hymo_override_fd);
#elif defined(__x86_64__)
	regs->ax = this_cpu_read(hymo_override_fd);
#endif
	this_cpu_write(hymo_override_active, 0);
	return 0;
}

static struct kprobe hymo_kp_ni = {
	.pre_handler = hymo_ni_syscall_pre,
};
static struct kretprobe hymo_krp_ni = {
	.handler = hymo_ni_syscall_ret,
};

/*
 * GET_FD via kprobe on __arm64_sys_reboot (same as susfs/KernelSU old kprobes).
 * When userspace calls SYS_reboot(142) with our magic, we intercept and return fd in kretprobe.
 * Real reboot sees invalid magic and returns -EINVAL; we overwrite return value with fd.
 * Compatible with 5.10+; use this when ni_syscall path is not available.
 */
static int hymo_reboot_pre(struct kprobe *p, struct pt_regs *regs)
{
	/*
	 * On aarch64 4.16+, __arm64_sys_reboot is a wrapper: first arg (regs->regs[0])
	 * is the pointer to the real syscall pt_regs. Read magic from there.
	 *
	 * We use the KernelSU approach: write fd to userspace via put_user on the
	 * 4th syscall argument (a user pointer). This avoids kretprobe return value
	 * issues entirely — invoke_syscall would overwrite any kretprobe changes.
	 *
	 * Userspace: int fd = -1; syscall(SYS_reboot, M1, M2, CMD, &fd);
	 */
#if defined(__aarch64__)
	struct pt_regs *real_regs;
	unsigned long a0, a1, a2;
	int __user *fd_ptr;
	int fd;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
	real_regs = (struct pt_regs *)regs->regs[0];
#else
	real_regs = regs;
#endif
	a0 = real_regs->regs[0];
	a1 = real_regs->regs[1];
	a2 = real_regs->regs[2];

	if (a0 != HYMO_MAGIC1 || a1 != HYMO_MAGIC2 || a2 != (unsigned long)HYMO_CMD_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;

	fd = hymofs_get_anon_fd();
	if (fd < 0)
		return 0;

	/* Write fd to userspace via 4th arg pointer (like KernelSU) */
	fd_ptr = (int __user *)(unsigned long)real_regs->regs[3];
	if (fd_ptr)
		put_user(fd, fd_ptr);
#elif defined(__x86_64__)
	unsigned long a0 = regs->di;
	unsigned long a1 = regs->si;
	unsigned long a2 = regs->dx;

	if (a0 != HYMO_MAGIC1 || a1 != HYMO_MAGIC2 || a2 != (unsigned long)HYMO_CMD_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;
	{
		int fd = hymofs_get_anon_fd();
		if (fd < 0)
			return 0;
		this_cpu_write(hymo_override_fd, fd);
		this_cpu_write(hymo_override_active, 1);
	}
#endif
	return 0;
}

static struct kprobe hymo_kp_reboot = {
	.pre_handler = hymo_reboot_pre,
};
static struct kretprobe hymo_krp_reboot = {
	.handler = hymo_ni_syscall_ret, /* same: replace return with fd */
};
static int hymo_reboot_kprobe_registered;

/*
 * GET_FD via prctl (SECCOMP-safe). option=HYMO_PRCTL_GET_FD, arg2=(int *) for fd.
 * No kretprobe: we put_user(fd, arg2) in pre_handler; syscall return value ignored.
 */
static int hymo_prctl_pre(struct kprobe *p, struct pt_regs *regs)
{
#if defined(__aarch64__)
	struct pt_regs *real_regs;
	unsigned long option;
	unsigned long arg2;
	int __user *fd_ptr;
	int fd;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
	real_regs = (struct pt_regs *)regs->regs[0];
#else
	real_regs = regs;
#endif
	option = real_regs->regs[0];
	arg2 = real_regs->regs[1];

	if (option != (unsigned long)HYMO_PRCTL_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;

	fd = hymofs_get_anon_fd();
	if (fd < 0)
		return 0;

	fd_ptr = (int __user *)(unsigned long)arg2;
	if (fd_ptr && put_user(fd, fd_ptr) != 0)
		pr_err("hymofs: prctl GET_FD put_user failed\n");
#elif defined(__x86_64__)
	unsigned long option = regs->di;
	unsigned long arg2 = regs->si;

	if (option != (unsigned long)HYMO_PRCTL_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;
	{
		int fd = hymofs_get_anon_fd();
		int __user *fd_ptr;

		if (fd < 0)
			return 0;
		fd_ptr = (int __user *)(unsigned long)arg2;
		if (fd_ptr && put_user(fd, fd_ptr) != 0)
			pr_err("hymofs: prctl GET_FD put_user failed\n");
	}
#endif
	return 0;
}

static struct kprobe hymo_kp_prctl = {
	.pre_handler = hymo_prctl_pre,
};
static int hymo_prctl_kprobe_registered;

/* ======================================================================
 * uname spoofing: kretprobe on __arm64_sys_newuname / __x64_sys_newuname
 * On return, kernel has filled user buf; we overwrite with spoofed values.
 * ====================================================================== */

static int hymo_uname_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	void __user *buf;
#if defined(__aarch64__)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
	struct pt_regs *real_regs = (struct pt_regs *)regs->regs[0];
	buf = (void __user *)real_regs->regs[0];
#else
	buf = (void __user *)regs->regs[0];
#endif
#elif defined(__x86_64__)
	buf = (void __user *)regs->di;
#else
	buf = NULL;
#endif
	*(void __user **)ri->data = buf;
	return 0;
}

static int hymo_uname_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	void __user *buf = *(void __user **)ri->data;
	struct new_utsname kbuf;
	struct hymo_spoof_uname spoof;
	pid_t pid;

	if (!buf || !hymo_uname_spoof_active)
		return 0;
	pid = task_tgid_vnr(current);
	if (hymo_daemon_pid > 0 && pid == hymo_daemon_pid)
		return 0;
	if (copy_from_user(&kbuf, buf, sizeof(kbuf)))
		return 0;
	spin_lock(&hymo_uname_lock);
	spoof = hymo_spoof_uname_store;
	spin_unlock(&hymo_uname_lock);
	if (spoof.sysname[0])
		strscpy(kbuf.sysname, spoof.sysname, sizeof(kbuf.sysname));
	if (spoof.nodename[0])
		strscpy(kbuf.nodename, spoof.nodename, sizeof(kbuf.nodename));
	if (spoof.release[0])
		strscpy(kbuf.release, spoof.release, sizeof(kbuf.release));
	if (spoof.version[0])
		strscpy(kbuf.version, spoof.version, sizeof(kbuf.version));
	if (spoof.machine[0])
		strscpy(kbuf.machine, spoof.machine, sizeof(kbuf.machine));
	if (spoof.domainname[0])
		strscpy(kbuf.domainname, spoof.domainname, sizeof(kbuf.domainname));
	if (copy_to_user(buf, &kbuf, sizeof(kbuf)))
		; /* ignore */
	return 0;
}

static struct kretprobe hymo_krp_uname = {
	.entry_handler = hymo_uname_entry,
	.handler = hymo_uname_ret,
	.data_size = sizeof(void __user *),
	.maxactive = 64,
};
static int hymo_uname_kprobe_registered;

/* ======================================================================
 * iterate_dir: filldir filter (runs in fs callback context, not kprobe)
 * ====================================================================== */

static HYMO_FILLDIR_RET_TYPE
hymofs_filldir_filter(struct dir_context *ctx, const char *name,
		      int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	struct hymofs_filldir_wrapper *w =
		container_of(ctx, struct hymofs_filldir_wrapper, wrap_ctx);
	HYMO_FILLDIR_RET_TYPE ret;

	/* Inject phase: before first real entry, emit entries from merge targets
	 * and hymo_paths into the directory listing. */
	if (w->dir_has_inject && !w->inject_done && w->dir_path && w->parent_dentry) {
		struct list_head head;
		struct hymo_name_list *item, *tmp;
		loff_t inj_pos = HYMO_MAGIC_POS;

		w->inject_done = true;
		INIT_LIST_HEAD(&head);
		hymofs_populate_injected_list(w->dir_path, w->parent_dentry, &head);

		list_for_each_entry_safe(item, tmp, &head, list) {
			int nlen = strlen(item->name);
			ret = w->orig_ctx->actor(w->orig_ctx, item->name, nlen,
						 inj_pos, 1, item->type);
			list_del(&item->list);
			kfree(item->name);
			kfree(item);
			if (ret != HYMO_FILLDIR_CONTINUE) {
				list_for_each_entry_safe(item, tmp, &head, list) {
					list_del(&item->list);
					kfree(item->name);
					kfree(item);
				}
				return ret;
			}
			inj_pos++;
		}
	}

	if (unlikely(namlen <= 2 && name[0] == '.')) {
		if (namlen == 1 || (namlen == 2 && name[1] == '.'))
			goto passthrough;
	}

	if (hymo_stealth_enabled && w->dir_path_len == 4) {
		size_t mlen = strlen(hymo_current_mirror_name);
		if ((unsigned int)namlen == mlen &&
		    memcmp(name, hymo_current_mirror_name, namlen) == 0)
			return HYMO_FILLDIR_CONTINUE;
	}

	/* Hide real entries that also exist in merge targets. This prevents
	 * duplicates: the injected version (from populate_injected_list)
	 * replaces the original, just like original hymofs.c does.
	 * Skip when merge target IS the dir we're listing (e.g. target path
	 * resolved to same inode via symlink) - otherwise we'd hide everything. */
	if (w->merge_target_count > 0 && w->parent_dentry) {
		int i;
		for (i = 0; i < w->merge_target_count; i++) {
			struct dentry *tgt = w->merge_target_dentries[i];
			if (!tgt || tgt == w->parent_dentry)
				continue;
			if (d_inode(tgt) && d_inode(tgt) == d_inode(w->parent_dentry))
				continue;
			{
				struct dentry *child = hymo_d_hash_and_lookup(tgt,
					&(struct qstr)QSTR_INIT(name, namlen));
				if (child) {
					dput(child);
					return HYMO_FILLDIR_CONTINUE;
				}
			}
		}
	}

	if (w->dir_has_hidden && w->parent_dentry &&
	    !hymo_is_privileged_process() && hymo_should_apply_hide_rules()) {
		struct dentry *child;

		child = hymo_d_hash_and_lookup(w->parent_dentry,
				&(struct qstr)QSTR_INIT(name, namlen));
		if (child) {
			struct inode *cinode = d_inode(child);
			if (cinode && cinode->i_mapping &&
			    test_bit(AS_FLAGS_HYMO_HIDE,
				     &cinode->i_mapping->flags)) {
				dput(child);
				return HYMO_FILLDIR_CONTINUE;
			}
			dput(child);
		}
	}

passthrough:
	return w->orig_ctx->actor(w->orig_ctx, name, namlen, offset, ino, d_type);
}

/* ======================================================================
 * Kprobe pre_handlers (modify regs / user path only; return 0 to run original)
 * ====================================================================== */

#if defined(__aarch64__)
#define HYMO_REG0(regs)		((regs)->regs[0])
#define HYMO_REG1(regs)		((regs)->regs[1])
#define HYMO_REG2(regs)		((regs)->regs[2])
#define HYMO_REG3(regs)		((regs)->regs[3])
#define HYMO_REG4(regs)		((regs)->regs[4])
#define HYMO_LR(regs)		((regs)->regs[30])
#define HYMO_POP_STACK(regs)	do { } while (0)
#elif defined(__x86_64__)
#define HYMO_REG0(regs)		((regs)->di)
#define HYMO_REG1(regs)		((regs)->si)
#define HYMO_REG2(regs)		((regs)->dx)
#define HYMO_REG3(regs)		((regs)->cx)
#define HYMO_REG4(regs)		((regs)->r8)
#define HYMO_LR(regs)		(*(unsigned long *)(regs)->sp)
#define HYMO_POP_STACK(regs)	do { (regs)->sp += 8; } while (0)
#elif defined(__arm__)
/* ARM32: pt_regs uses uregs[] (r0=0, r1=1, ..., lr=14, pc=15) */
#define HYMO_REG0(regs)		((regs)->uregs[0])
#define HYMO_REG1(regs)		((regs)->uregs[1])
#define HYMO_REG2(regs)		((regs)->uregs[2])
#define HYMO_REG3(regs)		((regs)->uregs[3])
#define HYMO_REG4(regs)		((regs)->uregs[4])
#define HYMO_LR(regs)		((regs)->uregs[14])
#define HYMO_POP_STACK(regs)	do { } while (0)
#else
#define HYMO_REG0(regs)		(0)
#define HYMO_REG1(regs)		(0)
#define HYMO_REG2(regs)		(0)
#define HYMO_REG3(regs)		(0)
#define HYMO_REG4(regs)		(0)
#define HYMO_LR(regs)		(0)
#define HYMO_POP_STACK(regs)	do { } while (0)
#endif

/*
 * vfs_getattr / vfs_getxattr argument positions across kernel versions.
 * <5.12:  vfs_getattr(path, kstat, mask, flags)
 * >=5.12: vfs_getattr(userns/idmap, path, kstat, mask, flags)
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
#define HYMO_GETATTR_PATH_REG(regs) HYMO_REG1(regs)
#define HYMO_GETATTR_STAT_REG(regs) HYMO_REG2(regs)
#define HYMO_GETXATTR_DENTRY_REG(regs) HYMO_REG1(regs)
#define HYMO_GETXATTR_NAME_REG(regs)   HYMO_REG2(regs)
#define HYMO_GETXATTR_VALUE_REG(regs)  HYMO_REG3(regs)
#define HYMO_GETXATTR_SIZE_REG(regs)   HYMO_REG4(regs)
#else
#define HYMO_GETATTR_PATH_REG(regs) HYMO_REG0(regs)
#define HYMO_GETATTR_STAT_REG(regs) HYMO_REG1(regs)
#define HYMO_GETXATTR_DENTRY_REG(regs) HYMO_REG0(regs)
#define HYMO_GETXATTR_NAME_REG(regs)   HYMO_REG1(regs)
#define HYMO_GETXATTR_VALUE_REG(regs)  HYMO_REG2(regs)
#define HYMO_GETXATTR_SIZE_REG(regs)   HYMO_REG3(regs)
#endif

/*
 * Atomic-safe user access for kprobe pre-handler (cannot sleep).
 * copy_from_user/copy_to_user may sleep on page fault -> use nofault variants.
 * Resolved dynamically via kallsyms (not exported on GKI).
 * CFI-safe wrapper defined earlier in the file.
 */

#if HYMOFS_USE_SYSCALL_TRACEPOINT && HYMOFS_TP_AVAILABLE
/* Path for hide: non-existent so syscall fails with ENOENT */
#define HYMO_HIDE_PATH "/.hymo_hidden_placeholder"

static char __user *hymo_userspace_stack_buffer(const char *data, size_t len)
{
	char __user *p;

	if (!current->mm)
		return NULL;
	p = (void __user *)current_user_stack_pointer() - len;
	return copy_to_user(p, data, len) ? NULL : p;
}

static inline bool hymo_tp_check_path_syscall(long id)
{
	switch (id) {
	case __NR_openat:
	case __NR_faccessat:
	case __NR_newfstatat:
	case __NR_execve:
#ifdef __NR_execveat
	case __NR_execveat:
#endif
#ifdef __NR_openat2
	case __NR_openat2:
#endif
		return true;
	default:
		return false;
	}
}

static HYMO_NOCFI void hymo_sys_enter_handler(void *data, struct pt_regs *regs, long id)
{
	const char __user *filename_user;
	char *buf;
	char *target;
	char __user *new_path;
	u64 *path_reg;

	(void)data;

	if (!hymo_tp_check_path_syscall(id))
		return;
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return;
	if (atomic_long_read(&hymo_xattr_source_tgid) == (long)task_tgid_vnr(current))
		return;

	/* execve: path in parm1; openat/faccessat/newfstatat/execveat: path in parm2 */
	path_reg = (id == __NR_execve) ? &HYMO_REG0(regs) : &HYMO_REG1(regs);
	filename_user = (const char __user *)(uintptr_t)*path_reg;
	if (!filename_user)
		return;

	buf = this_cpu_ptr(hymo_getname_path_buf);
	if (hymo_strncpy_from_user_nofault_ptr) {
		long ret = hymo_strncpy_from_user_nofault(buf, filename_user, HYMO_PATH_BUF - 1);
		if (ret < 0)
			return;
		buf[ret < (long)(HYMO_PATH_BUF - 1) ? ret : (long)(HYMO_PATH_BUF - 1)] = '\0';
	} else {
		if (copy_from_user(buf, filename_user, HYMO_PATH_BUF - 1))
			return;
		buf[HYMO_PATH_BUF - 1] = '\0';
	}

	if (likely(hash_empty(hymo_paths) &&
		   hash_empty(hymo_hide_paths) &&
		   hash_empty(hymo_merge_dirs)))
		return;

	if (unlikely(hymofs_should_hide(buf))) {
		new_path = hymo_userspace_stack_buffer(HYMO_HIDE_PATH, sizeof(HYMO_HIDE_PATH));
		if (new_path) {
			*path_reg = (u64)(uintptr_t)new_path;
		}
		return;
	}

	if (buf[0] != '/')
		return;
	target = hymofs_resolve_target(buf);
	if (!target)
		return;
	{
		size_t tlen = strlen(target) + 1;
		if (tlen > HYMO_PATH_BUF) {
			kfree(target);
			return; /* target too long for userspace stack buffer */
		}
		new_path = hymo_userspace_stack_buffer(target, tlen);
		kfree(target);
		if (new_path)
			*path_reg = (u64)(uintptr_t)new_path;
	}
}

#endif /* HYMOFS_USE_SYSCALL_TRACEPOINT && HYMOFS_TP_AVAILABLE */

/* Set when sys_enter tracepoint is used for path redirect (avoids getname_flags kprobe) */
static int hymo_tracepoint_path_registered;

/* getname_flags pre-handler: only modify user path and regs; return 0 to run original. */
static HYMO_NOCFI int hymo_kp_getname_flags_pre(struct kprobe *p, struct pt_regs *regs)
{
	const char __user *filename_user;
	char *buf;
	char *target;

	(void)p;

	if (this_cpu_read(hymo_kprobe_reent))
		return 0;
	/* Skip when current is in ioctl path resolution (avoids reent / deadlock with metamount+hymod). */
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	/* Skip when resolving source path for xattr spoofing (need unredirected path). */
	if (atomic_long_read(&hymo_xattr_source_tgid) == (long)task_tgid_vnr(current))
		return 0;
	filename_user = (const char __user *)HYMO_REG0(regs);
	if (!filename_user)
		return 0;

	buf = this_cpu_ptr(hymo_getname_path_buf);
	if (hymo_strncpy_from_user_nofault_ptr) {
		long ret = hymo_strncpy_from_user_nofault(buf, filename_user, HYMO_PATH_BUF - 1);
		if (ret < 0)
			return 0;
		buf[ret < (long)(HYMO_PATH_BUF - 1) ? ret : (HYMO_PATH_BUF - 1)] = '\0';
	} else {
		if (copy_from_user(buf, filename_user, HYMO_PATH_BUF - 1))
			return 0;
		buf[HYMO_PATH_BUF - 1] = '\0';
	}

	if (likely(hash_empty(hymo_paths) &&
		   hash_empty(hymo_hide_paths) &&
		   hash_empty(hymo_merge_dirs)))
		return 0;

	/* Hide: skip original and return error (no putname needed) */
	if (unlikely(hymofs_should_hide(buf))) {
		this_cpu_write(hymo_kprobe_reent, 1);
		HYMO_REG0(regs) = (unsigned long)ERR_PTR(-ENOENT);
		instruction_pointer_set(regs, HYMO_LR(regs));
		HYMO_POP_STACK(regs);
#if defined(__x86_64__)
		regs->ax = (unsigned long)ERR_PTR(-ENOENT);
#endif
		this_cpu_write(hymo_kprobe_reent, 0);
		return 1;
	}

	/* Redirect: use getname_kernel to build a struct filename from the target
	 * path, then skip the original getname_flags entirely.  This avoids
	 * writing back to user memory (which may be read-only, too small, or
	 * cause PAN/MTE faults in atomic context). */
	if (buf[0] != '/')
		return 0;
	target = hymofs_resolve_target(buf);
	if (!target)
		return 0;
	{
		struct filename *fname;

		this_cpu_write(hymo_kprobe_reent, 1);
		fname = hymo_getname_kernel(target);
		this_cpu_write(hymo_kprobe_reent, 0);
		kfree(target);
		if (IS_ERR(fname))
			return 0;
		HYMO_REG0(regs) = (unsigned long)fname;
		instruction_pointer_set(regs, HYMO_LR(regs));
		HYMO_POP_STACK(regs);
		return 1;
	}
}

/* vfs_getattr kprobe pre: nop (stat spoofing is done in kretprobe entry/ret). */
static int hymo_kp_vfs_getattr_pre(struct kprobe *p, struct pt_regs *regs)
{
	(void)p; (void)regs;
	return 0;
}

/*
 * Reverse-lookup helper: check if a resolved path is a redirect target.
 * Returns the matching hymo_entry (under rcu_read_lock) or NULL.
 * Caller must hold rcu_read_lock.
 */
static struct hymo_entry *hymofs_reverse_lookup_target(const char *path_str)
{
	struct hymo_entry *entry;
	u32 hash;

	if (!path_str || !*path_str)
		return NULL;
	hash = full_name_hash(NULL, path_str, strlen(path_str));
	hlist_for_each_entry_rcu(entry,
		&hymo_targets[hash_min(hash, HYMO_HASH_BITS)], target_node) {
		if (strcmp(entry->target, path_str) == 0)
			return entry;
	}
	return NULL;
}

/*
 * vfs_getattr kretprobe entry: resolve path, check hymo_targets.
 * Uses ri->data (migration-safe) instead of per-CPU storage.
 */
static HYMO_NOCFI int hymo_krp_vfs_getattr_entry(struct kretprobe_instance *ri,
						  struct pt_regs *regs)
{
	struct hymo_getattr_ri_data *d = (void *)ri->data;
	const struct path *p;
	char buf[256];
	char *dp;

	d->is_target = false;
	d->stat = NULL;
	d->mapping = NULL;

	if (!READ_ONCE(hymofs_enabled))
		return 0;
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	if (this_cpu_read(hymo_in_populate_inject))
		return 0;
	if (atomic_read(&hymo_rule_count) == 0)
		return 0;

	p = (const struct path *)HYMO_GETATTR_PATH_REG(regs);
	d->stat = (struct kstat *)HYMO_GETATTR_STAT_REG(regs);

	if (!p || !p->dentry || !d->stat)
		return 0;

	if (d_inode(p->dentry) && d_inode(p->dentry)->i_mapping)
		d->mapping = d_inode(p->dentry)->i_mapping;

	/* Fast path: inode already marked from a previous redirect match */
	if (d->mapping && test_bit(AS_FLAGS_HYMO_SPOOF_KSTAT, &d->mapping->flags)) {
		d->is_target = true;
		return 0;
	}

	dp = ERR_PTR(-ENOENT);
	dp = hymo_d_absolute_path(p, buf, sizeof(buf));
	if (IS_ERR(dp))
		dp = hymo_dentry_path_raw(p->dentry, buf, sizeof(buf));
	if (IS_ERR_OR_NULL(dp) || dp[0] != '/')
		return 0;

	rcu_read_lock();
	if (hymofs_reverse_lookup_target(dp))
		d->is_target = true;
	rcu_read_unlock();

	return 0;
}

/*
 * vfs_getattr kretprobe ret: spoof kstat for redirect targets.
 * Makes the file appear to belong to /system with root ownership.
 */
static int hymo_krp_vfs_getattr_ret(struct kretprobe_instance *ri,
				    struct pt_regs *regs)
{
	struct hymo_getattr_ri_data *d = (void *)ri->data;
	struct kstat *stat;
	int ret_val;

	if (!d->is_target || !d->stat)
		return 0;

#if defined(__aarch64__)
	ret_val = (int)regs->regs[0];
#elif defined(__x86_64__)
	ret_val = (int)regs->ax;
#else
	ret_val = 0;
#endif
	if (ret_val != 0)
		return 0;

	stat = d->stat;
	if (hymo_system_dev)
		stat->dev = hymo_system_dev;
	stat->uid = GLOBAL_ROOT_UID;
	stat->gid = GLOBAL_ROOT_GID;
	stat->ino = (u64)jhash(stat, sizeof(stat->ino), 0x48594D4F) | 0x100000ULL;
	if (S_ISREG(stat->mode))
		stat->nlink = 1;

	/* Mark inode so xattr and future stat calls use fast O(1) check */
	if (d->mapping)
		set_bit(AS_FLAGS_HYMO_SPOOF_KSTAT, &d->mapping->flags);

	return 0;
}

/*
 * Get SELinux context from a path (used for source path when spoofing).
 * Bypass must be set (hymo_xattr_source_tgid) so path resolution is not redirected.
 * Returns length of context string (excl. NUL) or negative on error.
 */
static HYMO_NOCFI ssize_t hymo_get_selinux_ctx_from_path(struct path *path, char *buf, size_t buflen)
{
	if (!hymo_vfs_getxattr_addr || buflen < 2)
		return -ENOENT;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	return ((ssize_t (*)(void *, struct dentry *, const char *, void *, size_t))hymo_vfs_getxattr_addr)(
		mnt_idmap(path->mnt), path->dentry, "security.selinux", buf, buflen);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	return ((ssize_t (*)(void *, struct dentry *, const char *, void *, size_t))hymo_vfs_getxattr_addr)(
		mnt_user_ns(path->mnt), path->dentry, "security.selinux", buf, buflen);
#else
	return ((ssize_t (*)(struct dentry *, const char *, void *, size_t))hymo_vfs_getxattr_addr)(
		path->dentry, "security.selinux", buf, buflen);
#endif
}

/*
 * vfs_getxattr kretprobe entry: check if querying security.selinux on a
 * redirect target.  Resolves source path and reads its actual SELinux context
 * from the mounted directory (no hardcoding).
 */
static HYMO_NOCFI int hymo_krp_vfs_getxattr_entry(struct kretprobe_instance *ri,
						   struct pt_regs *regs)
{
	struct hymo_getxattr_ri_data *d = (void *)ri->data;
	struct dentry *dentry;
	const char *xattr_name;
	struct inode *inode;
	char tmp[256];
	char *dp;
	struct hymo_entry *entry;
	struct path src_path;
	ssize_t ret;

	d->spoof_selinux = false;
	d->value_buf = NULL;
	d->value_size = 0;
	d->src_ctx[0] = '\0';
	d->src_ctx_len = 0;

	/* Skip when we're in the inner call (resolving source path's context) */
	if (atomic_long_read(&hymo_xattr_source_tgid) == (long)task_tgid_vnr(current))
		return 0;

	if (!READ_ONCE(hymofs_enabled))
		return 0;
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	if (atomic_read(&hymo_rule_count) == 0)
		return 0;

	xattr_name = (const char *)HYMO_GETXATTR_NAME_REG(regs);
	if (!xattr_name)
		return 0;
	if (strcmp(xattr_name, "security.selinux") != 0)
		return 0;

	dentry = (struct dentry *)HYMO_GETXATTR_DENTRY_REG(regs);
	if (!dentry)
		return 0;

	inode = d_inode(dentry);
	if (!inode || !inode->i_mapping)
		return 0;
	if (!test_bit(AS_FLAGS_HYMO_SPOOF_KSTAT, &inode->i_mapping->flags))
		return 0;

	/* Resolve target path for reverse lookup. dentry_path_raw gives path
	 * relative to fs root; try full path and /data + rel for common Android layout. */
	dp = hymo_dentry_path_raw(dentry, tmp, sizeof(tmp));
	if (IS_ERR_OR_NULL(dp) || dp[0] != '/')
		return 0;

	rcu_read_lock();
	entry = hymofs_reverse_lookup_target(dp);
	if (!entry && dp[0] == '/' && dp[1] != '\0') {
		char full[256];
		if (snprintf(full, sizeof(full), "/data%s", dp) < (int)sizeof(full))
			entry = hymofs_reverse_lookup_target(full);
	}
	rcu_read_unlock();
	if (!entry || !entry->src)
		return 0;

	/* Resolve source path (bypass redirect) and get its actual SELinux context.
	 * When source file doesn't exist (e.g. overlay dir is empty), try parent
	 * directories. Use d_absolute_path on resolved parent to get symlink-resolved
	 * path (e.g. /system/product -> /product), then try resolved+remainder. */
	atomic_long_set(&hymo_xattr_source_tgid, (long)task_tgid_vnr(current));
	if (hymo_kern_path_ptr) {
		char parent[256];
		char resolved[256];
		char alt[512];
		const char *try_path = entry->src;
		size_t len = strlen(entry->src);
		size_t parent_len;

		while (try_path && len > 1) {
			/* Try logical path (LOOKUP_FOLLOW resolves symlinks) */
			if (hymo_kern_path(try_path, LOOKUP_FOLLOW, &src_path) == 0) {
				ret = hymo_get_selinux_ctx_from_path(&src_path, d->src_ctx, HYMO_SELINUX_CTX_MAX);
				path_put(&src_path);
				if (ret > 0 && (size_t)ret < HYMO_SELINUX_CTX_MAX) {
					d->src_ctx_len = (size_t)ret;
					d->src_ctx[d->src_ctx_len] = '\0';
					d->spoof_selinux = true;
					break;
				}
			}
			/* Logical path failed: try parent, get resolved path via d_absolute_path,
			 * then try resolved+remainder (handles any symlink, not just /system/product). */
			if (len >= sizeof(parent))
				break;
			memcpy(parent, try_path, len + 1);
			{
				char *slash = strrchr(parent, '/');
				if (!slash || slash == parent)
					break;
				*slash = '\0';
				parent_len = slash - parent;
			}
			if (hymo_kern_path(parent, LOOKUP_FOLLOW, &src_path) == 0) {
				char *res = NULL;
				bool got_ctx = false;
				res = hymo_d_absolute_path(&src_path, resolved, sizeof(resolved));
				if (IS_ERR_OR_NULL(res))
					res = hymo_dentry_path_raw(src_path.dentry, resolved, sizeof(resolved));
				if (res && !IS_ERR(res) && res[0] == '/' &&
				    parent_len < len && try_path[parent_len] == '/') {
					const char *remainder = try_path + parent_len;
					if (snprintf(alt, sizeof(alt), "%s%s", res, remainder) < (int)sizeof(alt) &&
					    strcmp(alt, try_path) != 0) {
						struct path alt_path;
						if (hymo_kern_path(alt, LOOKUP_FOLLOW, &alt_path) == 0) {
							ret = hymo_get_selinux_ctx_from_path(&alt_path, d->src_ctx, HYMO_SELINUX_CTX_MAX);
							path_put(&alt_path);
							if (ret > 0 && (size_t)ret < HYMO_SELINUX_CTX_MAX)
								got_ctx = true;
						}
					}
				}
				if (!got_ctx) {
					ret = hymo_get_selinux_ctx_from_path(&src_path, d->src_ctx, HYMO_SELINUX_CTX_MAX);
					if (ret > 0 && (size_t)ret < HYMO_SELINUX_CTX_MAX)
						got_ctx = true;
				}
				path_put(&src_path);
				if (got_ctx) {
					d->src_ctx_len = (size_t)ret;
					d->src_ctx[d->src_ctx_len] = '\0';
					d->spoof_selinux = true;
					break;
				}
			}
			try_path = parent;
			len = parent_len;
		}
	}
	atomic_long_set(&hymo_xattr_source_tgid, 0);

	d->value_buf = (void *)HYMO_GETXATTR_VALUE_REG(regs);
	d->value_size = (size_t)HYMO_GETXATTR_SIZE_REG(regs);

	return 0;
}

/*
 * vfs_getxattr kretprobe ret: overwrite value buffer with source path's
 * actual SELinux context (from entry handler) and fix return value.
 */
static int hymo_krp_vfs_getxattr_ret(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	struct hymo_getxattr_ri_data *d = (void *)ri->data;
	long ret_val;
	size_t ctx_len;

	if (!d->spoof_selinux || !d->value_buf || !d->src_ctx_len)
		return 0;

#if defined(__aarch64__)
	ret_val = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret_val = (long)regs->ax;
#else
	ret_val = 0;
#endif
	if (ret_val <= 0)
		return 0;

	ctx_len = d->src_ctx_len + 1; /* include NUL */
	if (d->value_size < ctx_len)
		return 0;
	memcpy(d->value_buf, d->src_ctx, ctx_len);

#if defined(__aarch64__)
	regs->regs[0] = (unsigned long)d->src_ctx_len;
#elif defined(__x86_64__)
	regs->ax = (unsigned long)d->src_ctx_len;
#endif

	return 0;
}

/* d_path: kprobe pre now a nop; entry handler below does the real work. */
static int hymo_kp_d_path_pre(struct kprobe *p, struct pt_regs *regs)
{
	(void)p; (void)regs;
	return 0;
}

/*
 * d_path kretprobe entry: save buf/buflen from regs, resolve the struct path
 * to see if it's a redirect target.  d_path signature:
 *   char *d_path(const struct path *path, char *buf, int buflen)
 */
static HYMO_NOCFI int hymo_krp_d_path_entry(struct kretprobe_instance *ri,
					     struct pt_regs *regs)
{
	struct hymo_d_path_ri_data *d = (void *)ri->data;
	const struct path *p;
	char tmp[256];
	char *dp;
	struct hymo_entry *entry;

	d->is_target = false;
	d->buf = (char *)HYMO_REG1(regs);
	d->buflen = (int)HYMO_REG2(regs);
	d->src_path[0] = '\0';

	if (!READ_ONCE(hymofs_enabled))
		return 0;
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	if (atomic_read(&hymo_rule_count) == 0)
		return 0;

	p = (const struct path *)HYMO_REG0(regs);
	if (!p || !p->dentry)
		return 0;

	dp = ERR_PTR(-ENOENT);
	dp = hymo_d_absolute_path(p, tmp, sizeof(tmp));
	if (IS_ERR(dp))
		dp = hymo_dentry_path_raw(p->dentry, tmp, sizeof(tmp));
	if (IS_ERR_OR_NULL(dp) || dp[0] != '/')
		return 0;

	rcu_read_lock();
	entry = hymofs_reverse_lookup_target(dp);
	if (entry && strlen(entry->src) < HYMO_D_PATH_SRC_MAX) {
		d->is_target = true;
		strscpy(d->src_path, entry->src, HYMO_D_PATH_SRC_MAX);
	}
	rcu_read_unlock();

	return 0;
}

/*
 * d_path kretprobe ret: if the resolved path was a redirect target,
 * overwrite the result so /proc/pid/fd/N shows /system/... instead of
 * /data/adb/modules/xxx/...
 *
 * d_path() returns a pointer INSIDE the caller's buffer (buf + offset).
 * We write the source path into the buffer from the end and update the
 * return value register to point to the new start.
 */
static int hymo_krp_d_path_ret(struct kretprobe_instance *ri,
			       struct pt_regs *regs)
{
	struct hymo_d_path_ri_data *d = (void *)ri->data;
	char *ret_ptr;
	size_t src_len;
	char *new_start;

	if (!d->is_target || !d->src_path[0] || !d->buf || d->buflen <= 0)
		return 0;

#if defined(__aarch64__)
	ret_ptr = (char *)regs->regs[0];
#elif defined(__x86_64__)
	ret_ptr = (char *)regs->ax;
#else
	ret_ptr = NULL;
#endif
	if (IS_ERR_OR_NULL(ret_ptr))
		return 0;

	src_len = strlen(d->src_path);
	if ((int)src_len + 1 > d->buflen)
		return 0;

	new_start = d->buf + d->buflen - src_len - 1;
	memcpy(new_start, d->src_path, src_len + 1);

#if defined(__aarch64__)
	regs->regs[0] = (unsigned long)new_start;
#elif defined(__x86_64__)
	regs->ax = (unsigned long)new_start;
#endif

	return 0;
}

/*
 * iterate_dir: pre swaps ctx to our wrapper so kernel runs filldir filter.
 * HYMO_NOCFI: indirect calls to hymo_d_absolute_path / hymo_dentry_path_raw.
 */
static HYMO_NOCFI int hymo_kp_iterate_dir_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file;
	struct hymofs_filldir_wrapper *w;
	struct dir_context *orig_ctx;
	struct inode *dir_inode;
	const char *dname;

	(void)p;
	this_cpu_write(hymo_iterate_did_swap, 0);

	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	if (this_cpu_read(hymo_in_populate_inject))
		return 0;
	if (!READ_ONCE(hymofs_enabled))
		return 0;
	if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;
	if (hymo_daemon_pid > 0 && task_tgid_vnr(current) == hymo_daemon_pid)
		return 0;

	file = (struct file *)HYMO_REG0(regs);
	orig_ctx = (struct dir_context *)HYMO_REG1(regs);
	if (!orig_ctx)
		return 0;

	w = this_cpu_ptr(&hymo_iterate_wrapper);
	w->orig_ctx = orig_ctx;
	w->wrap_ctx.actor = hymofs_filldir_filter;
	w->wrap_ctx.pos = orig_ctx->pos;
	w->parent_dentry = file && file->f_path.dentry ? file->f_path.dentry : NULL;
	w->dir_has_hidden = false;
	w->dir_path_len = 0;
	w->dir_path = NULL;
	w->dir_has_inject = false;
	w->inject_done = false;
	w->merge_target_count = 0;

	if (w->parent_dentry) {
		dir_inode = d_inode(w->parent_dentry);
		if (dir_inode && dir_inode->i_mapping) {
			w->dir_has_hidden = test_bit(AS_FLAGS_HYMO_DIR_HAS_HIDDEN,
						     &dir_inode->i_mapping->flags);
			/* Fast path: if dir has no inject flag, skip rcu_read_lock + hash traversal */
			w->dir_has_inject = test_bit(AS_FLAGS_HYMO_DIR_HAS_INJECT,
						    &dir_inode->i_mapping->flags);
		}
		dname = w->parent_dentry->d_name.name;
		if (dname[0] == 'd' && dname[1] == 'e' && dname[2] == 'v' && dname[3] == '\0')
			w->dir_path_len = 4;

		/*
		 * Only when dir_has_inject (from flag) is true: build full path and
		 * traverse hash to get merge_target_dentries. Most dirs skip this.
		 */
		if (atomic_read(&hymo_rule_count) > 0 && w->dir_has_inject) {
			char *buf = this_cpu_ptr(hymo_iterate_dir_path);
			char *dp;

			dp = hymo_d_absolute_path(&file->f_path, buf,
						  HYMO_ITERATE_PATH_BUF);
			if (IS_ERR(dp))
				dp = hymo_dentry_path_raw(w->parent_dentry, buf,
						  HYMO_ITERATE_PATH_BUF);

			if (!IS_ERR_OR_NULL(dp) && *dp == '/') {
				struct hymo_inject_entry *ie;
				struct hymo_merge_entry *me;
				u32 h;
				int mbkt;

				w->dir_path = dp;
				h = full_name_hash(NULL, dp, strlen(dp));

				rcu_read_lock();
				hlist_for_each_entry_rcu(ie,
					&hymo_inject_dirs[hash_min(h, HYMO_HASH_BITS)],
					node) {
					if (strcmp(ie->dir, dp) == 0) {
						w->dir_has_inject = true;
						break;
					}
				}
				/* Scan all merge entries (few) to match both
				 * src and resolved_src; cache target dentries. */
				hash_for_each_rcu(hymo_merge_dirs, mbkt, me, node) {
					if (strcmp(me->src, dp) == 0 ||
					    (me->resolved_src &&
					     strcmp(me->resolved_src, dp) == 0)) {
						w->dir_has_inject = true;
						if (me->target_dentry &&
						    w->merge_target_count < HYMO_MAX_MERGE_TARGETS)
							w->merge_target_dentries[w->merge_target_count++] =
								me->target_dentry;
					}
				}
				rcu_read_unlock();
			}
		}
	}

	/* Only swap ctx when we need filtering or inject (avoids per-CPU reentrancy). */
	if (!w->dir_has_hidden && !w->dir_has_inject &&
	    (!hymo_stealth_enabled || w->dir_path_len != 4)) {
		this_cpu_write(hymo_iterate_did_swap, 0);
		return 0;
	}

	this_cpu_write(hymo_iterate_did_swap, 1);
	HYMO_REG1(regs) = (unsigned long)&w->wrap_ctx;
	return 0;
}

struct hymo_iterate_ri_data {
	int did_swap;
	struct hymofs_filldir_wrapper *wrapper;
};

static int hymo_krp_iterate_dir_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hymo_iterate_ri_data *d = (void *)ri->data;
	(void)regs;
	d->did_swap = this_cpu_read(hymo_iterate_did_swap);
	d->wrapper = d->did_swap ? this_cpu_ptr(&hymo_iterate_wrapper) : NULL;
	return 0;
}

static int hymo_krp_iterate_dir_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hymo_iterate_ri_data *d = (void *)ri->data;
	(void)regs;
	if (d->did_swap && d->wrapper && d->wrapper->orig_ctx)
		d->wrapper->orig_ctx->pos = d->wrapper->wrap_ctx.pos;
	return 0;
}

#define HYMOFS_VFS_HOOK_COUNT 4
#define HYMOFS_VFS_IDX_GETNAME   0
#define HYMOFS_VFS_IDX_GETATTR  1
#define HYMOFS_VFS_IDX_DPATH    2
#define HYMOFS_VFS_IDX_ITERDIR  3

static const struct {
	const char *name;
	int (*pre)(struct kprobe *, struct pt_regs *);
} hymofs_vfs_hooks[] = {
	{ "getname_flags", hymo_kp_getname_flags_pre },
	{ "vfs_getattr",   hymo_kp_vfs_getattr_pre },
	{ "d_path",        hymo_kp_d_path_pre },
	{ "iterate_dir",   hymo_kp_iterate_dir_pre },
};
static struct kprobe hymofs_kprobes[HYMOFS_VFS_HOOK_COUNT];

static struct kretprobe hymo_krp_vfs_getattr;
static struct kretprobe hymo_krp_d_path;
static struct kretprobe hymo_krp_iterate_dir;
static struct kretprobe hymo_krp_vfs_getxattr;
static int hymo_getxattr_kprobe_registered;

/* ======================================================================
 * Part 24: Module Init / Exit
 * ====================================================================== */

static int __init hymofs_lkm_init(void)
{
	pr_info("hymofs: initializing LKM v%s\n", HYMOFS_VERSION);

	/*
	 * Resolve ALL VFS symbols via kprobe - GKI kernels protect these
	 * behind namespaces or don't export them at all.
	 * Critical symbols fail the module load; optional ones just warn.
	 */
	hymo_kern_path_ptr = (void *)hymofs_lookup_name("kern_path");
	if (!hymo_kern_path_ptr) {
		pr_err("hymofs: FATAL - kern_path not found\n");
		return -ENOENT;
	}
	hymo_strndup_user_ptr = (void *)hymofs_lookup_name("strndup_user");
	if (!hymo_strndup_user_ptr) {
		pr_err("hymofs: FATAL - strndup_user not found\n");
		return -ENOENT;
	}
	hymo_ihold_ptr = (void *)hymofs_lookup_name("ihold");
	if (!hymo_ihold_ptr) {
		pr_err("hymofs: FATAL - ihold not found\n");
		return -ENOENT;
	}
	hymo_getname_kernel_ptr = (void *)hymofs_lookup_name("getname_kernel");
	if (!hymo_getname_kernel_ptr)
		pr_warn("hymofs: getname_kernel not found, path redirect may fail\n");

	/* Optional: allowlist support */
	hymo_filp_open_ptr = (void *)hymofs_lookup_name("filp_open");
	hymo_filp_close_ptr = (void *)hymofs_lookup_name("filp_close");
	hymo_kernel_read_ptr = (void *)hymofs_lookup_name("kernel_read");
	hymo_vfs_getattr_ptr = (void *)hymofs_lookup_name("vfs_getattr");
	hymo_dentry_open_ptr = (void *)hymofs_lookup_name("dentry_open");
	hymo_d_absolute_path_ptr = (void *)hymofs_lookup_name("d_absolute_path");
	hymo_dentry_path_raw_ptr = (void *)hymofs_lookup_name("dentry_path_raw");
	hymo_d_hash_and_lookup_ptr = (void *)hymofs_lookup_name("d_hash_and_lookup");
	if (!hymo_d_absolute_path_ptr && !hymo_dentry_path_raw_ptr)
		pr_warn("hymofs: neither d_absolute_path nor dentry_path_raw found, inject/merge listing disabled\n");
	hymo_strncpy_from_user_nofault_ptr = (void *)hymofs_lookup_name("strncpy_from_user_nofault");
	if (!hymo_strncpy_from_user_nofault_ptr)
		pr_warn("hymofs: strncpy_from_user_nofault not found, falling back to copy_from_user\n");
	if (!hymo_filp_open_ptr || !hymo_kernel_read_ptr)
		pr_warn("hymofs: filp_open/kernel_read not found, allowlist disabled\n");
	if (!hymo_vfs_getattr_ptr || !hymo_dentry_open_ptr)
		pr_warn("hymofs: vfs_getattr/dentry_open not found, merge whiteout/iterate disabled\n");

	/* Initialize hash tables */
	hash_init(hymo_paths);
	hash_init(hymo_targets);
	hash_init(hymo_hide_paths);
	hash_init(hymo_inject_dirs);
	hash_init(hymo_xattr_sbs);
	hash_init(hymo_merge_dirs);

	/* Resolve kallsyms first so all lookups can use it (no kernel exports needed). */
	hymofs_resolve_kallsyms_lookup();

	/* Resolve /system device number for stat spoofing */
	if (hymo_kern_path_ptr) {
		struct path sys_path;
		if (hymo_kern_path("/system", LOOKUP_FOLLOW, &sys_path) == 0) {
			hymo_system_dev = sys_path.dentry->d_sb->s_dev;
			pr_info("hymofs: /system dev=%u:%u\n",
				MAJOR(hymo_system_dev), MINOR(hymo_system_dev));
			path_put(&sys_path);
		} else {
			pr_warn("hymofs: could not resolve /system for stat spoofing\n");
		}
	}

	/* GET_FD: kprobe+kretprobe on ni_syscall; no sys_call_table patch. */
	if (hymo_syscall_nr_param <= 0) {
		pr_err("hymofs: hymo_syscall_nr must be positive (got %d), pass at insmod e.g. hymo_syscall_nr=448\n",
		       hymo_syscall_nr_param);
		return -EINVAL;
	}
	{
		const char *ni_names[] = { "__arm64_sys_ni_syscall", "sys_ni_syscall", "__x64_sys_ni_syscall", NULL };
		unsigned long ni_addr = 0;
		int i, ret;

		for (i = 0; ni_names[i]; i++) {
			ni_addr = hymofs_lookup_name(ni_names[i]);
			if (ni_addr)
				break;
		}
		if (!ni_addr) {
			pr_err("hymofs: ni_syscall symbol not found (tried __arm64_sys_ni_syscall, sys_ni_syscall, __x64_sys_ni_syscall)\n");
			return -ENOENT;
		}
		hymo_kp_ni.addr = (kprobe_opcode_t *)ni_addr;
		hymo_krp_ni.kp.addr = (kprobe_opcode_t *)ni_addr;
		ret = register_kprobe(&hymo_kp_ni);
		if (ret) {
			pr_err("hymofs: register_kprobe(ni_syscall@%px) failed: %d (errno %d)\n",
			       (void *)ni_addr, ret, -ret);
			return ret;
		}
		ret = register_kretprobe(&hymo_krp_ni);
		if (ret) {
			unregister_kprobe(&hymo_kp_ni);
			pr_err("hymofs: register_kretprobe(ni_syscall) failed: %d (errno %d)\n", ret, -ret);
			return ret;
		}
		pr_info("hymofs: GET_FD via kprobe on ni_syscall (syscall nr=%d)\n", hymo_syscall_nr_param);
	}

	/* Optional: GET_FD via SYS_reboot (142) like susfs/KernelSU kprobes; works on 5.10+ */
	{
		int ret;
		static const char *reboot_symbols[] = {
#if defined(__aarch64__)
			"__arm64_sys_reboot", "sys_reboot", NULL
#elif defined(__x86_64__)
			"__x64_sys_reboot", "sys_reboot", NULL
#else
			NULL
#endif
		};
		void *reboot_addr = NULL;
		int i;

		for (i = 0; reboot_symbols[i]; i++) {
			reboot_addr = (void *)hymofs_lookup_name(reboot_symbols[i]);
			if (reboot_addr)
				break;
		}
		if (reboot_addr) {
			hymo_kp_reboot.addr = (kprobe_opcode_t *)reboot_addr;
			hymo_krp_reboot.kp.addr = (kprobe_opcode_t *)reboot_addr;
			hymo_krp_reboot.maxactive = 16;
			ret = register_kprobe(&hymo_kp_reboot);
			if (ret == 0) {
				ret = register_kretprobe(&hymo_krp_reboot);
				if (ret) {
					unregister_kprobe(&hymo_kp_reboot);
				} else {
					pr_info("hymofs: GET_FD also via kprobe on %s (SYS_reboot)\n", reboot_symbols[i]);
					hymo_reboot_kprobe_registered = 1;
				}
			}
		}
	}

	/* GET_FD via prctl (SECCOMP-safe); preferred over reboot when seccomp may block. */
	{
		static const char *prctl_symbols[] = {
#if defined(__aarch64__)
			"__arm64_sys_prctl", "sys_prctl", NULL
#elif defined(__x86_64__)
			"__x64_sys_prctl", "sys_prctl", NULL
#else
			NULL
#endif
		};
		void *prctl_addr = NULL;
		int i, ret;

		for (i = 0; prctl_symbols[i]; i++) {
			prctl_addr = (void *)hymofs_lookup_name(prctl_symbols[i]);
			if (prctl_addr)
				break;
		}
		if (prctl_addr) {
			hymo_kp_prctl.addr = (kprobe_opcode_t *)prctl_addr;
			ret = register_kprobe(&hymo_kp_prctl);
			if (ret == 0) {
				pr_info("hymofs: GET_FD also via kprobe on %s (prctl, SECCOMP-safe)\n", prctl_symbols[i]);
				hymo_prctl_kprobe_registered = 1;
			}
		}
	}

	/* uname spoofing: kretprobe on newuname syscall */
	{
		static const char *uname_symbols[] = {
#if defined(__aarch64__)
			"__arm64_sys_newuname", "sys_newuname", NULL
#elif defined(__x86_64__)
			"__x64_sys_newuname", "sys_newuname", NULL
#else
			NULL
#endif
		};
		void *uname_addr = NULL;
		int i, ret;

		for (i = 0; uname_symbols[i]; i++) {
			uname_addr = (void *)hymofs_lookup_name(uname_symbols[i]);
			if (uname_addr)
				break;
		}
		if (uname_addr) {
			hymo_krp_uname.kp.addr = (kprobe_opcode_t *)uname_addr;
			ret = register_kretprobe(&hymo_krp_uname);
			if (ret == 0) {
				pr_info("hymofs: uname spoofing via kretprobe on %s\n", uname_symbols[i]);
				hymo_uname_kprobe_registered = 1;
			}
		}
	}

#if HYMOFS_VFS_KPROBES
#if HYMOFS_USE_SYSCALL_TRACEPOINT && HYMOFS_TP_AVAILABLE
	/* Try sys_enter tracepoint for path redirect */
	{
		int tp_ret = register_trace_sys_enter(hymo_sys_enter_handler, NULL);
		if (tp_ret == 0) {
			hymo_tracepoint_path_registered = 1;
			pr_info("hymofs: sys_enter tracepoint registered (path redirect)\n");
		} else {
			pr_warn("hymofs: register_trace_sys_enter failed: %d, falling back to getname_flags kprobe\n", tp_ret);
		}
	}
#endif
	/* Install VFS kprobes (skip getname_flags if tracepoint is used) */
	{
		size_t i;
		int ret;
		size_t start_idx = (hymo_tracepoint_path_registered ? 1 : 0);

		for (i = start_idx; i < HYMOFS_VFS_HOOK_COUNT; i++) {
			unsigned long addr = hymofs_lookup_name(hymofs_vfs_hooks[i].name);
			if (!addr) {
				pr_err("hymofs: symbol not found: %s\n", hymofs_vfs_hooks[i].name);
				for (; i > start_idx; i--)
					unregister_kprobe(&hymofs_kprobes[i - 1]);
#if HYMOFS_USE_SYSCALL_TRACEPOINT && HYMOFS_TP_AVAILABLE
				if (hymo_tracepoint_path_registered) {
					unregister_trace_sys_enter(hymo_sys_enter_handler, NULL);
					tracepoint_synchronize_unregister();
				}
#endif
				return -ENOENT;
			}
			hymofs_kprobes[i].addr = (kprobe_opcode_t *)addr;
			hymofs_kprobes[i].pre_handler = hymofs_vfs_hooks[i].pre;
			ret = register_kprobe(&hymofs_kprobes[i]);
			if (ret) {
				pr_err("hymofs: register_kprobe(%s) failed: %d\n",
				       hymofs_vfs_hooks[i].name, ret);
				for (; i > start_idx; i--)
					unregister_kprobe(&hymofs_kprobes[i - 1]);
#if HYMOFS_USE_SYSCALL_TRACEPOINT && HYMOFS_TP_AVAILABLE
				if (hymo_tracepoint_path_registered) {
					unregister_trace_sys_enter(hymo_sys_enter_handler, NULL);
					tracepoint_synchronize_unregister();
				}
#endif
				return ret;
			}
			pr_info("hymofs: kprobe %s @0x%lx\n", hymofs_vfs_hooks[i].name, addr);
		}

		/* kretprobes for vfs_getattr and d_path (modify after return) */
		hymo_krp_vfs_getattr.kp.addr = hymofs_kprobes[HYMOFS_VFS_IDX_GETATTR].addr;
		hymo_krp_vfs_getattr.entry_handler = hymo_krp_vfs_getattr_entry;
		hymo_krp_vfs_getattr.handler = hymo_krp_vfs_getattr_ret;
		hymo_krp_vfs_getattr.data_size = sizeof(struct hymo_getattr_ri_data);
		hymo_krp_vfs_getattr.maxactive = 64;
		ret = register_kretprobe(&hymo_krp_vfs_getattr);
		if (ret) {
			pr_err("hymofs: register_kretprobe(vfs_getattr) failed: %d\n", ret);
			for (i = HYMOFS_VFS_HOOK_COUNT; i > start_idx; i--)
				unregister_kprobe(&hymofs_kprobes[i - 1]);
#if HYMOFS_USE_SYSCALL_TRACEPOINT && HYMOFS_TP_AVAILABLE
			if (hymo_tracepoint_path_registered) {
				unregister_trace_sys_enter(hymo_sys_enter_handler, NULL);
				tracepoint_synchronize_unregister();
			}
#endif
			return ret;
		}
		hymo_krp_d_path.kp.addr = hymofs_kprobes[HYMOFS_VFS_IDX_DPATH].addr;
		hymo_krp_d_path.entry_handler = hymo_krp_d_path_entry;
		hymo_krp_d_path.handler = hymo_krp_d_path_ret;
		hymo_krp_d_path.data_size = sizeof(struct hymo_d_path_ri_data);
		hymo_krp_d_path.maxactive = 64;
		ret = register_kretprobe(&hymo_krp_d_path);
		if (ret) {
			pr_err("hymofs: register_kretprobe(d_path) failed: %d\n", ret);
			unregister_kretprobe(&hymo_krp_vfs_getattr);
			for (i = HYMOFS_VFS_HOOK_COUNT; i > start_idx; i--)
				unregister_kprobe(&hymofs_kprobes[i - 1]);
#if HYMOFS_USE_SYSCALL_TRACEPOINT && HYMOFS_TP_AVAILABLE
			if (hymo_tracepoint_path_registered) {
				unregister_trace_sys_enter(hymo_sys_enter_handler, NULL);
				tracepoint_synchronize_unregister();
			}
#endif
			return ret;
		}
		hymo_krp_iterate_dir.kp.addr = hymofs_kprobes[HYMOFS_VFS_IDX_ITERDIR].addr;
		hymo_krp_iterate_dir.entry_handler = hymo_krp_iterate_dir_entry;
		hymo_krp_iterate_dir.handler = hymo_krp_iterate_dir_ret;
		hymo_krp_iterate_dir.data_size = sizeof(struct hymo_iterate_ri_data);
		hymo_krp_iterate_dir.maxactive = 64;
		ret = register_kretprobe(&hymo_krp_iterate_dir);
		if (ret) {
			pr_err("hymofs: register_kretprobe(iterate_dir) failed: %d\n", ret);
			unregister_kretprobe(&hymo_krp_d_path);
			unregister_kretprobe(&hymo_krp_vfs_getattr);
			for (i = HYMOFS_VFS_HOOK_COUNT; i > start_idx; i--)
				unregister_kprobe(&hymofs_kprobes[i - 1]);
#if HYMOFS_USE_SYSCALL_TRACEPOINT && HYMOFS_TP_AVAILABLE
			if (hymo_tracepoint_path_registered) {
				unregister_trace_sys_enter(hymo_sys_enter_handler, NULL);
				tracepoint_synchronize_unregister();
			}
#endif
			return ret;
		}
		pr_info("hymofs: kretprobes vfs_getattr, d_path, iterate_dir registered\n");

		/* vfs_getxattr kretprobe for SELinux context spoofing (optional) */
		{
			unsigned long xattr_addr = hymofs_lookup_name("vfs_getxattr");
			if (xattr_addr) {
				hymo_vfs_getxattr_addr = (void *)xattr_addr;
				hymo_krp_vfs_getxattr.kp.addr = (kprobe_opcode_t *)xattr_addr;
				hymo_krp_vfs_getxattr.entry_handler = hymo_krp_vfs_getxattr_entry;
				hymo_krp_vfs_getxattr.handler = hymo_krp_vfs_getxattr_ret;
				hymo_krp_vfs_getxattr.data_size = sizeof(struct hymo_getxattr_ri_data);
				hymo_krp_vfs_getxattr.maxactive = 64;
				ret = register_kretprobe(&hymo_krp_vfs_getxattr);
				if (ret == 0) {
					hymo_getxattr_kprobe_registered = 1;
					pr_info("hymofs: kretprobe vfs_getxattr registered (SELinux spoof)\n");
				} else {
					pr_warn("hymofs: register_kretprobe(vfs_getxattr) failed: %d\n", ret);
				}
			} else {
				pr_warn("hymofs: vfs_getxattr not found, SELinux context spoofing disabled\n");
			}
		}
	}
	pr_info("hymofs: initialized (%d VFS kprobes + 3 kretprobes + GET_FD%s)\n",
		(int)(HYMOFS_VFS_HOOK_COUNT - (hymo_tracepoint_path_registered ? 1 : 0)),
		hymo_tracepoint_path_registered ? " + sys_enter tracepoint" : "");
#else
	pr_info("hymofs: initialized (GET_FD only, VFS kprobes disabled)\n");
#endif
	return 0;
}

static void __exit hymofs_lkm_exit(void)
{
	pr_info("hymofs: shutting down\n");

	if (hymo_uname_kprobe_registered)
		unregister_kretprobe(&hymo_krp_uname);
	if (hymo_prctl_kprobe_registered)
		unregister_kprobe(&hymo_kp_prctl);
	if (hymo_reboot_kprobe_registered) {
		unregister_kretprobe(&hymo_krp_reboot);
		unregister_kprobe(&hymo_kp_reboot);
	}
	unregister_kretprobe(&hymo_krp_ni);
	unregister_kprobe(&hymo_kp_ni);

#if HYMOFS_VFS_KPROBES
#if HYMOFS_USE_SYSCALL_TRACEPOINT && HYMOFS_TP_AVAILABLE
	if (hymo_tracepoint_path_registered) {
		unregister_trace_sys_enter(hymo_sys_enter_handler, NULL);
		tracepoint_synchronize_unregister();
		pr_info("hymofs: sys_enter tracepoint unregistered\n");
	}
#endif
	if (hymo_getxattr_kprobe_registered)
		unregister_kretprobe(&hymo_krp_vfs_getxattr);
	unregister_kretprobe(&hymo_krp_iterate_dir);
	unregister_kretprobe(&hymo_krp_d_path);
	unregister_kretprobe(&hymo_krp_vfs_getattr);
	{
		size_t i, start = 0;
#if HYMOFS_USE_SYSCALL_TRACEPOINT && HYMOFS_TP_AVAILABLE
		if (hymo_tracepoint_path_registered)
			start = 1; /* getname_flags was skipped */
#endif
		for (i = start; i < HYMOFS_VFS_HOOK_COUNT; i++)
			unregister_kprobe(&hymofs_kprobes[i]);
	}
#endif

	/* Clean up all rules and wait for RCU grace period */
	spin_lock(&hymo_cfg_lock);
	spin_lock(&hymo_rules_lock);
	spin_lock(&hymo_hide_lock);
	spin_lock(&hymo_allow_uids_lock);
	spin_lock(&hymo_xattr_sbs_lock);
	spin_lock(&hymo_merge_lock);
	spin_lock(&hymo_inject_lock);
	hymo_cleanup_locked();
	spin_unlock(&hymo_inject_lock);
	spin_unlock(&hymo_merge_lock);
	spin_unlock(&hymo_xattr_sbs_lock);
	spin_unlock(&hymo_allow_uids_lock);
	spin_unlock(&hymo_hide_lock);
	spin_unlock(&hymo_rules_lock);
	spin_unlock(&hymo_cfg_lock);

	rcu_barrier();
	pr_info("hymofs: unloaded\n");
}

module_init(hymofs_lkm_init);
module_exit(hymofs_lkm_exit);
