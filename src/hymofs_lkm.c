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
 */
#ifndef HYMOFS_VFS_KPROBES
#define HYMOFS_VFS_KPROBES 1
#endif

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

/* Per-CPU for vfs_getattr kretprobe: save path and kstat at entry. */
static DEFINE_PER_CPU(const struct path *, hymo_vfs_getattr_path);
static DEFINE_PER_CPU(struct kstat *, hymo_vfs_getattr_stat);
/* Per-CPU for d_path kretprobe: save buf and bufsize at entry. */
static DEFINE_PER_CPU(char *, hymo_d_path_buf);
static DEFINE_PER_CPU(int, hymo_d_path_bufsize);
/* Per-CPU for iterate_dir: swap ctx so kernel runs our filldir filter. */
static DEFINE_PER_CPU(struct hymofs_filldir_wrapper, hymo_iterate_wrapper);
static DEFINE_PER_CPU(int, hymo_iterate_did_swap);
static DEFINE_PER_CPU(char[HYMO_ITERATE_PATH_BUF], hymo_iterate_dir_path);
/* When set, we're inside hymofs_populate_injected_list; skip ctx swap in iterate_dir pre. */
static DEFINE_PER_CPU(int, hymo_in_populate_inject);

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
static unsigned long hymofs_lookup_name(const char *name)
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

static struct hymo_merge_trie_node *hymo_merge_trie_root __rcu;
static DEFINE_SPINLOCK(hymo_merge_trie_lock);

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

/* VFS symbols resolved at init; forward-declared for use in merge/inject before init. */
static int (*hymo_kern_path)(const char *, unsigned int, struct path *);
static int (*hymo_vfs_getattr)(const struct path *, struct kstat *, u32, unsigned int);
static struct file *(*hymo_dentry_open)(const struct path *, int, const struct cred *);

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
	kfree(e->src);
	kfree(e->target);
	kfree(e);
}

/* ======================================================================
 * Part 7: Merge Trie
 * ====================================================================== */

static void hymo_merge_trie_free_node(struct hymo_merge_trie_node *n)
{
	struct hymo_merge_trie_node *c, *next;

	if (!n)
		return;
	for (c = n->first_child; c; c = next) {
		next = c->next_sibling;
		hymo_merge_trie_free_node(c);
	}
	kfree(n->comp);
	kfree(n);
}

static void hymo_merge_trie_free_rcu(struct rcu_head *head)
{
	struct hymo_merge_trie_node *root =
		container_of(head, struct hymo_merge_trie_node, rcu);
	hymo_merge_trie_free_node(root);
}

/* Build trie from hymo_merge_dirs. Must hold hymo_merge_lock. */
static void hymo_merge_trie_build_locked(void)
{
	struct hymo_merge_trie_node *new_root, *old_root, *cur, **slot;
	struct hymo_merge_entry *me;
	const char *path, *start;
	char *comp;
	size_t comp_len;
	int bkt;

	spin_lock(&hymo_merge_trie_lock);
	new_root = kzalloc(sizeof(*new_root), GFP_ATOMIC);
	if (!new_root) {
		spin_unlock(&hymo_merge_trie_lock);
		return;
	}

	hash_for_each(hymo_merge_dirs, bkt, me, node) {
		if (!me->src)
			continue;
		path = me->src;
		while (*path == '/')
			path++;
		cur = new_root;
		while (*path) {
			start = path;
			while (*path && *path != '/')
				path++;
			comp_len = (size_t)(path - start);
			if (comp_len == 0) {
				if (*path) path++;
				continue;
			}
			comp = kmalloc(comp_len + 1, GFP_ATOMIC);
			if (!comp)
				break;
			memcpy(comp, start, comp_len);
			comp[comp_len] = '\0';
			for (slot = &cur->first_child; *slot;
			     slot = &(*slot)->next_sibling) {
				if ((*slot)->comp_len == comp_len &&
				    memcmp((*slot)->comp, comp, comp_len) == 0)
					break;
			}
			if (!*slot) {
				*slot = kzalloc(sizeof(struct hymo_merge_trie_node),
						GFP_ATOMIC);
				if (!*slot) {
					kfree(comp);
					break;
				}
				(*slot)->comp = comp;
				(*slot)->comp_len = comp_len;
			} else {
				kfree(comp);
			}
			cur = *slot;
			if (*path == '/')
				path++;
		}
		cur->entry = me;
	}

	old_root = rcu_dereference_protected(hymo_merge_trie_root,
				lockdep_is_held(&hymo_merge_trie_lock));
	rcu_assign_pointer(hymo_merge_trie_root, new_root);
	if (old_root)
		call_rcu(&old_root->rcu, hymo_merge_trie_free_rcu);
	spin_unlock(&hymo_merge_trie_lock);
}

/* Longest-prefix lookup; caller must hold rcu_read_lock. */
static struct hymo_merge_entry *
hymo_merge_trie_lookup_longest(const char *pathname)
{
	struct hymo_merge_trie_node *root, *cur, *child;
	const char *path, *start;
	size_t comp_len;
	struct hymo_merge_entry *last = NULL;

	root = rcu_dereference(hymo_merge_trie_root);
	if (!root)
		return NULL;
	path = pathname;
	while (*path == '/')
		path++;
	cur = root;
	while (*path) {
		start = path;
		while (*path && *path != '/')
			path++;
		comp_len = (size_t)(path - start);
		if (comp_len == 0) {
			if (*path) path++;
			continue;
		}
		for (child = rcu_dereference(cur->first_child); child;
		     child = rcu_dereference(child->next_sibling)) {
			if (child->comp_len == comp_len &&
			    memcmp(child->comp, start, comp_len) == 0)
				break;
		}
		if (!child)
			return last;
		cur = child;
		if (cur->entry)
			last = cur->entry;
		if (*path == '/')
			path++;
	}
	return last;
}

/* ======================================================================
 * Part 8: Inode Marking
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
	struct hymo_merge_trie_node *old_trie;
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

	spin_lock(&hymo_merge_trie_lock);
	old_trie = rcu_dereference_protected(hymo_merge_trie_root,
				lockdep_is_held(&hymo_merge_trie_lock));
	rcu_assign_pointer(hymo_merge_trie_root, NULL);
	if (old_trie)
		call_rcu(&old_trie->rcu, hymo_merge_trie_free_rcu);
	spin_unlock(&hymo_merge_trie_lock);

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

static HYMO_FILLDIR_RET_TYPE hymo_merge_filldir(struct dir_context *ctx, const char *name,
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
	if (d_type == DT_CHR && mctx->dir_path && hymo_vfs_getattr) {
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

static void hymofs_populate_injected_list(const char *dir_path, struct dentry *parent,
					  struct list_head *head)
{
	struct hymo_entry *entry;
	struct hymo_inject_entry *inject_entry;
	struct hymo_merge_entry *merge_entry;
	struct hymo_name_list *item;
	struct hymo_merge_target_node *target_node, *tmp_node;
	struct list_head merge_targets;
	u32 hash;
	int bkt;
	bool should_inject = false;
	size_t dir_len;

	if (unlikely(!hymofs_enabled || !dir_path))
		return;

	INIT_LIST_HEAD(&merge_targets);
	dir_len = strlen(dir_path);
	hash = full_name_hash(NULL, dir_path, dir_len);

	rcu_read_lock();
	hlist_for_each_entry_rcu(inject_entry,
		&hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (strcmp(inject_entry->dir, dir_path) == 0) {
			should_inject = true;
			break;
		}
	}
	hlist_for_each_entry_rcu(merge_entry,
		&hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (strcmp(merge_entry->src, dir_path) == 0) {
			target_node = kmalloc(sizeof(*target_node), GFP_ATOMIC);
			if (target_node) {
				target_node->target = kstrdup(merge_entry->target, GFP_ATOMIC);
				target_node->target_dentry = NULL;
				list_add_tail(&target_node->list, &merge_targets);
			}
			should_inject = true;
		}
	}

	if (should_inject) {
		hash_for_each_rcu(hymo_paths, bkt, entry, node) {
			if (strncmp(entry->src, dir_path, dir_len) != 0)
				continue;
			{
				char *name = NULL;
				if (dir_len == 1 && dir_path[0] == '/')
					name = (char *)entry->src + 1;
				else if (entry->src[dir_len] == '/')
					name = (char *)entry->src + dir_len + 1;

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
		if (target_node->target && hymo_kern_path && hymo_dentry_open) {
			struct path path;
			if (hymo_kern_path(target_node->target, LOOKUP_FOLLOW, &path) == 0) {
				struct file *f = hymo_dentry_open(&path, O_RDONLY | O_DIRECTORY,
								current_cred());
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
				path_put(&path);
			}
			kfree(target_node->target);
		}
		list_del(&target_node->list);
		kfree(target_node);
	}
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
 */
static struct file *(*hymo_filp_open)(const char *, int, umode_t);
static int (*hymo_filp_close)(struct file *, fl_owner_t);
static ssize_t (*hymo_kernel_read)(struct file *, void *, size_t, loff_t *);
/* hymo_kern_path, hymo_vfs_getattr, hymo_dentry_open declared above (merge/inject) */
static char *(*hymo_strndup_user)(const char __user *, long);
static struct filename *(*hymo_getname_kernel)(const char *);
static void (*hymo_ihold)(struct inode *);

static bool hymo_reload_ksu_allowlist(void)
{
	struct file *fp;
	loff_t off = 0;
	u32 magic = 0, version = 0;
	ssize_t ret;
	struct hymo_app_profile profile;
	int count = 0;

	/* VFS symbols not available on this kernel - skip allowlist */
	if (!hymo_filp_open || !hymo_kernel_read)
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

	if (hymo_filp_close)
		hymo_filp_close(fp, NULL);
	else
		fput(fp);
	mutex_unlock(&hymo_allowlist_lock);
	return true;

bad:
	if (hymo_filp_close)
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
	struct hymo_merge_entry *me;
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

	/* Longest-prefix merge match via trie */
	me = hymo_merge_trie_lookup_longest(pathname);
	if (me) {
		size_t src_len = strlen(me->src);
		const char *suffix = pathname + src_len;

		if (suffix[0] != '\0' &&
		    strcmp(suffix, "/.") != 0 &&
		    strcmp(suffix, "/..") != 0) {
			size_t target_len = strlen(me->target);
			size_t suffix_len = path_len - src_len;

			target = kmalloc(target_len + suffix_len + 1, GFP_ATOMIC);
			if (target) {
				memcpy(target, me->target, target_len);
				memcpy(target + target_len, suffix, suffix_len);
				target[target_len + suffix_len] = '\0';
			}
		}
	}

	rcu_read_unlock();

	/*
	 * Skip kern_path validation here: this function is only called from
	 * hymo_kp_getname_flags_pre (kprobe handler), which runs in atomic
	 * context. kern_path -> d_alloc_parallel can sleep, causing
	 * "BUG: scheduling while atomic". If the target does not exist, the
	 * subsequent syscall will fail with -ENOENT.
	 */
	return target;
}

/* ======================================================================
 * Part 13: Reverse Lookup (for d_path kretprobe)
 * ====================================================================== */

static int hymofs_reverse_lookup(const char *pathname, char *buf, size_t buflen)
{
	struct hymo_entry *entry;
	struct hymo_merge_entry *me;
	u32 hash;
	int bkt, ret = -1;

	if (unlikely(!hymofs_enabled || !pathname || !buf))
		return -1;

	hash = full_name_hash(NULL, pathname, strlen(pathname));

	rcu_read_lock();

	hlist_for_each_entry_rcu(entry,
		&hymo_targets[hash_min(hash, HYMO_HASH_BITS)], target_node) {
		if (strcmp(entry->target, pathname) == 0) {
			ret = strscpy(buf, entry->src, buflen);
			if (ret < 0)
				ret = -ENAMETOOLONG;
			else
				ret = (int)strlen(buf);
			goto out;
		}
	}

	hash_for_each_rcu(hymo_merge_dirs, bkt, me, node) {
		size_t target_len = strlen(me->target);

		if (strncmp(pathname, me->target, target_len) == 0 &&
		    (pathname[target_len] == '/' || pathname[target_len] == '\0')) {
			size_t src_len = strlen(me->src);
			size_t suffix_len = strlen(pathname) - target_len;

			if (src_len + suffix_len + 1 > buflen) {
				ret = -ENAMETOOLONG;
			} else {
				memcpy(buf, me->src, src_len);
				memcpy(buf + src_len, pathname + target_len, suffix_len);
				buf[src_len + suffix_len] = '\0';
				ret = (int)(src_len + suffix_len);
			}
			goto out;
		}
	}

out:
	rcu_read_unlock();
	return ret;
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
		if (buf_size > 16 * 1024)
			buf_size = 16 * 1024;

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

		if (!src || !target) { ret = -EINVAL; break; }

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
				me->src = src;
				me->target = target;
				hlist_add_head_rcu(&me->node,
					&hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)]);
				src = NULL;
				target = NULL;
				hymo_merge_trie_build_locked();
			} else {
				ret = -ENOMEM;
			}
		} else {
			ret = -EEXIST;
		}
		spin_unlock(&hymo_inject_lock);
		spin_unlock(&hymo_merge_lock);
		if (!found && !ret)
			hymofs_add_inject_rule(kstrdup(me->src, GFP_ATOMIC));
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

		if (parent_dir)
			hymofs_add_inject_rule(parent_dir);

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

static long hymofs_dev_ioctl(struct file *file, unsigned int cmd,
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

	/* Inject: before first real entry, emit injected entries from merge/add rules. */
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
				/* Free remaining and return stop */
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

	if (w->dir_has_hidden && w->parent_dentry &&
	    !hymo_is_privileged_process() && hymo_should_apply_hide_rules()) {
		struct dentry *child;

		child = d_hash_and_lookup(w->parent_dentry,
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
#define HYMO_LR(regs)		((regs)->regs[30])
#define HYMO_POP_STACK(regs)	do { } while (0)
#elif defined(__x86_64__)
#define HYMO_REG0(regs)		((regs)->di)
#define HYMO_REG1(regs)		((regs)->si)
#define HYMO_REG2(regs)		((regs)->dx)
#define HYMO_REG3(regs)		((regs)->cx)
#define HYMO_LR(regs)		(*(unsigned long *)(regs)->sp)
#define HYMO_POP_STACK(regs)	do { (regs)->sp += 8; } while (0)
#else
#define HYMO_REG0(regs)		(0)
#define HYMO_REG1(regs)		(0)
#define HYMO_REG2(regs)		(0)
#define HYMO_REG3(regs)		(0)
#define HYMO_LR(regs)		(0)
#define HYMO_POP_STACK(regs)	do { } while (0)
#endif

/* getname_flags pre-handler: only modify user path and regs; return 0 to run original. */
static int hymo_kp_getname_flags_pre(struct kprobe *p, struct pt_regs *regs)
{
	const char __user *filename_user;
	char *buf;
	size_t len;
	char *target;

	(void)p;

	if (this_cpu_read(hymo_kprobe_reent))
		return 0;
	/* Skip when current is in ioctl path resolution (avoids reent / deadlock with metamount+hymod). */
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	filename_user = (const char __user *)HYMO_REG0(regs);
	if (!filename_user)
		return 0;

	buf = this_cpu_ptr(hymo_getname_path_buf);
	if (copy_from_user(buf, filename_user, HYMO_PATH_BUF - 1))
		return 0;
	buf[HYMO_PATH_BUF - 1] = '\0';

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

	/* Redirect: overwrite user path in place so original getname_flags sees it */
	if (buf[0] != '/')
		return 0;
	target = hymofs_resolve_target(buf);
	if (!target)
		return 0;
	len = strlen(target);
	if (len >= HYMO_PATH_BUF)
		goto out;
	if (copy_to_user((void __user *)filename_user, target, len + 1))
		goto out;
	kfree(target);
	return 0;
out:
	kfree(target);
	return 0;
}

/* vfs_getattr: pre saves path and kstat for kretprobe. */
static int hymo_kp_vfs_getattr_pre(struct kprobe *p, struct pt_regs *regs)
{
	(void)p;
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	this_cpu_write(hymo_vfs_getattr_path, (const struct path *)HYMO_REG0(regs));
	this_cpu_write(hymo_vfs_getattr_stat, (struct kstat *)HYMO_REG1(regs));
	return 0;
}

static inline bool hymofs_needs_stat_check(const struct path *path)
{
	const char *name;

	if (!path || !path->dentry)
		return false;
	name = path->dentry->d_name.name;
	if (name[0] == 'd' && name[1] == 'e' && name[2] == 'v' && name[3] == '\0')
		return false;
	if (name[0] == 'p' && !strncmp(name, "proc", 4))
		return false;
	if (name[0] == 's' && !strncmp(name, "sys", 3))
		return false;
	return true;
}

/*
 * vfs_getattr kretprobe: stat spoofing (ino/mtime) is disabled.
 * Per-CPU path/kstat is unsafe here: return can run on a different CPU than
 * entry (task migration), so we would dereference stale/invalid pointers and
 * fault. Re-enable only when using per-task or per-instance storage.
 */
static int hymo_krp_vfs_getattr_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	(void)ri;
	(void)regs;
	return 0;
}

/* d_path: pre saves buf and bufsize for kretprobe. */
static int hymo_kp_d_path_pre(struct kprobe *p, struct pt_regs *regs)
{
	(void)p;
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	this_cpu_write(hymo_d_path_buf, (char *)HYMO_REG1(regs));
	this_cpu_write(hymo_d_path_bufsize, (int)HYMO_REG2(regs));
	return 0;
}

static int hymo_krp_d_path_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	char *buf;
	int bufsize;
	char *res;
	char temp[256];
	int len;

	(void)ri;
#if defined(__aarch64__)
	res = (char *)regs->regs[0];
#elif defined(__x86_64__)
	res = (char *)regs->ax;
#else
	res = NULL;
#endif
	if (IS_ERR(res))
		return 0;
	if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;
	if (hymo_daemon_pid > 0 && task_tgid_vnr(current) == hymo_daemon_pid)
		return 0;
	if (hash_empty(hymo_targets) && hash_empty(hymo_merge_dirs))
		return 0;

	buf = this_cpu_read(hymo_d_path_buf);
	bufsize = this_cpu_read(hymo_d_path_bufsize);
	if (!buf || bufsize <= 0)
		return 0;

	len = hymofs_reverse_lookup(res, temp, sizeof(temp));
	if (len > 0 && len < bufsize) {
		memcpy(buf, temp, len + 1);
	}
	return 0;
}

/* iterate_dir: pre swaps ctx to our wrapper so kernel runs filldir filter. */
static int hymo_kp_iterate_dir_pre(struct kprobe *p, struct pt_regs *regs)
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

	if (w->parent_dentry && file) {
		char *path_buf = this_cpu_ptr(hymo_iterate_dir_path);
		char *res;

		dir_inode = d_inode(w->parent_dentry);
		if (dir_inode && dir_inode->i_mapping)
			w->dir_has_hidden = test_bit(AS_FLAGS_HYMO_DIR_HAS_HIDDEN,
						     &dir_inode->i_mapping->flags);
		dname = w->parent_dentry->d_name.name;
		if (dname[0] == 'd' && dname[1] == 'e' && dname[2] == 'v' && dname[3] == '\0')
			w->dir_path_len = 4;

		/* Get full path for inject lookup; d_path may sleep but we're in process context. */
		res = d_path(&file->f_path, path_buf, HYMO_ITERATE_PATH_BUF);
		if (!IS_ERR(res) && res[0] == '/') {
			w->dir_path = res;
			{
				struct hymo_inject_entry *ie;
				struct hymo_merge_entry *me;
				u32 h = full_name_hash(NULL, res, strlen(res));

				rcu_read_lock();
				hlist_for_each_entry_rcu(ie,
					&hymo_inject_dirs[hash_min(h, HYMO_HASH_BITS)], node) {
					if (strcmp(ie->dir, res) == 0) {
						w->dir_has_inject = true;
						break;
					}
				}
				if (!w->dir_has_inject) {
					hlist_for_each_entry_rcu(me,
						&hymo_merge_dirs[hash_min(h, HYMO_HASH_BITS)], node) {
						if (strcmp(me->src, res) == 0) {
							w->dir_has_inject = true;
							break;
						}
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

/* After iterate_dir returns, copy wrapper pos back to original ctx when we swapped. */
static int hymo_krp_iterate_dir_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hymofs_filldir_wrapper *w = this_cpu_ptr(&hymo_iterate_wrapper);

	(void)regs;
	(void)ri;
	if (this_cpu_read(hymo_iterate_did_swap) && w->orig_ctx)
		w->orig_ctx->pos = w->wrap_ctx.pos;
	this_cpu_write(hymo_iterate_did_swap, 0);
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
	hymo_kern_path = (void *)hymofs_lookup_name("kern_path");
	if (!hymo_kern_path) {
		pr_err("hymofs: FATAL - kern_path not found\n");
		return -ENOENT;
	}
	hymo_strndup_user = (void *)hymofs_lookup_name("strndup_user");
	if (!hymo_strndup_user) {
		pr_err("hymofs: FATAL - strndup_user not found\n");
		return -ENOENT;
	}
	hymo_ihold = (void *)hymofs_lookup_name("ihold");
	if (!hymo_ihold) {
		pr_err("hymofs: FATAL - ihold not found\n");
		return -ENOENT;
	}
	hymo_getname_kernel = (void *)hymofs_lookup_name("getname_kernel");
	if (!hymo_getname_kernel)
		pr_warn("hymofs: getname_kernel not found, path redirect may fail\n");

	/* Optional: allowlist support */
	hymo_filp_open = (void *)hymofs_lookup_name("filp_open");
	hymo_filp_close = (void *)hymofs_lookup_name("filp_close");
	hymo_kernel_read = (void *)hymofs_lookup_name("kernel_read");
	hymo_vfs_getattr = (void *)hymofs_lookup_name("vfs_getattr");
	hymo_dentry_open = (void *)hymofs_lookup_name("dentry_open");
	if (!hymo_filp_open || !hymo_kernel_read)
		pr_warn("hymofs: filp_open/kernel_read not found, allowlist disabled\n");
	if (!hymo_vfs_getattr || !hymo_dentry_open)
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
	/* Install VFS kprobes */
	{
		size_t i;
		int ret;

		for (i = 0; i < HYMOFS_VFS_HOOK_COUNT; i++) {
			unsigned long addr = hymofs_lookup_name(hymofs_vfs_hooks[i].name);
			if (!addr) {
				pr_err("hymofs: symbol not found: %s\n", hymofs_vfs_hooks[i].name);
				while (i--)
					unregister_kprobe(&hymofs_kprobes[i]);
				return -ENOENT;
			}
			hymofs_kprobes[i].addr = (kprobe_opcode_t *)addr;
			hymofs_kprobes[i].pre_handler = hymofs_vfs_hooks[i].pre;
			ret = register_kprobe(&hymofs_kprobes[i]);
			if (ret) {
				pr_err("hymofs: register_kprobe(%s) failed: %d\n",
				       hymofs_vfs_hooks[i].name, ret);
				while (i--)
					unregister_kprobe(&hymofs_kprobes[i]);
				return ret;
			}
			pr_info("hymofs: kprobe %s @0x%lx\n", hymofs_vfs_hooks[i].name, addr);
		}

		/* kretprobes for vfs_getattr and d_path (modify after return) */
		hymo_krp_vfs_getattr.kp.addr = hymofs_kprobes[HYMOFS_VFS_IDX_GETATTR].addr;
		hymo_krp_vfs_getattr.handler = hymo_krp_vfs_getattr_ret;
		hymo_krp_vfs_getattr.maxactive = 64;
		ret = register_kretprobe(&hymo_krp_vfs_getattr);
		if (ret) {
			pr_err("hymofs: register_kretprobe(vfs_getattr) failed: %d\n", ret);
			for (i = HYMOFS_VFS_HOOK_COUNT; i--; )
				unregister_kprobe(&hymofs_kprobes[i]);
			return ret;
		}
		hymo_krp_d_path.kp.addr = hymofs_kprobes[HYMOFS_VFS_IDX_DPATH].addr;
		hymo_krp_d_path.handler = hymo_krp_d_path_ret;
		hymo_krp_d_path.maxactive = 64;
		ret = register_kretprobe(&hymo_krp_d_path);
		if (ret) {
			pr_err("hymofs: register_kretprobe(d_path) failed: %d\n", ret);
			unregister_kretprobe(&hymo_krp_vfs_getattr);
			for (i = HYMOFS_VFS_HOOK_COUNT; i--; )
				unregister_kprobe(&hymofs_kprobes[i]);
			return ret;
		}
		hymo_krp_iterate_dir.kp.addr = hymofs_kprobes[HYMOFS_VFS_IDX_ITERDIR].addr;
		hymo_krp_iterate_dir.handler = hymo_krp_iterate_dir_ret;
		hymo_krp_iterate_dir.maxactive = 64;
		ret = register_kretprobe(&hymo_krp_iterate_dir);
		if (ret) {
			pr_err("hymofs: register_kretprobe(iterate_dir) failed: %d\n", ret);
			unregister_kretprobe(&hymo_krp_d_path);
			unregister_kretprobe(&hymo_krp_vfs_getattr);
			for (i = HYMOFS_VFS_HOOK_COUNT; i--; )
				unregister_kprobe(&hymofs_kprobes[i]);
			return ret;
		}
		pr_info("hymofs: kretprobes vfs_getattr, d_path, iterate_dir registered\n");
	}
	pr_info("hymofs: initialized (%d VFS kprobes + 3 kretprobes + GET_FD)\n",
		HYMOFS_VFS_HOOK_COUNT);
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
	unregister_kretprobe(&hymo_krp_iterate_dir);
	unregister_kretprobe(&hymo_krp_d_path);
	unregister_kretprobe(&hymo_krp_vfs_getattr);
	{
		size_t i;
		for (i = 0; i < HYMOFS_VFS_HOOK_COUNT; i++)
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
