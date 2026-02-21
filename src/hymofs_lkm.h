/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS LKM - internal header.
 * Shared constants and data structures (hooks use kprobes in .c).
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _HYMOFS_LKM_H
#define _HYMOFS_LKM_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/xarray.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/atomic.h>

#include "hymo_magic.h"

/* Bypass CFI/kCFI for indirect calls to dynamically resolved kernel symbols.
 * Classic CFI uses "cfi"; kernel 6.2+ kCFI uses "kcfi". Older Clang (e.g. in android12-5.10 DDK)
 * does not know "kcfi" and -Werror treats unknown sanitizer as error. Use 17+ for kcfi to
 * avoid DDK/backported Clang that reports 16 but lacks kcfi. */
#if defined(__clang__)
#if __clang_major__ >= 17
#define HYMO_NOCFI __attribute__((no_sanitize("cfi", "kcfi")))
#else
#define HYMO_NOCFI __attribute__((no_sanitize("cfi")))
#endif
#else
#define HYMO_NOCFI
#endif

/* ======================================================================
 * Configuration & Constants
 * ====================================================================== */

#define HYMO_HASH_BITS              12
#define HYMO_BLOOM_BITS             10
#define HYMO_BLOOM_SIZE             (1 << HYMO_BLOOM_BITS)
#define HYMO_BLOOM_MASK             (HYMO_BLOOM_SIZE - 1)
#define HYMO_MERGE_HASH_BITS        6
#define HYMO_MERGE_HASH_SIZE        (1 << HYMO_MERGE_HASH_BITS)

#define HYMO_ALLOWLIST_UID_MAX      1024
#define HYMO_KSU_ALLOWLIST_PATH     "/data/adb/ksu/.allowlist"
#define HYMO_KSU_ALLOWLIST_MAGIC    0x7f4b5355
#define HYMO_KSU_ALLOWLIST_VERSION  3
#define HYMO_KSU_MAX_PACKAGE_NAME   256
#define HYMO_KSU_MAX_GROUPS         32
#define HYMO_KSU_SELINUX_DOMAIN     64

#define HYMO_DEFAULT_MIRROR_NAME    "hymo_mirror"
#define HYMO_DEFAULT_MIRROR_PATH    "/dev/" HYMO_DEFAULT_MIRROR_NAME

/* Max path length in getname_flags pre-handler buffer. */
#define HYMO_PATH_BUF               512
/* iterate_dir path buffer; keep small to avoid percpu OOM on low-mem devices */
#define HYMO_ITERATE_PATH_BUF       512

/* dir_context.actor return type: 6.1+ uses bool */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0))
#define HYMO_FILLDIR_RET_TYPE int
#define HYMO_FILLDIR_CONTINUE 0
#define HYMO_FILLDIR_STOP     1
#else
#define HYMO_FILLDIR_RET_TYPE bool
#define HYMO_FILLDIR_CONTINUE true
#define HYMO_FILLDIR_STOP     false
#endif

/* Allowlist UID marker */
#define HYMO_UID_ALLOW_MARKER ((void *)1)


/* ======================================================================
 * Data Structures
 * ====================================================================== */

struct hymo_entry {
	char *src;
	char *target;
	unsigned char type;
	u32 src_hash;
	struct hlist_node node;
	struct hlist_node target_node;
	struct rcu_head rcu;
};

struct hymo_hide_entry {
	char *path;
	u32 path_hash;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct hymo_inject_entry {
	char *dir;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct hymo_xattr_sb_entry {
	struct super_block *sb;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct hymo_merge_entry {
	char *src;
	char *target;
	char *resolved_src;	/* canonical path for iterate_dir lookup; NULL if same as src */
	struct dentry *target_dentry;	/* cached dentry of target dir for d_hash_and_lookup */
	struct hlist_node node;
	struct rcu_head rcu;
};

struct hymo_merge_target_node {
	struct list_head list;
	char *target;
	struct dentry *target_dentry;
};

struct hymo_name_list {
	char *name;
	unsigned char type;
	struct list_head list;
};

/* KSU allowlist structures */
struct hymo_root_profile {
	s32 uid;
	s32 gid;
	s32 groups_count;
	s32 groups[HYMO_KSU_MAX_GROUPS];
	struct {
		u64 effective;
		u64 permitted;
		u64 inheritable;
	} capabilities;
	char selinux_domain[HYMO_KSU_SELINUX_DOMAIN];
	s32 namespaces;
};

struct hymo_non_root_profile {
	bool umount_modules;
};

struct hymo_app_profile {
	u32 version;
	char key[HYMO_KSU_MAX_PACKAGE_NAME];
	s32 current_uid;
	bool allow_su;
	union {
		struct {
			bool use_default;
			char template_name[HYMO_KSU_MAX_PACKAGE_NAME];
			struct hymo_root_profile profile;
		} rp_config;
		struct {
			bool use_default;
			struct hymo_non_root_profile profile;
		} nrp_config;
	};
};

/* kretprobe instance data for vfs_getattr stat spoofing */
struct hymo_getattr_ri_data {
	struct kstat *stat;
	struct address_space *mapping;
	bool is_target;
};

/* kretprobe instance data for vfs_getxattr SELinux context spoofing */
#define HYMO_SELINUX_CTX_MAX 96
struct hymo_getxattr_ri_data {
	void *value_buf;
	size_t value_size;
	bool spoof_selinux;
	char src_ctx[HYMO_SELINUX_CTX_MAX];
	size_t src_ctx_len;
};

/* kretprobe instance data for d_path reverse mapping */
#define HYMO_D_PATH_SRC_MAX 256
struct hymo_d_path_ri_data {
	char *buf;
	int buflen;
	bool is_target;
	char src_path[HYMO_D_PATH_SRC_MAX];
};

#define HYMO_MAX_MERGE_TARGETS 4

/* iterate_dir: wrapper passed as second arg so kernel runs our filldir filter. */
struct hymofs_filldir_wrapper {
	struct dir_context wrap_ctx;
	struct dir_context *orig_ctx;
	struct dentry *parent_dentry;
	int dir_path_len;
	bool dir_has_hidden;
	const char *dir_path;	/* full path for inject lookup; points to per-CPU buf */
	bool dir_has_inject;	/* merge/inject dir: inject entries before real ones */
	bool inject_done;	/* inject already performed this iteration */
	int merge_target_count;
	struct dentry *merge_target_dentries[HYMO_MAX_MERGE_TARGETS];
};

/* ======================================================================
 * Logging
 * ====================================================================== */

#define hymo_log(fmt, ...) do { \
	if (hymo_debug_enabled) \
		pr_info("hymofs: " fmt, ##__VA_ARGS__); \
} while (0)

/* debug flag - defined in hymofs_lkm.c */
extern bool hymo_debug_enabled;

/* Called by syscall handler (e.g. KP) when userspace requests HYMO_CMD_GET_FD. Returns anon fd or negative errno. */
int hymofs_get_anon_fd(void);

#endif /* _HYMOFS_LKM_H */
