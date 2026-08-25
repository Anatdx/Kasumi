/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - shared in-kernel data structures for rules and hook state.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_TYPES_H
#define _KASUMI_TYPES_H

#include <linux/atomic.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/xarray.h>

#include "kasumi_base.h"

struct kasumi_entry {
	char *src;
	char *target;
	char *source_canonical;
	/* Pinned data source resolved from target when the rule is installed. */
	struct path source_path;
	struct path source_nofollow_path;
	struct inode *source_inode;
	struct kstat source_stat;
	struct kstat source_nofollow_stat;
	struct kstat visible_stat;
	unsigned long source_ino;
	unsigned long source_dev;
	unsigned long visible_ino;
	unsigned long visible_dev;
	unsigned long nofollow_visible_ino;
	unsigned long nofollow_visible_dev;
	umode_t source_mode;
	umode_t source_nofollow_mode;
	kuid_t source_uid;
	kgid_t source_gid;
	loff_t source_size;
	bool source_stat_valid;
	bool visible_stat_valid;
	/* A real node existed at src when the rule was installed.  Its DAC and
	 * timestamp metadata remains the visible template while source-backed
	 * type/size/allocation fields are refreshed dynamically. */
	bool preserve_visible_metadata;
	bool source_path_valid;
	bool source_nofollow_stat_valid;
	bool source_nofollow_path_valid;
	unsigned char type;
	u32 src_hash;
	struct hlist_node node;
	struct hlist_node target_node;
	struct rcu_head rcu;
};

struct kasumi_hide_entry {
	char *path;
	u32 path_hash;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct kasumi_inject_entry {
	char *dir;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct kasumi_xattr_sb_entry {
	struct super_block *sb;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct kasumi_merge_entry {
	char *src;
	char *target;
	char *resolved_src;
	struct dentry *target_dentry;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct kasumi_merge_target_node {
	struct list_head list;
	char *target;
	struct dentry *target_dentry;
};

struct kasumi_name_list {
	char *name;
	u64 ino;
	unsigned char type;
	struct list_head list;
};

struct kasumi_root_profile {
	s32 uid;
	s32 gid;
	s32 groups_count;
	s32 groups[KASUMI_KSU_MAX_GROUPS];
	struct {
		u64 effective;
		u64 permitted;
		u64 inheritable;
	} capabilities;
	char selinux_domain[KASUMI_KSU_SELINUX_DOMAIN];
	s32 namespaces;
};

struct kasumi_non_root_profile {
	bool umount_modules;
};

struct kasumi_app_profile {
	u32 version;
	char key[KASUMI_KSU_MAX_PACKAGE_NAME];
	s32 curr_uid;
	bool allow_su;
	union {
		struct {
			bool use_default;
			char template_name[KASUMI_KSU_MAX_PACKAGE_NAME];
			struct kasumi_root_profile profile;
		} rp_config;
		struct {
			bool use_default;
			struct kasumi_non_root_profile profile;
		} nrp_config;
	};
};

struct kasumi_getattr_ri_data {
	struct kstat *stat;
	struct address_space *mapping;
	bool is_target;
};

struct kasumi_getxattr_ri_data {
	void *value_buf;
	size_t value_size;
	bool spoof_selinux;
	char src_ctx[KASUMI_SELINUX_CTX_MAX];
	size_t src_ctx_len;
};

struct kasumi_d_path_ri_data {
	char *buf;
	int buflen;
	bool is_target;
	char src_path[KASUMI_D_PATH_SRC_MAX];
};

struct kasumi_filldir_wrapper {
	struct dir_context wrap_ctx;
	struct dir_context *orig_ctx;
	struct dentry *parent_dentry;
	int dir_path_len;
	bool dir_has_hidden;
	const char *dir_path;
	bool dir_has_inject;
	bool inject_done;
	bool view_allowed;
	bool spoof_allowed;
	int merge_target_count;
	struct dentry *merge_target_dentries[KASUMI_MAX_MERGE_TARGETS];
	char dir_path_buf[KASUMI_ITERATE_PATH_BUF];
};

struct kasumi_iterate_ri_data {
	int did_swap;
	struct kasumi_filldir_wrapper *wrapper;
};

#endif /* _KASUMI_TYPES_H */
