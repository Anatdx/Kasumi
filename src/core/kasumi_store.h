/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - rule store declarations and cleanup helpers for shared tables.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_STORE_H
#define _KASUMI_STORE_H

#include <linux/bitmap.h>
#include <linux/limits.h>

#include "kasumi_runtime.h"

struct kasumi_spoof_kstat_entry {
	char *target_pathname;
	u32 path_hash;
	unsigned long target_ino;
	unsigned long target_dev;
	unsigned long spoofed_ino;
	unsigned long spoofed_dev;
	unsigned int spoofed_nlink;
	long long spoofed_size;
	long spoofed_atime_sec;
	long spoofed_atime_nsec;
	long spoofed_mtime_sec;
	long spoofed_mtime_nsec;
	long spoofed_ctime_sec;
	long spoofed_ctime_nsec;
	unsigned long spoofed_blksize;
	unsigned long long spoofed_blocks;
	int is_static;
	struct hlist_node path_node;
	struct hlist_node ino_node;
	struct rcu_head rcu;
};

struct kasumi_maps_rule_entry {
	struct list_head list;
	unsigned long target_ino;
	unsigned long target_dev;
	unsigned long spoofed_ino;
	unsigned long spoofed_dev;
	char spoofed_pathname[KSM_MAX_LEN_PATHNAME];
};

extern struct hlist_head kasumi_paths[1 << KASUMI_HASH_BITS];
extern struct hlist_head kasumi_targets[1 << KASUMI_HASH_BITS];
extern struct hlist_head kasumi_hide_paths[1 << KASUMI_HASH_BITS];
extern struct xarray kasumi_allow_uids_xa;
extern struct xarray kasumi_policy_allow_uids_xa;
extern struct xarray kasumi_policy_deny_uids_xa;
extern u32 kasumi_policy_allow_uid_list[KASUMI_ALLOWLIST_UID_MAX];
extern u32 kasumi_policy_deny_uid_list[KASUMI_ALLOWLIST_UID_MAX];
extern u32 kasumi_policy_allow_uid_count;
extern u32 kasumi_policy_deny_uid_count;
extern struct hlist_head kasumi_inject_dirs[1 << KASUMI_HASH_BITS];
extern struct hlist_head kasumi_xattr_sbs[1 << KASUMI_HASH_BITS];
extern struct hlist_head kasumi_merge_dirs[1 << KASUMI_HASH_BITS];
extern struct hlist_head kasumi_spoof_kstat_path[1 << KASUMI_HASH_BITS];
extern struct hlist_head kasumi_spoof_kstat_ino[1 << KASUMI_HASH_BITS];
extern struct list_head kasumi_maps_rules;

extern struct mutex kasumi_config_mutex;
extern struct mutex kasumi_maps_mutex;

extern bool kasumi_allowlist_loaded;
extern u32 kasumi_policy_flags;
extern unsigned long kasumi_path_bloom[BITS_TO_LONGS(KASUMI_BLOOM_SIZE)];
extern unsigned long kasumi_hide_bloom[BITS_TO_LONGS(KASUMI_BLOOM_SIZE)];

struct kasumi_spoof_kstat_entry *kasumi_spoof_kstat_lookup_by_path(const char *path_str);
struct kasumi_spoof_kstat_entry *kasumi_spoof_kstat_lookup_by_ino(unsigned long ino,
								unsigned long dev);

void kasumi_mark_inode_hidden(struct inode *inode);
bool kasumi_is_inode_hidden_bit(struct inode *inode);
void kasumi_mark_dir_has_inject(const char *path_str);
void kasumi_clear_inode_flags_for_path(const char *path_str, unsigned int bit);
void kasumi_cleanup_locked(void);

void kasumi_entry_free_rcu(struct rcu_head *head);
void kasumi_hide_entry_free_rcu(struct rcu_head *head);
void kasumi_inject_entry_free_rcu(struct rcu_head *head);
void kasumi_xattr_sb_entry_free_rcu(struct rcu_head *head);
void kasumi_merge_entry_free_rcu(struct rcu_head *head);
void kasumi_spoof_kstat_entry_free_rcu(struct rcu_head *head);

#endif /* _KASUMI_STORE_H */
