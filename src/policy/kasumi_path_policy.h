/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - policy helpers for path visibility and redirect decisions.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_PATH_POLICY_H
#define _KASUMI_PATH_POLICY_H

#include <linux/list.h>
#include <linux/path.h>
#include <linux/stat.h>
#include <linux/types.h>

struct kasumi_entry;
struct kasumi_policy_state_arg;

struct kasumi_rule_source {
	struct path path;
	struct kstat stat;
	umode_t source_mode;
	unsigned long visible_ino;
	unsigned long visible_dev;
	bool stat_valid;
	bool preserve_visible_metadata;
	int error;
};

void kasumi_project_visible_stat(struct kstat *result,
				 const struct kstat *source_stat,
				 const struct kstat *visible_template,
				 bool preserve_visible_metadata,
				 unsigned long visible_ino,
				 unsigned long visible_dev);
int kasumi_visible_access(const struct kstat *stat, int mode,
			  bool effective_ids);
int kasumi_visible_open_access(const struct kstat *stat, int mode);

enum kasumi_policy_scope {
	KASUMI_POLICY_SCOPE_NONE = 0,
	KASUMI_POLICY_SCOPE_VIEW,
	KASUMI_POLICY_SCOPE_SPOOF,
};

bool kasumi_is_privileged_process(void);
bool kasumi_policy_prepare_enable_locked(void);
void kasumi_policy_disable_provider_locked(void);
bool kasumi_policy_uid_is_view_target(uid_t uid);
bool kasumi_policy_uid_is_spoof_target(uid_t uid);
u32 kasumi_policy_configured_owner(void);
u32 kasumi_policy_effective_owner(void);
int kasumi_policy_replace(u32 owner, u32 flags,
			  const u32 *allow_uids, u32 allow_count,
			  const u32 *deny_uids, u32 deny_count);
int kasumi_set_policy_owner(u32 owner, u32 flags);
int kasumi_replace_policy_uid_list(u32 list, const u32 *uids, u32 count);
int kasumi_clear_policy_uid_list(u32 list);
void kasumi_policy_get_state(struct kasumi_policy_state_arg *state);
int kasumi_policy_copy_uids(u32 list, u32 *uids, u32 capacity,
			    u32 *copied, u32 *total, u64 *generation);
int kasumi_policy_reset(void);
void kasumi_policy_shutdown_locked(void);
enum kasumi_policy_scope kasumi_policy_current_scope(void);
bool kasumi_policy_current_is_view_target(void);
bool kasumi_policy_current_is_spoof_target(void);
bool kasumi_policy_current_is_isolated(void);
bool kasumi_current_is_selinux_guard_target(void);
char *kasumi_resolve_target(const char *pathname);
char *kasumi_resolve_target_slow(const char *pathname);
bool kasumi_rule_get_source(const char *pathname,
			    struct kasumi_rule_source *source);
bool kasumi_rule_get_source_flags(const char *pathname,
				  unsigned int lookup_flags,
				  struct kasumi_rule_source *source);
bool kasumi_rule_get_visible_path(const struct path *source,
				  char *visible_path,
				  size_t visible_path_size);
bool kasumi_rule_path_is_virtual(const char *pathname);
bool kasumi_should_hide(const char *pathname);
/* Caller must hold rcu_read_lock(); returned entry is only valid until unlock. */
struct kasumi_entry *kasumi_reverse_lookup_target(const char *path_str);

/*
 * Slice 4c-v2 pure-virtual directory topology: resolve names under a synthetic
 * (source-less) directory against the rule table.  A F_VIRTUAL_DIR vnode uses
 * these to decide whether a child name is an exact redirect (a leaf) or the
 * prefix of one (a deeper virtual dir), and to enumerate its children.
 */
enum kasumi_vpath_kind {
	KASUMI_VPATH_NONE = 0,	/* no rule under dir/child */
	KASUMI_VPATH_LEAF,	/* dir/child is an exact rule -> a real redirect */
	KASUMI_VPATH_VDIR,	/* dir/child is a prefix of some rule -> virtual dir */
};

/*
 * Resolve @child within virtual directory @dir.  On KASUMI_VPATH_LEAF pins
 * *leaf_src (caller kasumi_path_put) and fills *leaf_mode / *leaf_ino with the
 * leaf's source identity (the nofollow link for a symlink target).  Non-sleeping
 * apart from a GFP_KERNEL scratch alloc; the rule-table scan runs under RCU.
 */
int kasumi_rule_vpath_child(const char *dir, const char *child,
			    struct path *leaf_src, umode_t *leaf_mode,
			    unsigned long *leaf_ino);

/*
 * Collect the direct children of virtual directory @dir into @out as
 * struct kasumi_name_list nodes (name/ino/type), deduplicated.  Caller emits and
 * frees each node (kfree(name) then kfree(node)).  Returns the child count.
 */
int kasumi_rule_vpath_emit(const char *dir, struct list_head *out);

#endif /* _KASUMI_PATH_POLICY_H */
