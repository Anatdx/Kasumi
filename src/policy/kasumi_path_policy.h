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

#include <linux/types.h>

struct kasumi_entry;
struct kasumi_policy_state_arg;

bool kasumi_is_privileged_process(void);
bool kasumi_policy_prepare_enable(void);
void kasumi_policy_disable_provider_locked(void);
u32 kasumi_policy_configured_owner(void);
u32 kasumi_policy_effective_owner(void);
int kasumi_policy_replace(u32 owner, u32 flags,
			  const u32 *allow_uids, u32 allow_count,
			  const u32 *deny_uids, u32 deny_count);
bool kasumi_policy_mutation_allowed(void);
int kasumi_set_policy_owner(u32 owner, u32 flags);
int kasumi_replace_policy_uid_list(u32 list, const u32 *uids, u32 count);
int kasumi_clear_policy_uid_list(u32 list);
void kasumi_policy_get_state(struct kasumi_policy_state_arg *state);
int kasumi_policy_copy_uids(u32 list, u32 *uids, u32 capacity,
			    u32 *copied, u32 *total, u64 *generation);
int kasumi_policy_reset(void);
void kasumi_policy_shutdown_locked(void);
bool kasumi_should_apply_hide_rules(void);
bool kasumi_current_is_selinux_guard_target(void);
char *kasumi_resolve_target(const char *pathname);
char *kasumi_resolve_target_slow(const char *pathname);
bool kasumi_should_hide(const char *pathname);
/* Caller must hold rcu_read_lock(); returned entry is only valid until unlock. */
struct kasumi_entry *kasumi_reverse_lookup_target(const char *path_str);

#endif /* _KASUMI_PATH_POLICY_H */
