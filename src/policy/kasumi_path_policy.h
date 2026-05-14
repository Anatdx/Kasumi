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

bool kasumi_is_privileged_process(void);
bool kasumi_reload_ksu_allowlist(void);
bool kasumi_current_is_selinux_guard_target(void);
char *kasumi_resolve_target(const char *pathname);
bool kasumi_should_hide(const char *pathname);
/* Caller must hold rcu_read_lock(); returned entry is only valid until unlock. */
struct kasumi_entry *kasumi_reverse_lookup_target(const char *path_str);

#endif /* _KASUMI_PATH_POLICY_H */
