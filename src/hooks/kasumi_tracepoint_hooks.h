/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
#ifndef _KASUMI_TRACEPOINT_HOOKS_H
#define _KASUMI_TRACEPOINT_HOOKS_H

#include <linux/types.h>

int kasumi_tracepoint_hooks_init(void);
int kasumi_tracepoint_hooks_set_enabled(bool enabled);
void kasumi_tracepoint_hooks_exit(void);
bool kasumi_tracepoint_hooks_active(void);
bool kasumi_tracepoint_hooks_available(void);
bool kasumi_tracepoint_hooks_owned_mark_clear_safe(void);
bool kasumi_tracepoint_hooks_exclusive_owner(void);
bool kasumi_tracepoint_hooks_ksu_shared(void);

#endif /* _KASUMI_TRACEPOINT_HOOKS_H */
