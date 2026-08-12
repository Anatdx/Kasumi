/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
#ifndef _KASUMI_TRACEPOINT_HOOKS_H
#define _KASUMI_TRACEPOINT_HOOKS_H

#include <linux/types.h>

int kasumi_tracepoint_hooks_init(void);
void kasumi_tracepoint_hooks_exit(void);
bool kasumi_tracepoint_hooks_active(void);

#endif /* _KASUMI_TRACEPOINT_HOOKS_H */
