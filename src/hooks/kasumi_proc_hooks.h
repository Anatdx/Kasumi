/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - proc-facing hook lifecycle and mount-proxy interfaces.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_PROC_HOOKS_H
#define _KASUMI_PROC_HOOKS_H

#include <linux/types.h>

int kasumi_proc_hooks_init(bool skip_getfd, bool no_tracepoint);
void kasumi_proc_hooks_start(void);
void kasumi_proc_hooks_exit(void);
void kasumi_proc_hooks_stop_new(void);
unsigned int kasumi_proc_getfd_pending(void);
void kasumi_proc_read_hooks_init(void);
void kasumi_proc_read_hooks_stop_new(void);
void kasumi_proc_read_hooks_exit(void);
unsigned int kasumi_proc_proxy_live(void);

#endif /* _KASUMI_PROC_HOOKS_H */
