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

int kasumi_proc_hooks_init(bool skip_getfd, bool no_tracepoint, bool skip_extra_kprobes);
void kasumi_proc_hooks_exit(void);
void kasumi_proc_read_hooks_init(void);
void kasumi_proc_read_hooks_exit(void);
int kasumi_mount_proxy_install_fd(int fd);
bool kasumi_proc_proxy_should_try(void);
bool kasumi_path_is_proc_mount_view(const char *path);
bool kasumi_path_is_proc_mountinfo(const char *path);
bool kasumi_path_needs_proc_proxy(const char *path);

#endif /* _KASUMI_PROC_HOOKS_H */
