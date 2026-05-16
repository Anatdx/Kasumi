/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - VFS hook lifecycle interfaces for path, stat, xattr, and iterate flows.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_VFS_HOOKS_H
#define _KASUMI_VFS_HOOKS_H

#include <linux/types.h>

struct dir_context;
struct file;
struct kasumi_filldir_wrapper;

int kasumi_vfs_hooks_init(bool skip_vfs);
void kasumi_vfs_hooks_exit(bool skip_vfs);
struct kasumi_filldir_wrapper *kasumi_iterate_prepare_wrapper(struct file *file,
							      struct dir_context *orig_ctx);
void kasumi_iterate_finish_wrapper(struct kasumi_filldir_wrapper *wrapper);
char __user *kasumi_userspace_stack_buffer(const char *data, size_t len);

#if defined(__aarch64__) || defined(__x86_64__)
/* Resolve whether `fd` currently refers to /proc/cmdline.  Safe to call
 * from process context (issues fget/fput). Used by the direct read hook
 * and kretprobe fallback. */
bool kasumi_fd_is_proc_cmdline(int fd);
#endif

#endif /* _KASUMI_VFS_HOOKS_H */
