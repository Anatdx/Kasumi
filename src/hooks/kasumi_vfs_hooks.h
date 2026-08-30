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
struct kprobe;
struct kretprobe_instance;
struct pt_regs;

int kasumi_vfs_hooks_init(bool skip_vfs);
void kasumi_vfs_hooks_exit(bool skip_vfs);
struct kasumi_filldir_wrapper *kasumi_iterate_prepare_wrapper(struct file *file,
							      struct dir_context *orig_ctx);
void kasumi_iterate_finish_wrapper(struct kasumi_filldir_wrapper *wrapper);
char __user *kasumi_userspace_stack_buffer(const char *data, size_t len);
int kasumi_krp_vfs_getattr_entry(struct kretprobe_instance *ri,
					 struct pt_regs *regs);
int kasumi_krp_vfs_getattr_ret(struct kretprobe_instance *ri,
				       struct pt_regs *regs);
int kasumi_krp_vfs_getxattr_entry(struct kretprobe_instance *ri,
					 struct pt_regs *regs);
int kasumi_krp_vfs_getxattr_ret(struct kretprobe_instance *ri,
				       struct pt_regs *regs);
int kasumi_krp_d_path_entry(struct kretprobe_instance *ri,
			     struct pt_regs *regs);
int kasumi_krp_d_path_ret(struct kretprobe_instance *ri,
			   struct pt_regs *regs);
int kasumi_kp_iterate_dir_pre(struct kprobe *p, struct pt_regs *regs);
int kasumi_krp_iterate_dir_ret(struct kretprobe_instance *ri,
				       struct pt_regs *regs);

#endif /* _KASUMI_VFS_HOOKS_H */
