/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - shared cross-module entry points used by hook and feature code.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_ENTRYPOINTS_H
#define _KASUMI_ENTRYPOINTS_H

#include <asm/ptrace.h>
#include <linux/fs.h>

#include "kasumi_base.h"
#include "kasumi_types.h"

extern int kasumi_syscall_nr_param;

int kasumi_get_anon_fd(void);

void kasumi_handle_sys_enter_path(struct pt_regs *regs, long id);
void kasumi_handle_sys_exit_path(struct pt_regs *regs, long ret);
void kasumi_handle_sys_enter_statx(struct pt_regs *regs, long id);
void kasumi_handle_sys_exit_statx(struct pt_regs *regs, long ret);
void kasumi_handle_sys_enter_statfs(struct pt_regs *regs, long id);
void kasumi_handle_sys_exit_statfs(struct pt_regs *regs, long ret);
void kasumi_handle_sys_enter_getfd(struct pt_regs *regs, long id);
void kasumi_handle_sys_exit_getfd(struct pt_regs *regs, long ret);
void kasumi_handle_sys_enter_cmdline(struct pt_regs *regs, long id);
void kasumi_handle_sys_exit_cmdline(struct pt_regs *regs, long ret);

unsigned long kasumi_lookup_name(const char *name);
unsigned long kasumi_lookup_callable(const char *name);
bool kasumi_should_apply_hide_rules(void);

KASUMI_FILLDIR_RET_TYPE kasumi_filldir_filter(struct dir_context *ctx, const char *name,
					    int namlen, loff_t offset, u64 ino,
					    unsigned int d_type);

#endif /* _KASUMI_ENTRYPOINTS_H */
