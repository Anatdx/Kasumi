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

int kasumi_install_anon_fd(int __user *outp);

unsigned long kasumi_lookup_name(const char *name);
unsigned long kasumi_lookup_callable(const char *name);
bool kasumi_policy_current_is_view_target(void);
bool kasumi_policy_current_is_spoof_target(void);

KASUMI_FILLDIR_RET_TYPE kasumi_filldir_filter(struct dir_context *ctx, const char *name,
					    int namlen, loff_t offset, u64 ino,
					    unsigned int d_type);

#endif /* _KASUMI_ENTRYPOINTS_H */
