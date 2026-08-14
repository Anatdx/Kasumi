/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - directory file_operations shadow overrides for readdir filtering.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_FOP_OVERRIDE_H
#define _KASUMI_FOP_OVERRIDE_H

#include <linux/fs.h>

int kasumi_fop_override_init(void);
void kasumi_fop_override_stop_new(void);
void kasumi_fop_override_exit(void);

int kasumi_fop_install(struct inode *inode);
bool kasumi_fop_file_is_shadowed(const struct file *file);
void kasumi_fop_cleanup_inode(struct inode *inode);

#endif /* _KASUMI_FOP_OVERRIDE_H */
