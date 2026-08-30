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

typedef int (*kasumi_fop_iterate_client_fn)(struct file *file,
					    struct dir_context *ctx,
					    const struct file_operations *orig,
					    void *data);

int kasumi_fop_override_init(void);
void kasumi_fop_override_stop_new(void);
void kasumi_fop_override_exit(void);
/* Retire all inode bindings without permanently disabling future installs.
 * Dynamic fops and their original-owner reference remain allocated until
 * module exit so already-open directory files stay safe. */
void kasumi_fop_override_clear(void);

int kasumi_fop_install(struct inode *inode);
/* Bind one specialized iterate client to an installed inode shadow.  The data
 * pointer is release-published with @client and is protected by the client SRCU
 * domain while callbacks execute. */
int kasumi_fop_bind_iterate_client(struct inode *inode,
				   kasumi_fop_iterate_client_fn client, void *data);
/* Withdraw a matching client.  Call synchronize_iterate_clients() before
 * freeing @data or rebinding this inode to different client data. */
void kasumi_fop_unbind_iterate_client(struct inode *inode, void *data);
void kasumi_fop_synchronize_iterate_clients(void);
bool kasumi_fop_file_is_shadowed(const struct file *file);
void kasumi_fop_cleanup_inode(struct inode *inode);

#endif /* _KASUMI_FOP_OVERRIDE_H */
