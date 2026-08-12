/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - scoped selinuxfs transaction filtering for hidden-app views.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_FAKE_SELINUXFS_ACCESS_H
#define _KASUMI_FAKE_SELINUXFS_ACCESS_H

#include <linux/types.h>

int kasumi_fake_selinuxfs_access_init(void);
void kasumi_fake_selinuxfs_access_exit(void);
bool kasumi_fake_selinuxfs_access_active(void);
bool kasumi_fake_selinuxfs_status_active(void);
bool kasumi_fake_selinuxfs_proc_attr_active(void);
bool kasumi_fake_selinuxfs_context_is_sensitive(const char *context);

#endif /* _KASUMI_FAKE_SELINUXFS_ACCESS_H */
