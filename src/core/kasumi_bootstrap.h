/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - top-level module bootstrap and teardown interfaces.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_BOOTSTRAP_H
#define _KASUMI_BOOTSTRAP_H

#include <linux/types.h>

int kasumi_bootstrap_init(void);
bool kasumi_bootstrap_quiesce_supported(void);
bool kasumi_bootstrap_unload_pin_held(void);
void kasumi_bootstrap_release_unload_pin(void);
void kasumi_bootstrap_exit(void);

#endif /* _KASUMI_BOOTSTRAP_H */
