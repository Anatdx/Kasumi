/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - root implementation detection header.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_ROOT_DETECTION_H
#define _KASUMI_ROOT_DETECTION_H

enum kasumi_root_type {
	KASUMI_ROOT_NONE      = 0,
	KASUMI_ROOT_KSU       = 1 << 0,
	KASUMI_ROOT_KSU_RDR   = 1 << 1,
	KASUMI_ROOT_APATCH    = 1 << 2,
	KASUMI_ROOT_MAGISK    = 1 << 3,
};

extern int kasumi_root_mask;

void kasumi_root_detect(void);

#endif
