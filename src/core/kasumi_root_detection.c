/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - root implementation detection.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>

#include "kasumi_root_detection.h"
#include "kasumi_runtime.h"

int kasumi_root_mask;

void kasumi_root_detect(void)
{
	unsigned long a;

	kasumi_root_mask = KASUMI_ROOT_NONE;

	a = kasumi_lookup_name("ksu_syscall_table");
	if (a && kasumi_valid_kernel_addr(a)) {
		kasumi_root_mask |= KASUMI_ROOT_KSU;
		a = kasumi_lookup_name("ksu_dispatcher_nr");
		if (a && kasumi_valid_kernel_addr(a) &&
		    READ_ONCE(*(int *)a) >= 0)
			kasumi_root_mask |= KASUMI_ROOT_KSU_RDR;
		pr_info("Kasumi: KernelSU detected%s\n",
			(kasumi_root_mask & KASUMI_ROOT_KSU_RDR) ?
			" (redirect)" : "");
	}

	a = kasumi_lookup_name("su_get_path");
	if (a && kasumi_valid_kernel_addr(a)) {
		kasumi_root_mask |= KASUMI_ROOT_APATCH;
		pr_info("Kasumi: APatch sucompat detected\n");
	}

	if (!(kasumi_root_mask & KASUMI_ROOT_KSU)) {
		struct file *f = filp_open("/sbin/magisk", O_RDONLY, 0);

		if (!IS_ERR(f)) {
			filp_close(f, NULL);
			kasumi_root_mask |= KASUMI_ROOT_MAGISK;
			pr_info("Kasumi: Magisk detected\n");
		}
	}
}
