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

#include <linux/types.h>

enum kasumi_root_type {
	KASUMI_ROOT_NONE      = 0,
	KASUMI_ROOT_KSU       = 1 << 0,
	KASUMI_ROOT_KSU_RDR   = 1 << 1,
	KASUMI_ROOT_APATCH    = 1 << 2,
	KASUMI_ROOT_MAGISK    = 1 << 3,
	KASUMI_ROOT_MULTI     = 1 << 4,
	KASUMI_ROOT_NON_ROOT  = 1 << 5,
};

struct kasumi_ap_su_profile {
	uid_t uid;
	uid_t to_uid;
	char scontext[0x60];
};

extern int kasumi_root_mask;
extern int kasumi_ksu_dispatcher_nr;
extern int kasumi_policy_owner_override;
extern bool kasumi_root_spoof_allowed;
extern const char *(*kasumi_ap_su_get_path)(void);
extern int (*kasumi_ap_is_su_allow_uid)(uid_t uid);
extern int (*kasumi_ap_su_allow_uid_nums)(void);
extern int (*kasumi_ap_su_allow_uids)(int is_user, uid_t *out_uids,
				      int out_num);
extern int (*kasumi_ap_su_allow_uid_profile)(int is_user, uid_t uid,
					     struct kasumi_ap_su_profile *profile);
extern int (*kasumi_ap_get_mod_exclude)(uid_t uid);
extern int (*kasumi_ap_list_mod_exclude)(uid_t *uids, int len);
extern int (*kasumi_ap_read_kstorage)(int gid, long did, void *data,
				      int offset, int len, bool data_is_user);
extern int (*kasumi_ap_list_kstorage_ids)(int gid, long *ids, int idslen,
					  bool data_is_user);

void kasumi_root_detect(void);
bool kasumi_root_allows_spoofing(void);

#endif
