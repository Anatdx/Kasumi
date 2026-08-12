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
#include "kasumi_uapi.h"

enum kasumi_root_type {
	KASUMI_ROOT_NONE      = 0,
	KASUMI_ROOT_KSU       = KSM_POLICY_ROOT_KERNELSU,
	KASUMI_ROOT_KSU_RDR   = KSM_POLICY_ROOT_KERNELSU_REDIRECT,
	KASUMI_ROOT_APATCH    = KSM_POLICY_ROOT_APATCH,
	KASUMI_ROOT_MAGISK    = KSM_POLICY_ROOT_MAGISK,
	KASUMI_ROOT_MULTI     = KSM_POLICY_ROOT_MULTI,
	KASUMI_ROOT_NON_ROOT  = KSM_POLICY_ROOT_NO_PROVIDER,
};

struct kasumi_ap_su_profile {
	uid_t uid;
	uid_t to_uid;
	char scontext[0x60];
};

extern int kasumi_root_mask;
extern int kasumi_ksu_dispatcher_nr;
extern int kasumi_root_policy_owner;
extern bool kasumi_root_spoof_allowed;
extern bool kasumi_ksu_policy_available;
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
extern bool kasumi_apatch_policy_lifetime_stable;

void kasumi_root_detect(void);
bool kasumi_root_allows_spoofing(void);
bool kasumi_refresh_apatch_policy(void);
bool kasumi_probe_apatch_policy(unsigned long *addr, bool *lifetime_stable);

#endif
