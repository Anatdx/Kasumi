/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/* Kasumi - explicitly retired per-superblock super_operations owner. */
#ifndef _KASUMI_SOP_SHADOW_H
#define _KASUMI_SOP_SHADOW_H

#include <linux/fs.h>

int kasumi_sop_shadow_init(void);
void kasumi_sop_shadow_stop_new(void);
void kasumi_sop_shadow_exit(void);

unsigned int kasumi_sop_shadow_active(void);
unsigned int kasumi_sop_shadow_installed(void);
bool kasumi_sop_shadow_quiesced(void);
bool kasumi_sop_shadow_available(void);

/* One client is registered for each installed dirhijack parent directory. */
int kasumi_sop_shadow_register_dh(struct super_block *sb);
void kasumi_sop_shadow_unregister_dh(struct super_block *sb);

/* Actual new_inode() objects, distinct from rule/source capture counts. */
bool kasumi_sop_vnode_get(struct super_block *sb);
void kasumi_sop_vnode_put(struct super_block *sb);

/* Restore and release every owner with no client and no live vnode. */
void kasumi_sop_shadow_reap(void);

#endif /* _KASUMI_SOP_SHADOW_H */
