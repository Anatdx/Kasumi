/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - parent-directory lookup/iterate hijack (Tier 3.1 control surface).
 *
 * Installs a shadow inode_operations->lookup (and, later, iterate_shared) on
 * the real parent directory of a rule so that resolving the visible child path
 * yields a Kasumi virtual inode (kasumi_vnode_new) through the ordinary VFS
 * lookup chokepoint — replacing the per-syscall TSR path routes.  A shadow
 * super_operations->destroy_inode on the same superblock reclaims virtual
 * inode state on eviction.
 *
 * DEFAULT-OFF: nothing installs unless kasumi_dirhijack is explicitly enabled.
 * This is behaviour-critical dcache code; enable only with on-device validation.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_DIRHIJACK_H
#define _KASUMI_DIRHIJACK_H

#include <linux/path.h>
#include <linux/types.h>

int kasumi_dirhijack_init(void);
void kasumi_dirhijack_exit(void);

bool kasumi_dirhijack_enabled(void);

/*
 * Register a virtual child at @visible_path backed by @source, projected with
 * stable identity @v_ino.  Resolves the visible parent directory, installs the
 * lookup/superblock hijack there if needed, and indexes the child.  Sleepable
 * context only (control path).  Returns 0 or a negative errno.
 */
int kasumi_dirhijack_add(const char *visible_path, const struct path *source,
			 unsigned long v_ino, u8 flags);

/* Remove one registered child (by visible path). */
int kasumi_dirhijack_del(const char *visible_path);

/* Drop every registered child and restore all hijacked dirs/superblocks. */
void kasumi_dirhijack_clear(void);

#endif /* _KASUMI_DIRHIJACK_H */
