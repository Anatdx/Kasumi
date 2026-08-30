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
 * DEFAULT-ON (kasumi_dirhijack=1): the production path-view transport.  The
 * coverage gate keeps TSR as a live fallback for any class not yet served, and
 * kasumi_dirhijack=0 forces the legacy TSR routes.
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

struct inode;
struct super_operations;

int kasumi_dirhijack_init(void);
void kasumi_dirhijack_stop_new(void);
void kasumi_dirhijack_exit(void);

bool kasumi_dirhijack_enabled(void);

/*
 * Virtual-inode reclaim leaf functions, invoked by the unified super_operations
 * owner (kasumi_sop_shadow) from its destroy/evict/drop_inode trampolines with
 * @orig already resolved under RCU.  The trampoline owns the active-counter
 * drain, so these bodies may early-return freely.  Kept here so the load-bearing
 * kasumi_vnode reclaim branches stay co-located with the rest of dirhijack.
 */
void kasumi_dh_reclaim_destroy_inode(struct inode *inode,
				     const struct super_operations *orig);
void kasumi_dh_reclaim_free_inode(struct inode *inode,
				  const struct super_operations *orig);
void kasumi_dh_reclaim_evict_inode(struct inode *inode,
				   const struct super_operations *orig);
int kasumi_dh_reclaim_drop_inode(struct inode *inode,
				 const struct super_operations *orig);

/*
 * Register a virtual child at @visible_path backed by @source, projected with
 * stable identity @v_ino.  Resolves the visible parent directory, installs the
 * lookup/superblock hijack there if needed, and indexes the child.  Sleepable
 * context only (control path).  Returns 0 or a negative errno.
 */
int kasumi_dirhijack_add(const char *visible_path, const struct path *source,
			 unsigned long v_ino, u8 flags);

/*
 * Register a lookup-only child at @visible_path backed by @source: VFS lookup
 * resolves it to a Kasumi vnode, but dirhijack does not shadow this dir's
 * readdir — the overlay filldir injection keeps emitting and deduping the name.
 * Sinks a merge-materialized file's lookup axis onto the VFS layer (Slice 4a).
 * Sleepable context only.  Returns 0 or a negative errno.
 */
int kasumi_dirhijack_add_shadow(const char *visible_path,
				const struct path *source,
				unsigned long v_ino, u8 flags);

/* Remove one registered child (by visible path). */
int kasumi_dirhijack_del(const char *visible_path);

/*
 * Register a suppress-only ("hide") child at @visible_path: VFS lookup returns a
 * negative dentry and readdir omits the name for view-target observers, so the
 * real entry disappears for the view without a per-syscall TSR route.  Non-target
 * observers keep resolving the real entry.  Sleepable context only.
 */
int kasumi_dirhijack_hide(const char *visible_path);

/*
 * Restore every inode/file/dentry operation shadow, invalidate affected
 * dentries, drain callbacks, and release all dirhijack metadata.  May sleep.
 */
void kasumi_dirhijack_clear(void);

#endif /* _KASUMI_DIRHIJACK_H */
