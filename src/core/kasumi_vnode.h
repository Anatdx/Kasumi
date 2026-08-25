/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - real-superblock virtual inode backend (Tier 3 data plane).
 *
 * A virtual node is a real inode allocated on the *visible path's own*
 * superblock (new_inode(dir->i_sb)), so dentry and inode share a superblock
 * (no cross-sb pairing) and stat naturally reports the containing filesystem's
 * device.  Identity (ino) is projected from Kasumi's captured rule via the
 * scheme-A vnode identity, so stat/fstat/maps/ls all agree.  Real I/O, mmap,
 * xattr and symlink resolution are delegated to the pinned data source, which
 * keeps SELinux AVC decisions and security.selinux tied to the source without
 * writing an inode SID.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_VNODE_H
#define _KASUMI_VNODE_H

#include <linux/fs.h>
#include <linux/path.h>
#include <linux/types.h>

#define KASUMI_VNODE_F_DIR		(1u << 0)  /* node is a directory */
#define KASUMI_VNODE_F_VIRTUAL_DIR	(1u << 1)  /* synthesized dir, no source */
#define KASUMI_VNODE_F_LNK		(1u << 2)  /* node is a symlink */

/*
 * Per virtual inode state, stored in inode->i_private.  @source is a pinned
 * reference to the data backing this visible node; it is {NULL,NULL} for a
 * pure virtual directory that only exists to host injected children.
 */
struct kasumi_vnode_info {
	struct path source;
	unsigned long v_ino;
	u8 flags;
	/* Visible path of a KASUMI_VNODE_F_VIRTUAL_DIR (source-less) node, used to
	 * resolve its children against the rule table.  NULL for backed nodes. */
	char *visible_path;
};

/*
 * Allocate a virtual inode on @sb (the visible parent's superblock) backed by
 * @source (may be NULL for a virtual directory).  @v_ino is the stable visible
 * inode number (kasumi_vnode_source_ino()|bit63) and @flags carry the node
 * kind.  Returns NULL on failure; on success the inode owns a pinned copy of
 * @source and must be released through the ordinary iput()/eviction path with
 * the superblock destroy_inode shim calling kasumi_vnode_free_info().
 */
struct inode *kasumi_vnode_new(struct super_block *sb, const struct path *source,
			       unsigned long v_ino, umode_t mode, u8 flags);

/*
 * Allocate a pure-virtual directory inode (KASUMI_VNODE_F_VIRTUAL_DIR) on @sb
 * with no data source.  @visible_path is the node's own visible path; its
 * lookup/iterate resolve children against the rule table (kasumi_rule_vpath_*).
 * Owns a copy of @visible_path, released through kasumi_vnode_free_info.
 */
struct inode *kasumi_vnode_new_virtual(struct super_block *sb,
				       const char *visible_path,
				       unsigned long v_ino);

/* True if @inode is a Kasumi virtual node (its i_op is one of our tables). */
bool kasumi_vnode_is_ours(const struct inode *inode);

/*
 * Release the i_private state of a virtual inode.  Called from the hijacked
 * superblock destroy_inode path (Tier 3.1); safe on non-virtual inodes.
 */
void kasumi_vnode_free_info(struct inode *inode);

#endif /* _KASUMI_VNODE_H */
