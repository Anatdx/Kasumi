/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - real-superblock virtual inode backend (Tier 3 data plane).
 *
 * See kasumi_vnode.h.  This file implements only the per-inode data plane:
 * identity projection (getattr), and delegation of open/read/write/mmap/ioctl/
 * splice/xattr/symlink to the pinned data source.  Directory nodes and the
 * parent-directory lookup/iterate hijack that manufactures these inodes are
 * added in Tier 3.1; nothing here is wired into a live lookup yet.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/version.h>
#include <linux/xattr.h>

#include "kasumi_base.h"
#include "kasumi_runtime.h"
#include "kasumi_vnode.h"

/* i_op->getattr / *attr first argument varies across kernel versions. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#define KVN_IDMAP_ARG		struct mnt_idmap *idmap,
#define KVN_IDMAP_CALL		idmap,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#define KVN_IDMAP_ARG		struct user_namespace *userns,
#define KVN_IDMAP_CALL		userns,
#else
#define KVN_IDMAP_ARG
#define KVN_IDMAP_CALL
#endif

static const struct inode_operations kasumi_vnode_file_iops;
static const struct inode_operations kasumi_vnode_dir_iops;
static const struct file_operations kasumi_vnode_file_fops;
static const struct file_operations kasumi_vnode_dir_fops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
static const struct file_operations kasumi_vnode_file_fops_mmap_prepare;
#endif

/* dir_context actor (filldir_t) returns int pre-6.1, bool since 6.1. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define KVN_DIR_ACTOR_RET	bool
#else
#define KVN_DIR_ACTOR_RET	int
#endif

bool kasumi_vnode_is_ours(const struct inode *inode)
{
	return inode && (inode->i_op == &kasumi_vnode_file_iops ||
			 inode->i_op == &kasumi_vnode_dir_iops);
}

void kasumi_vnode_free_info(struct inode *inode)
{
	struct kasumi_vnode_info *info;

	if (!inode || !kasumi_vnode_is_ours(inode))
		return;
	info = inode->i_private;
	if (!info)
		return;
	if (info->source.dentry)
		kasumi_path_put(&info->source);
	inode->i_private = NULL;
	kfree(info);
}

/* ---- identity ---------------------------------------------------------- */

static int KASUMI_NOCFI kasumi_vnode_getattr(KVN_IDMAP_ARG const struct path *path,
					     struct kstat *stat,
					     u32 request_mask,
					     unsigned int query_flags)
{
	struct inode *vi = d_inode(path->dentry);
	struct kasumi_vnode_info *info = vi ? vi->i_private : NULL;
	int ret;

	if (!info)
		return -EIO;

	/* Live attributes come from the source; identity is projected so that
	 * stat/fstat/maps/ls all report the same (dev, ino) pair — dev is this
	 * inode's real superblock (the visible path's filesystem), ino is the
	 * scheme-A stable value captured in the rule. */
	if (!info->source.dentry || !kasumi_vfs_getattr) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		generic_fillattr(KVN_IDMAP_CALL request_mask, vi, stat);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
		generic_fillattr(KVN_IDMAP_CALL vi, stat);
#else
		generic_fillattr(vi, stat);
#endif
		stat->ino = info->v_ino;
		stat->dev = vi->i_sb->s_dev;
		return 0;
	}

	/* The VFS invokes i_op->getattr from vfs_getattr_nosec() with the internal
	 * AT_GETATTR_NOSEC bit set in query_flags.  Forwarding that to a security-
	 * level getattr trips WARN_ON_ONCE in vfs_getattr() and returns -EPERM, so
	 * request a plain stat-consistent sync of the source instead. */
	ret = kasumi_vfs_getattr_unprojected(&info->source, stat, request_mask,
					     AT_STATX_SYNC_AS_STAT);
	if (ret == 0) {
		stat->ino = info->v_ino;
		stat->dev = vi->i_sb->s_dev;
	}
	return ret;
}

static ssize_t KASUMI_NOCFI kasumi_vnode_listxattr(struct dentry *dentry,
						   char *buffer, size_t size)
{
	struct inode *vi = d_inode(dentry);
	struct kasumi_vnode_info *info = vi ? vi->i_private : NULL;
	struct inode *r_inode;

	if (!info || !info->source.dentry)
		return -EOPNOTSUPP;
	r_inode = d_inode(info->source.dentry);
	if (!r_inode || !r_inode->i_op || !r_inode->i_op->listxattr)
		return -EOPNOTSUPP;
	return r_inode->i_op->listxattr(info->source.dentry, buffer, size);
}

static const char *KASUMI_NOCFI kasumi_vnode_get_link(struct dentry *dentry,
						      struct inode *inode,
						      struct delayed_call *done)
{
	struct kasumi_vnode_info *info = inode ? inode->i_private : NULL;
	struct inode *r_inode;

	if (!info || !info->source.dentry)
		return ERR_PTR(-ECHILD);
	r_inode = d_inode(info->source.dentry);
	if (!r_inode || !r_inode->i_op || !r_inode->i_op->get_link)
		return ERR_PTR(-EINVAL);
	return r_inode->i_op->get_link(dentry ? info->source.dentry : NULL,
				       r_inode, done);
}

/* ---- data plane: delegate to the pinned source ------------------------- */

static int KASUMI_NOCFI kasumi_vnode_open(struct inode *inode, struct file *file)
{
	struct kasumi_vnode_info *info = inode->i_private;
	struct file *real_file;

	if (!info || !info->source.dentry)
		return -ENODEV;
	if (!kasumi_dentry_open)
		return -EOPNOTSUPP;
	real_file = kasumi_dentry_open(&info->source, file->f_flags,
				       file->f_cred);
	if (IS_ERR(real_file))
		return PTR_ERR(real_file);
	file->private_data = real_file;
	return 0;
}

static int kasumi_vnode_release(struct inode *inode, struct file *file)
{
	struct file *real_file = file->private_data;

	if (real_file) {
		fput(real_file);
		file->private_data = NULL;
	}
	return 0;
}

static loff_t kasumi_vnode_llseek(struct file *file, loff_t offset, int whence)
{
	struct file *real_file = file->private_data;
	loff_t ret;

	if (!real_file)
		return -EINVAL;
	real_file->f_pos = file->f_pos;
	ret = vfs_llseek(real_file, offset, whence);
	file->f_pos = real_file->f_pos;
	return ret;
}

static ssize_t KASUMI_NOCFI kasumi_vnode_read_iter(struct kiocb *iocb,
						   struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct file *real_file = file->private_data;
	ssize_t ret;

	if (!real_file || !real_file->f_op || !real_file->f_op->read_iter)
		return -EINVAL;
	iocb->ki_filp = real_file;
	ret = real_file->f_op->read_iter(iocb, to);
	iocb->ki_filp = file;
	return ret;
}

static ssize_t KASUMI_NOCFI kasumi_vnode_write_iter(struct kiocb *iocb,
						    struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct file *real_file = file->private_data;
	ssize_t ret;

	if (!real_file || !real_file->f_op || !real_file->f_op->write_iter)
		return -EINVAL;
	iocb->ki_filp = real_file;
	ret = real_file->f_op->write_iter(iocb, from);
	iocb->ki_filp = file;
	return ret;
}

static int KASUMI_NOCFI kasumi_vnode_mmap(struct file *file,
					  struct vm_area_struct *vma)
{
	/* The virtual inode shares the source's address_space (set at create),
	 * so the generic mapping path serves source pages directly. */
	return generic_file_mmap(file, vma);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
static int KASUMI_NOCFI kasumi_vnode_mmap_prepare(struct vm_area_desc *desc)
{
	return generic_file_mmap_prepare(desc);
}
#endif

static long KASUMI_NOCFI kasumi_vnode_ioctl(struct file *file, unsigned int cmd,
					    unsigned long arg)
{
	struct file *real_file = file->private_data;

	if (!real_file || !real_file->f_op || !real_file->f_op->unlocked_ioctl)
		return -ENOTTY;
	return real_file->f_op->unlocked_ioctl(real_file, cmd, arg);
}

#ifdef CONFIG_COMPAT
static long KASUMI_NOCFI kasumi_vnode_compat_ioctl(struct file *file,
						   unsigned int cmd,
						   unsigned long arg)
{
	struct file *real_file = file->private_data;

	if (!real_file || !real_file->f_op || !real_file->f_op->compat_ioctl)
		return -ENOTTY;
	return real_file->f_op->compat_ioctl(real_file, cmd, arg);
}
#endif

static ssize_t KASUMI_NOCFI kasumi_vnode_splice_read(struct file *in,
						     loff_t *ppos,
						     struct pipe_inode_info *pipe,
						     size_t len,
						     unsigned int flags)
{
	struct file *real_file = in->private_data;

	if (!real_file || !real_file->f_op || !real_file->f_op->splice_read)
		return -EINVAL;
	return real_file->f_op->splice_read(real_file, ppos, pipe, len, flags);
}

static int KASUMI_NOCFI kasumi_vnode_fsync(struct file *file, loff_t start,
					   loff_t end, int datasync)
{
	struct file *real_file = file->private_data;

	if (!real_file || !real_file->f_op || !real_file->f_op->fsync)
		return -EINVAL;
	return real_file->f_op->fsync(real_file, start, end, datasync);
}

static const struct inode_operations kasumi_vnode_file_iops = {
	.getattr = kasumi_vnode_getattr,
	.listxattr = kasumi_vnode_listxattr,
	.get_link = kasumi_vnode_get_link,
};

static const struct file_operations kasumi_vnode_file_fops = {
	.owner = THIS_MODULE,
	.open = kasumi_vnode_open,
	.release = kasumi_vnode_release,
	.llseek = kasumi_vnode_llseek,
	.read_iter = kasumi_vnode_read_iter,
	.write_iter = kasumi_vnode_write_iter,
	.mmap = kasumi_vnode_mmap,
	.unlocked_ioctl = kasumi_vnode_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = kasumi_vnode_compat_ioctl,
#endif
	.splice_read = kasumi_vnode_splice_read,
	.fsync = kasumi_vnode_fsync,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
static const struct file_operations kasumi_vnode_file_fops_mmap_prepare = {
	.owner = THIS_MODULE,
	.open = kasumi_vnode_open,
	.release = kasumi_vnode_release,
	.llseek = kasumi_vnode_llseek,
	.read_iter = kasumi_vnode_read_iter,
	.write_iter = kasumi_vnode_write_iter,
	.mmap_prepare = kasumi_vnode_mmap_prepare,
	.unlocked_ioctl = kasumi_vnode_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = kasumi_vnode_compat_ioctl,
#endif
	.splice_read = kasumi_vnode_splice_read,
	.fsync = kasumi_vnode_fsync,
};
#endif

/* ---- directory vnode: lookup/iterate delegate to the pinned source dir ---- */

static int KASUMI_NOCFI kasumi_vnode_dir_open(struct inode *inode,
					      struct file *file)
{
	struct kasumi_vnode_info *info = inode->i_private;
	struct file *real_dir;

	if (!info || !info->source.dentry)
		return -ENOTDIR;
	if (!kasumi_dentry_open)
		return -EOPNOTSUPP;
	real_dir = kasumi_dentry_open(&info->source, O_RDONLY | O_DIRECTORY,
				      file->f_cred);
	if (IS_ERR(real_dir))
		return PTR_ERR(real_dir);
	file->private_data = real_dir;
	return 0;
}

struct kasumi_vnode_dir_ctx {
	struct dir_context ctx;
	struct dir_context *orig;
	dev_t source_dev;
	unsigned long self_ino;
};

static KVN_DIR_ACTOR_RET KASUMI_NOCFI kasumi_vnode_dir_actor(
	struct dir_context *ctx, const char *name, int namlen, loff_t offset,
	u64 ino, unsigned int d_type)
{
	struct kasumi_vnode_dir_ctx *dc =
		container_of(ctx, struct kasumi_vnode_dir_ctx, ctx);
	KVN_DIR_ACTOR_RET ret;
	u64 proj;

	/* Project each child's identity so getdents d_ino matches a later stat.
	 * "." maps to this vnode's own ino; ".." is left as the source value (the
	 * real parent's identity is projected where that dir is itself virtual);
	 * everything else goes through the scheme-A projection. */
	if (namlen == 1 && name[0] == '.')
		proj = dc->self_ino;
	else if (namlen == 2 && name[0] == '.' && name[1] == '.')
		proj = ino;
	else
		proj = kasumi_vnode_source_ino(dc->source_dev, ino);

	dc->orig->pos = dc->ctx.pos;
	ret = dc->orig->actor(dc->orig, name, namlen, offset, proj, d_type);
	dc->ctx.pos = dc->orig->pos;
	return ret;
}

static int KASUMI_NOCFI kasumi_vnode_dir_iterate(struct file *file,
						 struct dir_context *ctx)
{
	struct file *real_dir = file->private_data;
	struct inode *vi = file_inode(file);
	struct kasumi_vnode_info *info = vi ? vi->i_private : NULL;
	struct kasumi_vnode_dir_ctx dc = { .ctx.actor = kasumi_vnode_dir_actor };
	struct inode *r_inode;
	int ret;

	if (!real_dir || !info || !info->source.dentry)
		return -ENOTDIR;
	r_inode = d_inode(info->source.dentry);
	dc.source_dev = (r_inode && r_inode->i_sb) ? r_inode->i_sb->s_dev : 0;
	dc.self_ino = info->v_ino;
	dc.orig = ctx;
	/* iterate_dir keeps the cursor in the source dir file's f_pos; drive it
	 * from the vnode's requested position so rewinddir/seek work, and copy the
	 * advanced position back out. */
	real_dir->f_pos = ctx->pos;
	dc.ctx.pos = ctx->pos;
	ret = iterate_dir(real_dir, &dc.ctx);
	ctx->pos = real_dir->f_pos;
	return ret;
}

static struct dentry *KASUMI_NOCFI kasumi_vnode_dir_lookup(
	struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct kasumi_vnode_info *info = dir->i_private;
	struct path child = {};
	struct inode *ci;
	struct inode *cvi;
	unsigned long civ;
	char *name;
	u8 cflags;
	int ret;

	(void)flags;
	if (!info || !info->source.dentry || !info->source.mnt ||
	    !kasumi_vfs_path_lookup)
		return ERR_PTR(-ENOENT);
	if (dentry->d_name.len > NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);
	/* A sleeping path-walk callback on a static module op table: pin the module
	 * so a cooperative unload (prepare_unload's module-refcount gate) cannot
	 * free our text mid-lookup.  The pin is released before returning, and a
	 * pin held here keeps prepare_unload from reaching READY. */
	if (!try_module_get(THIS_MODULE))
		return ERR_PTR(-ENOENT);
	name = kstrndup(dentry->d_name.name, dentry->d_name.len, GFP_KERNEL);
	if (!name) {
		module_put(THIS_MODULE);
		return ERR_PTR(-ENOMEM);
	}
	/* Resolve the child within the pinned source dir (single component; do not
	 * follow a final symlink, so lstat/readlink see the link — a symlink child
	 * becomes a KASUMI_VNODE_F_LNK vnode whose get_link forwards the source). */
	ret = kasumi_vfs_path_lookup(info->source.dentry, info->source.mnt, name,
				     0, &child);
	kfree(name);
	if (ret) {
		module_put(THIS_MODULE);
		if (ret == -ENOENT) {
			d_add(dentry, NULL);
			return NULL;
		}
		return ERR_PTR(ret);
	}
	ci = d_inode(child.dentry);
	if (!ci) {
		kasumi_path_put(&child);
		module_put(THIS_MODULE);
		d_add(dentry, NULL);
		return NULL;
	}
	cflags = S_ISDIR(ci->i_mode) ? KASUMI_VNODE_F_DIR :
		 S_ISLNK(ci->i_mode) ? KASUMI_VNODE_F_LNK : 0;
	civ = kasumi_vnode_source_ino(ci->i_sb ? ci->i_sb->s_dev : 0,
				      (u64)ci->i_ino);
	cvi = kasumi_vnode_new(dir->i_sb, &child, civ, ci->i_mode, cflags);
	kasumi_path_put(&child);
	module_put(THIS_MODULE);
	if (!cvi)
		return ERR_PTR(-ENOMEM);
	return d_splice_alias(cvi, dentry);
}

static const struct inode_operations kasumi_vnode_dir_iops = {
	.lookup = kasumi_vnode_dir_lookup,
	.getattr = kasumi_vnode_getattr,
	.listxattr = kasumi_vnode_listxattr,
};

static const struct file_operations kasumi_vnode_dir_fops = {
	.owner = THIS_MODULE,
	.open = kasumi_vnode_dir_open,
	.release = kasumi_vnode_release,
	.read = generic_read_dir,
	.iterate_shared = kasumi_vnode_dir_iterate,
	.llseek = generic_file_llseek,
};

/* Clone the source inode's SELinux context onto the vnode's in-core SID, so
 * getxattr(security.selinux) and AVC checks on the vnode report the same label
 * as the source — the last view-consistency axis for a synthetic inode.  Uses
 * the public LSM secctx round-trip (getsecctx on source -> notifysecctx on
 * vnode); no SELinux blob offsets or struct layout assumptions, so it stays
 * stable across KMIs.  Best-effort: on any failure or missing symbol the vnode
 * keeps its default label rather than failing creation. */
static void kasumi_vnode_clone_sid(struct inode *vnode, struct inode *src)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
	void *ctx = NULL;
	u32 ctxlen = 0;

	if (!vnode || !src)
		return;
	if (!kasumi_security_inode_getsecctx || !kasumi_security_inode_notifysecctx)
		return;
	if (kasumi_security_inode_getsecctx(src, &ctx, &ctxlen) || !ctx || !ctxlen)
		return;

	/* notifysecctx maps the context string back to a SID and stores it in the
	 * vnode's in-core inode_security_struct, marking it initialized so SELinux
	 * never re-derives it from the (synthetic) on-disk xattr. */
	(void)kasumi_security_inode_notifysecctx(vnode, ctx, ctxlen);

	if (kasumi_security_release_secctx)
		kasumi_security_release_secctx(ctx, ctxlen);
#else
	/* The 6.14 LSM refactor changed security_{inode_getsecctx,release_secctx}
	 * to take struct lsm_context; not ported here.  All current Kasumi KMIs
	 * are <= 6.12, so shipping builds never reach this branch. */
	(void)vnode;
	(void)src;
#endif
}

struct inode *kasumi_vnode_new(struct super_block *sb, const struct path *source,
			       unsigned long v_ino, umode_t mode, u8 flags)
{
	struct inode *inode;
	struct inode *r_inode = NULL;
	struct kasumi_vnode_info *info;

	if (!sb)
		return NULL;
	inode = new_inode(sb);
	if (!inode)
		return NULL;
	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		iput(inode);
		return NULL;
	}

	info->v_ino = v_ino;
	info->flags = flags;
	if (source && source->dentry && source->mnt) {
		info->source = *source;
		kasumi_path_get(&info->source);
		r_inode = d_inode(source->dentry);
	}

	inode->i_private = info;
	inode->i_ino = v_ino;
	inode->i_mode = r_inode ? r_inode->i_mode : mode;
	inode->i_uid = r_inode ? r_inode->i_uid : GLOBAL_ROOT_UID;
	inode->i_gid = r_inode ? r_inode->i_gid : GLOBAL_ROOT_GID;
	if (r_inode) {
		inode->i_size = i_size_read(r_inode);
		/* Share the source page cache so the generic mmap/read path serves
		 * source content without a private snapshot.  Directories don't mmap
		 * and iterate through the pinned source, so keep their own mapping
		 * and carry the source link count. */
		if (!S_ISDIR(r_inode->i_mode))
			inode->i_mapping = r_inode->i_mapping;
		else
			set_nlink(inode, r_inode->i_nlink);
	}

	if ((flags & KASUMI_VNODE_F_DIR) ||
	    (r_inode && S_ISDIR(r_inode->i_mode))) {
		inode->i_op = &kasumi_vnode_dir_iops;
		inode->i_fop = &kasumi_vnode_dir_fops;
	} else {
		inode->i_op = &kasumi_vnode_file_iops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
		inode->i_fop = (r_inode && !S_ISLNK(r_inode->i_mode) &&
				r_inode->i_fop && r_inode->i_fop->mmap_prepare) ?
				       &kasumi_vnode_file_fops_mmap_prepare :
				       &kasumi_vnode_file_fops;
#else
		inode->i_fop = &kasumi_vnode_file_fops;
#endif
	}
	/* Deliberately NOT S_PRIVATE: the vnode must stay LSM-visible so SELinux
	 * serves security.selinux from the in-core SID we clone below and applies
	 * AVC using the source's label.  S_PRIVATE would make
	 * security_inode_getsecurity() short-circuit to -EOPNOTSUPP, leaking an
	 * empty/ENODATA label through the fs xattr fallback. */
	inode->i_flags |= S_NOATIME | S_NOCMTIME | S_NOSEC;
	inode->i_opflags |= IOP_XATTR;
	if (!S_ISLNK(inode->i_mode))
		inode->i_opflags |= IOP_NOFOLLOW;

	/* Project the source's SELinux label onto the vnode (view-consistency:
	 * security.selinux must match the source).  Done last, after i_security is
	 * allocated by new_inode() and all identity is in place. */
	if (r_inode)
		kasumi_vnode_clone_sid(inode, r_inode);
	return inode;
}
