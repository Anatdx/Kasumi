/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - parent-directory lookup/iterate hijack engine (Tier 3.1).
 *
 * Installs, on a rule's real visible parent directory:
 *   - inode_operations->lookup shadow: resolving the visible child yields a
 *     Kasumi virtual inode (kasumi_vnode_new) through the ordinary VFS lookup
 *     chokepoint, replacing the per-syscall TSR path routes;
 *   - file_operations->iterate_shared shadow: injects the virtual children into
 *     readdir (and suppresses a real entry of the same name to avoid dupes);
 *   - a d_revalidate on manufactured dentries: gates visibility per observer so
 *     a cached virtual dentry is not served to a UID the rule does not target;
 *   - super_operations shadow (destroy/evict/drop): reclaims virtual inodes
 *     without letting the real filesystem's evict run on a manufactured inode
 *     (free_inode is left original so the fs inode container is still freed).
 *
 * Teardown safety: the shadow op vectors carry no module-owner pin, and the
 * hijacked callbacks sleep (allocation, ->lookup, path_put).  All callbacks run
 * inside an SRCU read section; kasumi_dirhijack_clear() restores the original op
 * pointers, then synchronize_srcu() drains any in-flight callback before the
 * meta objects are freed.  This is why SRCU (sleepable) is used, not RCU.
 *
 * Scope (v1): inject a virtual *file* into an existing real directory.  Nested
 * pure-virtual directory topology is not built here.
 *
 * DEFAULT-OFF (kasumi_dirhijack=0).  Behaviour-critical dcache code; enable
 * only with on-device validation.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/string.h>
#include <linux/version.h>

#include "kasumi_base.h"
#include "kasumi_dirhijack.h"
#include "kasumi_path_policy.h"
#include "kasumi_runtime.h"
#include "kasumi_vnode.h"

static int kasumi_dirhijack_param;
module_param_named(kasumi_dirhijack, kasumi_dirhijack_param, int, 0600);
MODULE_PARM_DESC(kasumi_dirhijack,
		 "DBG/WIP: enable Tier 3 parent-dir lookup/iterate hijack (default 0)");

static int kasumi_dirhijack_force;
module_param_named(kasumi_dirhijack_force, kasumi_dirhijack_force, int, 0600);
MODULE_PARM_DESC(kasumi_dirhijack_force,
		 "DBG: bypass view-target gating so any observer sees virtual nodes (test only)");

/*
 * readdir cookie tag.  Virtual children are emitted after the real entries at
 * positions carrying a signature in the high bits.  NOTE: like nomount, this
 * leaves a getdents d_off distinguishable from native cookies — the one
 * residual view-consistency tell of injecting into a real directory; there is
 * no collision-free way to mint native-looking cookies in the host fs's space.
 */
#define KASUMI_DH_POS_SIG	0x6B6DULL	/* "km" */
static inline bool kasumi_dh_virtual_pos(loff_t pos)
{
	return (pos & 0xFFFFFFFF00000000ULL) == (KASUMI_DH_POS_SIG << 48);
}
static inline loff_t kasumi_dh_pack_pos(u32 id)
{
	return (loff_t)((KASUMI_DH_POS_SIG << 48) | id);
}
static inline u32 kasumi_dh_unpack_pos(loff_t pos)
{
	return (u32)(pos & 0xFFFFFFFFULL);
}

/* dir_context actor (filldir_t) returns int pre-6.1, bool since 6.1. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define KASUMI_DH_ACTOR_RET	bool
#define KASUMI_DH_ACTOR_OK	true
#else
#define KASUMI_DH_ACTOR_RET	int
#define KASUMI_DH_ACTOR_OK	0
#endif

struct kasumi_dh_iop {
	struct inode_operations fake_iop;	/* must stay first */
	const struct inode_operations *orig_iop;
	struct kasumi_dh_dir *dir;
};

struct kasumi_dh_fop {
	struct file_operations fake_fop;	/* must stay first */
	const struct file_operations *orig_fop;
	struct kasumi_dh_dir *dir;
};

struct kasumi_dh_dir {
	struct inode *dir_inode;	/* igrab'd real parent directory */
	struct hlist_head children;
	struct kasumi_dh_iop *iop_meta;
	struct kasumi_dh_fop *fop_meta;	/* may be NULL */
	spinlock_t lock;
	struct list_head list;
};

struct kasumi_dh_sop {
	struct super_operations fake_sop;	/* must stay first */
	const struct super_operations *orig_sop;
	struct super_block *sb;
	struct list_head list;
};

struct kasumi_dh_child {
	struct hlist_node node;
	struct rcu_head rcu;
	struct path source;		/* pinned; {NULL} for a virtual dir */
	unsigned long v_ino;
	u32 name_hash;
	u16 name_len;
	u8 flags;
	char name[];
};

static LIST_HEAD(kasumi_dh_dirs);
static LIST_HEAD(kasumi_dh_sbs);
static DEFINE_MUTEX(kasumi_dh_lock);
DEFINE_STATIC_SRCU(kasumi_dh_srcu);
static bool kasumi_dh_ready;

static struct dentry *kasumi_dh_lookup(struct inode *dir, struct dentry *dentry,
				       unsigned int flags);
static int kasumi_dh_iterate(struct file *file, struct dir_context *ctx);
static void kasumi_dh_destroy_inode(struct inode *inode);
static void kasumi_dh_evict_inode(struct inode *inode);
static int kasumi_dh_drop_inode(struct inode *inode);
static void kasumi_dh_set_dentry_ops(struct dentry *dentry);

bool kasumi_dirhijack_enabled(void)
{
	return READ_ONCE(kasumi_dh_ready) && READ_ONCE(kasumi_dirhijack_param);
}

/* ---- meta accessors ---------------------------------------------------- */

static struct kasumi_dh_iop *kasumi_dh_iop_of(const struct inode *inode)
{
	const struct inode_operations *iop;

	if (!inode)
		return NULL;
	iop = smp_load_acquire(&inode->i_op);
	if (iop && iop->lookup == kasumi_dh_lookup)
		return container_of(iop, struct kasumi_dh_iop, fake_iop);
	return NULL;
}

static struct kasumi_dh_fop *kasumi_dh_fop_of(const struct inode *inode)
{
	const struct file_operations *fop;

	if (!inode)
		return NULL;
	fop = smp_load_acquire(&inode->i_fop);
	if (fop && fop->iterate_shared == kasumi_dh_iterate)
		return container_of(fop, struct kasumi_dh_fop, fake_fop);
	return NULL;
}

static struct kasumi_dh_sop *kasumi_dh_sop_of(const struct super_block *sb)
{
	const struct super_operations *sop;

	if (!sb)
		return NULL;
	sop = smp_load_acquire(&sb->s_op);
	if (sop && sop->destroy_inode == kasumi_dh_destroy_inode)
		return container_of(sop, struct kasumi_dh_sop, fake_sop);
	return NULL;
}

static struct kasumi_dh_child *kasumi_dh_find_child(struct kasumi_dh_dir *dir,
						    const char *name, u16 len,
						    u32 hash)
{
	struct kasumi_dh_child *c;

	hlist_for_each_entry_rcu(c, &dir->children, node) {
		if (c->name_hash == hash && c->name_len == len &&
		    !memcmp(c->name, name, len))
			return c;
	}
	return NULL;
}

/* True if the current task should see this dir's injected children. */
static bool kasumi_dh_current_sees(void)
{
	if (!kasumi_dirhijack_enabled())
		return false;
	if (READ_ONCE(kasumi_dirhijack_force))
		return true;
	return kasumi_policy_current_is_view_target();
}

/* ---- hijacked lookup (SRCU-wrapped) ------------------------------------ */

static struct dentry *KASUMI_NOCFI kasumi_dh_lookup_inner(struct inode *dir,
							  struct dentry *dentry,
							  unsigned int flags)
{
	struct kasumi_dh_iop *m = kasumi_dh_iop_of(dir);
	struct kasumi_dh_dir *dn = m ? READ_ONCE(m->dir) : NULL;
	struct kasumi_dh_child *c;
	struct path source = {};
	unsigned long v_ino = 0;
	umode_t mode = S_IFREG | 0644;
	u8 cflags = 0;
	bool found = false;

	if (!m || !dn || !kasumi_dh_current_sees())
		goto orig;

	rcu_read_lock();
	c = kasumi_dh_find_child(dn, dentry->d_name.name,
				 (u16)dentry->d_name.len,
				 full_name_hash(dir, dentry->d_name.name,
						dentry->d_name.len));
	if (c) {
		if (c->source.dentry) {
			source = c->source;
			kasumi_path_get(&source);
		}
		v_ino = c->v_ino;
		cflags = c->flags;
		found = true;
	}
	rcu_read_unlock();

	if (found) {
		struct inode *vi = kasumi_vnode_new(dir->i_sb,
						    source.dentry ? &source : NULL,
						    v_ino, mode, cflags);
		struct dentry *res;

		if (source.dentry)
			kasumi_path_put(&source);
		if (vi) {
			kasumi_dh_set_dentry_ops(dentry);
			res = d_splice_alias(vi, dentry);
			if (!IS_ERR(res))
				kasumi_dh_set_dentry_ops(res ? res : dentry);
			return res;
		}
	}

orig:
	/* Not served to this observer.  If a rule nonetheless registers this
	 * name (for a different observer), govern the resulting dentry with our
	 * d_revalidate: otherwise a negative/real dentry cached here by a
	 * non-seeing observer (e.g. root probing first) would be inherited by a
	 * seeing observer without re-resolution, hiding the virtual file from the
	 * very view that must see it — and, in the reverse order, leaking it to a
	 * view that must not.  Attaching our d_op makes both orderings re-resolve
	 * through the shadow lookup per current observer. */
	{
		struct dentry *res = NULL;
		bool is_child = false;

		if (m && dn) {
			rcu_read_lock();
			is_child = kasumi_dh_find_child(
					   dn, dentry->d_name.name,
					   (u16)dentry->d_name.len,
					   full_name_hash(dir, dentry->d_name.name,
							  dentry->d_name.len)) != NULL;
			rcu_read_unlock();
		}
		if (m && m->orig_iop && m->orig_iop->lookup)
			res = m->orig_iop->lookup(dir, dentry, flags);
		else
			d_add(dentry, NULL);
		if (is_child && !IS_ERR(res))
			kasumi_dh_set_dentry_ops(res ? res : dentry);
		return res;
	}
}

static struct dentry *kasumi_dh_lookup(struct inode *dir, struct dentry *dentry,
				       unsigned int flags)
{
	struct dentry *res;
	int idx = srcu_read_lock(&kasumi_dh_srcu);

	res = kasumi_dh_lookup_inner(dir, dentry, flags);
	srcu_read_unlock(&kasumi_dh_srcu, idx);
	return res;
}

/* ---- hijacked iterate (readdir injection, SRCU-wrapped) ---------------- */

struct kasumi_dh_proxy {
	struct dir_context ctx;
	struct dir_context *orig;
	struct kasumi_dh_dir *dir;
	int emitted;
};

static KASUMI_DH_ACTOR_RET KASUMI_NOCFI kasumi_dh_proxy_actor(
	struct dir_context *ctx, const char *name, int namelen,
	loff_t offset, u64 ino, unsigned int d_type)
{
	struct kasumi_dh_proxy *p =
		container_of(ctx, struct kasumi_dh_proxy, ctx);
	KASUMI_DH_ACTOR_RET ret;
	bool injected = false;

	if (p->dir) {
		u32 hash = full_name_hash(p->dir->dir_inode, name, namelen);

		rcu_read_lock();
		injected = kasumi_dh_find_child(p->dir, name, (u16)namelen,
						hash) != NULL;
		rcu_read_unlock();
	}
	if (injected) {
		p->ctx.pos = offset;
		return KASUMI_DH_ACTOR_OK;
	}
	p->orig->pos = p->ctx.pos;
	ret = p->orig->actor(p->orig, name, namelen, offset, ino, d_type);
	p->ctx.pos = p->orig->pos;
	p->emitted++;
	return ret;
}

static void kasumi_dh_emit_children(struct dir_context *ctx,
				    struct kasumi_dh_dir *dir)
{
	struct kasumi_dh_child *c;
	u32 want = kasumi_dh_unpack_pos(ctx->pos);
	u32 idx = 0;

	if (!kasumi_dh_virtual_pos(ctx->pos))
		ctx->pos = kasumi_dh_pack_pos(0);
	rcu_read_lock();
	hlist_for_each_entry_rcu(c, &dir->children, node) {
		u32 cur = idx++;
		u8 dt;

		if (cur < want)
			continue;
		ctx->pos = kasumi_dh_pack_pos(cur);
		dt = (c->flags & KASUMI_VNODE_F_DIR) ? DT_DIR : DT_REG;
		if (!dir_emit(ctx, c->name, c->name_len, (u64)c->v_ino, dt))
			break;
		ctx->pos = kasumi_dh_pack_pos(cur + 1);
	}
	rcu_read_unlock();
}

static int KASUMI_NOCFI kasumi_dh_iterate_inner(struct file *file,
						struct dir_context *ctx)
{
	struct kasumi_dh_fop *m = kasumi_dh_fop_of(file_inode(file));
	struct kasumi_dh_dir *dn = m ? READ_ONCE(m->dir) : NULL;
	const struct file_operations *orig = m ? m->orig_fop : NULL;
	struct kasumi_dh_proxy proxy = { .ctx.actor = kasumi_dh_proxy_actor };
	int ret;

	if (!orig || !orig->iterate_shared)
		return -ENOTDIR;
	if (!dn || !kasumi_dh_current_sees())
		return orig->iterate_shared(file, ctx);

	if (kasumi_dh_virtual_pos(ctx->pos)) {
		kasumi_dh_emit_children(ctx, dn);
		return 0;
	}

	proxy.ctx.pos = ctx->pos;
	proxy.orig = ctx;
	proxy.dir = dn;
	ret = orig->iterate_shared(file, &proxy.ctx);
	ctx->pos = proxy.ctx.pos;
	if (ret < 0)
		return ret;

	ctx->pos = kasumi_dh_pack_pos(0);
	kasumi_dh_emit_children(ctx, dn);
	return 0;
}

static int kasumi_dh_iterate(struct file *file, struct dir_context *ctx)
{
	int ret;
	int idx = srcu_read_lock(&kasumi_dh_srcu);

	ret = kasumi_dh_iterate_inner(file, ctx);
	srcu_read_unlock(&kasumi_dh_srcu, idx);
	return ret;
}

/* ---- per-observer d_revalidate (SRCU-wrapped) -------------------------- */

static int KASUMI_NOCFI kasumi_dh_revalidate_inner(struct inode *dir,
						   const struct qstr *name,
						   struct dentry *dentry,
						   unsigned int flags)
{
	struct kasumi_dh_iop *m;
	struct kasumi_dh_dir *dn;
	struct inode *inode;
	bool is_virtual;
	bool rule_visible = false;

	if (!dir)
		return 1;
	m = kasumi_dh_iop_of(dir);
	dn = m ? READ_ONCE(m->dir) : NULL;
	inode = READ_ONCE(dentry->d_inode);
	is_virtual = inode && kasumi_vnode_is_ours(inode);

	if (dn && kasumi_dh_current_sees()) {
		rcu_read_lock();
		rule_visible = kasumi_dh_find_child(dn, name->name,
						    (u16)name->len,
						    full_name_hash(dir, name->name,
								   name->len)) != NULL;
		rcu_read_unlock();
	}

	/* A virtual dentry is valid iff the current observer's rule still makes
	 * it visible.  A cached real/negative dentry is valid unless a rule now
	 * injects this name for the current observer, in which case it must be
	 * re-resolved so the shadow lookup runs and yields the virtual inode.
	 * Correctly-hidden negatives are kept as-is (no d_drop / -ECHILD churn),
	 * so a hidden name stays indistinguishable from a genuinely absent one
	 * and the decision is rcu-walk safe (only 0/1, never sleeps). */
	(void)flags;
	if (is_virtual)
		return rule_visible ? 1 : 0;
	return rule_visible ? 0 : 1;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
static int kasumi_dh_revalidate(struct inode *dir, const struct qstr *name,
				struct dentry *dentry, unsigned int flags)
{
	int ret;
	/* srcu_read_lock() is non-sleeping and the inner never sleeps, so this is
	 * safe in rcu-walk; it also pins the meta against a concurrent clear(). */
	int idx = srcu_read_lock(&kasumi_dh_srcu);

	ret = kasumi_dh_revalidate_inner(dir, name, dentry, flags);
	srcu_read_unlock(&kasumi_dh_srcu, idx);
	return ret;
}
#else
static int kasumi_dh_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct inode *dir = d_inode(READ_ONCE(dentry->d_parent));
	const struct qstr *name = &dentry->d_name;
	int ret;
	int idx = srcu_read_lock(&kasumi_dh_srcu);

	ret = kasumi_dh_revalidate_inner(dir, name, dentry, flags);
	srcu_read_unlock(&kasumi_dh_srcu, idx);
	return ret;
}
#endif

static const struct dentry_operations kasumi_dh_dentry_ops = {
	.d_revalidate = kasumi_dh_revalidate,
};

static void kasumi_dh_set_dentry_ops(struct dentry *dentry)
{
	if (!dentry)
		return;
	spin_lock(&dentry->d_lock);
	if (dentry->d_op != &kasumi_dh_dentry_ops) {
		dentry->d_op = &kasumi_dh_dentry_ops;
		dentry->d_flags &= ~(DCACHE_OP_HASH | DCACHE_OP_COMPARE |
				     DCACHE_OP_WEAK_REVALIDATE | DCACHE_OP_DELETE |
				     DCACHE_OP_PRUNE | DCACHE_OP_REAL);
		dentry->d_flags |= DCACHE_OP_REVALIDATE;
	}
	spin_unlock(&dentry->d_lock);
}

/* ---- hijacked super_operations (SRCU-wrapped) -------------------------- */

static void KASUMI_NOCFI kasumi_dh_destroy_inode(struct inode *inode)
{
	struct kasumi_dh_sop *m;
	int idx = srcu_read_lock(&kasumi_dh_srcu);

	m = kasumi_dh_sop_of(inode->i_sb);
	if (kasumi_vnode_is_ours(inode))
		kasumi_vnode_free_info(inode);
	if (m && m->orig_sop && m->orig_sop->destroy_inode)
		m->orig_sop->destroy_inode(inode);
	srcu_read_unlock(&kasumi_dh_srcu, idx);
}

static void KASUMI_NOCFI kasumi_dh_evict_inode(struct inode *inode)
{
	struct kasumi_dh_sop *m;
	int idx;

	if (kasumi_vnode_is_ours(inode)) {
		truncate_inode_pages_final(&inode->i_data);
		clear_inode(inode);
		return;
	}
	idx = srcu_read_lock(&kasumi_dh_srcu);
	m = kasumi_dh_sop_of(inode->i_sb);
	if (m && m->orig_sop && m->orig_sop->evict_inode) {
		m->orig_sop->evict_inode(inode);
	} else {
		truncate_inode_pages_final(&inode->i_data);
		clear_inode(inode);
	}
	srcu_read_unlock(&kasumi_dh_srcu, idx);
}

static int KASUMI_NOCFI kasumi_dh_drop_inode(struct inode *inode)
{
	struct kasumi_dh_sop *m;
	int ret;
	int idx;

	if (kasumi_vnode_is_ours(inode))
		return !inode->i_nlink || inode_unhashed(inode);
	idx = srcu_read_lock(&kasumi_dh_srcu);
	m = kasumi_dh_sop_of(inode->i_sb);
	if (m && m->orig_sop && m->orig_sop->drop_inode)
		ret = m->orig_sop->drop_inode(inode);
	else
		ret = !inode->i_nlink || inode_unhashed(inode);
	srcu_read_unlock(&kasumi_dh_srcu, idx);
	return ret;
}

/* ---- install ----------------------------------------------------------- */

static int kasumi_dh_install_sb(struct super_block *sb)
{
	struct kasumi_dh_sop *m;

	if (!sb || !sb->s_op)
		return -EINVAL;
	if (kasumi_dh_sop_of(sb))
		return 0;
	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	m->fake_sop = *sb->s_op;
	m->orig_sop = sb->s_op;
	m->sb = sb;
	m->fake_sop.destroy_inode = kasumi_dh_destroy_inode;
	m->fake_sop.evict_inode = kasumi_dh_evict_inode;
	m->fake_sop.drop_inode = kasumi_dh_drop_inode;
	list_add_tail(&m->list, &kasumi_dh_sbs);
	smp_store_release(&sb->s_op, &m->fake_sop);
	return 0;
}

static struct kasumi_dh_dir *kasumi_dh_install_dir(struct inode *inode)
{
	struct kasumi_dh_iop *iop_meta = kasumi_dh_iop_of(inode);
	struct kasumi_dh_fop *fop_meta = NULL;
	struct kasumi_dh_iop *im;
	struct kasumi_dh_dir *dir;
	const struct inode_operations *orig_iop;
	const struct file_operations *orig_fop;

	if (iop_meta)
		return iop_meta->dir;
	orig_iop = inode->i_op;
	if (!orig_iop || !orig_iop->lookup)
		return NULL;

	dir = kzalloc(sizeof(*dir), GFP_KERNEL);
	if (!dir)
		return NULL;
	dir->dir_inode = igrab(inode);
	if (!dir->dir_inode) {
		kfree(dir);
		return NULL;
	}
	INIT_HLIST_HEAD(&dir->children);
	spin_lock_init(&dir->lock);
	INIT_LIST_HEAD(&dir->list);

	im = kzalloc(sizeof(*im), GFP_KERNEL);
	if (!im) {
		iput(dir->dir_inode);
		kfree(dir);
		return NULL;
	}
	im->fake_iop = *orig_iop;
	im->orig_iop = orig_iop;
	im->dir = dir;
	im->fake_iop.lookup = kasumi_dh_lookup;
	dir->iop_meta = im;

	orig_fop = READ_ONCE(inode->i_fop);
	if (orig_fop && orig_fop->iterate_shared) {
		fop_meta = kzalloc(sizeof(*fop_meta), GFP_KERNEL);
		if (fop_meta) {
			fop_meta->fake_fop = *orig_fop;
			fop_meta->orig_fop = orig_fop;
			fop_meta->dir = dir;
			fop_meta->fake_fop.iterate_shared = kasumi_dh_iterate;
			dir->fop_meta = fop_meta;
		}
	}

	list_add_tail(&dir->list, &kasumi_dh_dirs);
	if (fop_meta)
		smp_store_release(&inode->i_fop, &fop_meta->fake_fop);
	smp_store_release(&inode->i_op, &im->fake_iop);
	return dir;
}

/* ---- child index ------------------------------------------------------- */

static void kasumi_dh_child_free_rcu(struct rcu_head *rcu)
{
	struct kasumi_dh_child *c = container_of(rcu, struct kasumi_dh_child, rcu);

	if (c->source.dentry)
		kasumi_path_put(&c->source);
	kfree(c);
}

static void kasumi_dh_child_free(struct kasumi_dh_child *c)
{
	if (c->source.dentry)
		kasumi_path_put(&c->source);
	kfree(c);
}

static int kasumi_dh_dir_add_child(struct kasumi_dh_dir *dir, const char *name,
				   u16 len, const struct path *source,
				   unsigned long v_ino, u8 flags)
{
	struct kasumi_dh_child *c, *old;
	u32 hash = full_name_hash(dir->dir_inode, name, len);

	c = kmalloc(sizeof(*c) + len + 1, GFP_KERNEL);
	if (!c)
		return -ENOMEM;
	memset(&c->source, 0, sizeof(c->source));
	if (source && source->dentry) {
		c->source = *source;
		kasumi_path_get(&c->source);
	}
	c->v_ino = v_ino;
	c->name_hash = hash;
	c->name_len = len;
	c->flags = flags;
	memcpy(c->name, name, len);
	c->name[len] = '\0';

	spin_lock(&dir->lock);
	old = kasumi_dh_find_child(dir, name, len, hash);
	if (old)
		hlist_del_rcu(&old->node);
	hlist_add_head_rcu(&c->node, &dir->children);
	spin_unlock(&dir->lock);
	if (old)
		call_rcu(&old->rcu, kasumi_dh_child_free_rcu);
	return 0;
}

/* ---- public control surface -------------------------------------------- */

static int kasumi_dh_split_parent(const char *visible_path, char **parent_out,
				  const char **child_out)
{
	char *parent;
	char *slash;

	if (!visible_path || visible_path[0] != '/')
		return -EINVAL;
	parent = kstrdup(visible_path, GFP_KERNEL);
	if (!parent)
		return -ENOMEM;
	slash = strrchr(parent, '/');
	if (!slash || !slash[1]) {
		kfree(parent);
		return -EINVAL;
	}
	*child_out = visible_path + (slash - parent) + 1;
	if (slash == parent)
		parent[1] = '\0';
	else
		*slash = '\0';
	*parent_out = parent;
	return 0;
}

int kasumi_dirhijack_add(const char *visible_path, const struct path *source,
			 unsigned long v_ino, u8 flags)
{
	char *parent = NULL;
	const char *child = NULL;
	struct path ppath;
	struct inode *pinode;
	struct kasumi_dh_dir *dir;
	struct dentry *cached;
	struct qstr qname;
	size_t child_len;
	int ret;

	if (!READ_ONCE(kasumi_dh_ready) || !kasumi_kern_path)
		return -EOPNOTSUPP;
	ret = kasumi_dh_split_parent(visible_path, &parent, &child);
	if (ret)
		return ret;
	child_len = strlen(child);
	if (!child_len || child_len > NAME_MAX) {
		kfree(parent);
		return -EINVAL;
	}
	ret = kasumi_kern_path(parent, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &ppath);
	if (ret) {
		kfree(parent);
		return ret;
	}
	pinode = d_inode(ppath.dentry);
	if (!pinode || !S_ISDIR(pinode->i_mode)) {
		kasumi_path_put(&ppath);
		kfree(parent);
		return -ENOTDIR;
	}

	mutex_lock(&kasumi_dh_lock);
	ret = kasumi_dh_install_sb(ppath.dentry->d_sb);
	if (ret)
		goto out;
	dir = kasumi_dh_install_dir(pinode);
	if (!dir) {
		ret = -ENOMEM;
		goto out;
	}
	ret = kasumi_dh_dir_add_child(dir, child, (u16)child_len, source, v_ino,
				      flags);
	if (ret)
		goto out;

	qname.name = child;
	qname.len = (u32)child_len;
	qname.hash = full_name_hash(ppath.dentry, child, child_len);
	cached = d_lookup(ppath.dentry, &qname);
	if (cached) {
		d_drop(cached);
		dput(cached);
	}
out:
	mutex_unlock(&kasumi_dh_lock);
	kasumi_path_put(&ppath);
	pr_info("Kasumi: dirhijack_add visible=%s child=%s ret=%d\n",
		visible_path, child ? child : "(null)", ret);
	kfree(parent);
	return ret;
}

int kasumi_dirhijack_del(const char *visible_path)
{
	char *parent = NULL;
	const char *child = NULL;
	struct path ppath;
	struct kasumi_dh_iop *m;
	struct kasumi_dh_child *c = NULL;
	size_t child_len;
	int ret;

	if (!kasumi_kern_path)
		return -EOPNOTSUPP;
	ret = kasumi_dh_split_parent(visible_path, &parent, &child);
	if (ret)
		return ret;
	child_len = strlen(child);
	ret = kasumi_kern_path(parent, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &ppath);
	if (ret) {
		kfree(parent);
		return ret;
	}

	mutex_lock(&kasumi_dh_lock);
	m = kasumi_dh_iop_of(d_inode(ppath.dentry));
	if (m && m->dir) {
		spin_lock(&m->dir->lock);
		c = kasumi_dh_find_child(m->dir, child, (u16)child_len,
					 full_name_hash(m->dir->dir_inode, child,
							child_len));
		if (c)
			hlist_del_rcu(&c->node);
		spin_unlock(&m->dir->lock);
		if (c)
			call_rcu(&c->rcu, kasumi_dh_child_free_rcu);
	}
	mutex_unlock(&kasumi_dh_lock);
	kasumi_path_put(&ppath);
	kfree(parent);
	return c ? 0 : -ENOENT;
}

void kasumi_dirhijack_clear(void)
{
	struct kasumi_dh_dir *dir, *dtmp;
	struct kasumi_dh_sop *sop, *stmp;
	LIST_HEAD(dead_dirs);
	LIST_HEAD(dead_sbs);

	mutex_lock(&kasumi_dh_lock);

	/* Phase 1: restore the original op vectors so no NEW callback enters our
	 * code, and move the metas to private lists.  Evict virtual inodes while
	 * our super_operations is still installed. */
	list_for_each_entry_safe(dir, dtmp, &kasumi_dh_dirs, list) {
		struct inode *inode = dir->dir_inode;

		if (inode && dir->fop_meta)
			smp_store_release(&inode->i_fop, dir->fop_meta->orig_fop);
		if (inode && dir->iop_meta)
			smp_store_release(&inode->i_op, dir->iop_meta->orig_iop);
		list_move(&dir->list, &dead_dirs);
	}
	list_for_each_entry_safe(sop, stmp, &kasumi_dh_sbs, list) {
		if (sop->sb) {
			shrink_dcache_sb(sop->sb);
			smp_store_release(&sop->sb->s_op, sop->orig_sop);
		}
		list_move(&sop->list, &dead_sbs);
	}
	mutex_unlock(&kasumi_dh_lock);

	/* Phase 2: drain any callback that entered before the restores above. */
	synchronize_srcu(&kasumi_dh_srcu);

	/* Phase 3: no callback can reference the metas now — free them. */
	list_for_each_entry_safe(dir, dtmp, &dead_dirs, list) {
		struct kasumi_dh_child *c;
		struct hlist_node *ctmp;

		hlist_for_each_entry_safe(c, ctmp, &dir->children, node) {
			hlist_del(&c->node);
			kasumi_dh_child_free(c);
		}
		list_del(&dir->list);
		if (dir->dir_inode)
			iput(dir->dir_inode);
		kfree(dir->iop_meta);
		kfree(dir->fop_meta);
		kfree(dir);
	}
	list_for_each_entry_safe(sop, stmp, &dead_sbs, list) {
		list_del(&sop->list);
		kfree(sop);
	}

	/* Cover any per-child call_rcu() still pending from kasumi_dirhijack_del(). */
	rcu_barrier();
}

int kasumi_dirhijack_init(void)
{
	WRITE_ONCE(kasumi_dh_ready, true);
	pr_info("Kasumi: dirhijack initialized (param=%d)\n",
		READ_ONCE(kasumi_dirhijack_param));
	return 0;
}

void kasumi_dirhijack_exit(void)
{
	WRITE_ONCE(kasumi_dh_ready, false);
	kasumi_dirhijack_clear();
	pr_info("Kasumi: dirhijack exited\n");
}
