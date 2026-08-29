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
 * pointers, drops the affected dentries, then Tasks-RCU plus SRCU drain any
 * stale pointer fetch and in-flight callback before the pinned dentries and
 * meta objects are freed.  SRCU is required because these callbacks may sleep.
 *
 * Scope (v1): inject a virtual *file* into an existing real directory.  Nested
 * pure-virtual directory topology is not built here.
 *
 * DEFAULT-ON (kasumi_dirhijack=1): the VFS lookup layer is the production path
 * view transport, and the coverage gate keeps TSR as a live fallback for any
 * rule class it cannot yet serve.  Set kasumi_dirhijack=0 to force legacy TSR.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#include "kasumi_base.h"
#include "kasumi_dirhijack.h"
#include "kasumi_fop_override.h"
#include "kasumi_path_policy.h"
#include "kasumi_runtime.h"
#include "kasumi_sop_shadow.h"
#include "kasumi_vfs_hooks.h"
#include "kasumi_vnode.h"

static int kasumi_dirhijack_param = 1;
module_param_named(kasumi_dirhijack, kasumi_dirhijack_param, int, 0600);
MODULE_PARM_DESC(kasumi_dirhijack,
		 "Serve the path view through the VFS lookup layer, retiring the TSR path routes once every active view rule is covered (default 1); set 0 to force the legacy TSR transport");

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

struct kasumi_dh_dir {
	struct inode *dir_inode;	/* igrab'd real parent directory */
	struct hlist_head children;
	struct kasumi_dh_iop *iop_meta;
	spinlock_t lock;
	bool iterate_bound;	/* client of the shared fop_override owner */
	bool sop_client;		/* exactly one s_op client per installed dir */
	bool retiring;		/* blocks late d_op installs during CLEAR */
	struct list_head list;
};

/*
 * A per-dentry clone is required: real filesystems may already provide any of
 * the other dentry callbacks, and replacing their whole vector with one static
 * d_revalidate would silently discard those semantics.  @dentry is dget-held
 * until stale-result work or DEL/CLEAR has restored the vector, dropped the
 * dentry and drained SRCU.
 */
struct kasumi_dh_dop_meta {
	struct dentry_operations shadow_dop;
	const struct dentry_operations *orig_dop;
	struct dentry *dentry;
	struct kasumi_dh_dir *dir;
	unsigned long state;
	unsigned int orig_op_flags;
	u32 name_hash;
	u16 name_len;
	bool synthetic_negative;
	struct hlist_node node;
	struct list_head retire_node;
	char name[];
};

struct kasumi_dh_child {
	struct hlist_node node;
	struct rcu_head rcu;
	struct llist_node free_node;
	struct path source;		/* pinned; {NULL} for a hide or virtual dir */
	unsigned long v_ino;
	u32 name_hash;
	u16 name_len;
	u8 flags;
	u8 hide;			/* 1 = suppress-only: negative lookup, no
					 * vnode, not emitted in readdir (Slice 2) */
	u8 lookup_only;			/* 1 = dh serves lookup (vnode) but not
					 * readdir: the overlay filldir owns emit
					 * and dedup for this name (Slice 4a merge
					 * materialized files) */
	char *vpath;			/* F_VIRTUAL_DIR: the synthesized dir's own
					 * visible path, for rule-table child
					 * resolution (Slice 4c-v2); NULL else */
	char name[];
};

static LIST_HEAD(kasumi_dh_dirs);
#define KASUMI_DH_DOP_HASH_BITS	8
static DEFINE_HASHTABLE(kasumi_dh_dops, KASUMI_DH_DOP_HASH_BITS);
static DEFINE_MUTEX(kasumi_dh_lock);
DEFINE_STATIC_SRCU(kasumi_dh_srcu);
static bool kasumi_dh_ready;

#define KASUMI_DH_DOP_AUTO_RETIRE	0

static void kasumi_dh_reap_dops_workfn(struct work_struct *work);
static DECLARE_WORK(kasumi_dh_reap_dops_work,
			 kasumi_dh_reap_dops_workfn);
static void kasumi_dh_free_children_workfn(struct work_struct *work);
static DECLARE_WORK(kasumi_dh_free_children_work,
			 kasumi_dh_free_children_workfn);
static LLIST_HEAD(kasumi_dh_free_children);

static struct dentry *kasumi_dh_lookup(struct inode *dir, struct dentry *dentry,
				       unsigned int flags);
static int kasumi_dh_iterate(struct file *file, struct dir_context *ctx,
			     const struct file_operations *orig, void *data);
static int kasumi_dh_set_dentry_ops(struct kasumi_dh_dir *dir,
				    struct dentry *dentry,
				    bool synthetic_negative);
static void kasumi_dh_child_free(struct kasumi_dh_child *c);

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
	/* Sole path-view engine, so this is the only serve gate: an unregistered
	 * rule simply has no child here and falls through to the real entry. */
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
	char *vpath = NULL;
	bool found = false;
	bool is_hide = false;

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
		if (c->vpath)
			vpath = kstrdup(c->vpath, GFP_ATOMIC);
		v_ino = c->v_ino;
		cflags = c->flags;
		is_hide = c->hide;
		found = true;
	}
	rcu_read_unlock();

	if (found) {
		struct inode *vi;
		struct dentry *res;
		int dop_ret;

		if (is_hide) {
			/* Hidden for this observer: confirm a negative dentry so
			 * the name resolves to -ENOENT.  Never call the real
			 * lookup (it would surface the hidden inode) and never
			 * mint a vnode (a hide has no source).  Our d_op makes a
			 * non-seeing observer re-resolve to the real entry. */
			if (source.dentry)
				kasumi_path_put(&source);
			kfree(vpath);
			dop_ret = kasumi_dh_set_dentry_ops(dn, dentry, true);
			if (dop_ret) {
				/* DEL/CLEAR won the race: resolve through the original
				 * filesystem instead of publishing an ungoverned negative. */
				if (dop_ret == -ENOENT || dop_ret == -ESHUTDOWN)
					goto orig;
				return ERR_PTR(dop_ret);
			}
			d_add(dentry, NULL);
			return NULL;
		}
		if ((cflags & KASUMI_VNODE_F_VIRTUAL_DIR) && vpath)
			vi = kasumi_vnode_new_virtual(dir->i_sb, vpath, v_ino,
						      dir);
		else
			vi = kasumi_vnode_new(dir->i_sb,
					      source.dentry ? &source : NULL,
					      v_ino, mode, cflags);
		if (source.dentry)
			kasumi_path_put(&source);
		kfree(vpath);
		if (vi) {
			dop_ret = kasumi_dh_set_dentry_ops(dn, dentry, false);
			if (dop_ret) {
				iput(vi);
				if (dop_ret == -ENOENT || dop_ret == -ESHUTDOWN)
					goto orig;
				return ERR_PTR(dop_ret);
			}
			res = d_splice_alias(vi, dentry);
			if (res && !IS_ERR(res)) {
				dop_ret = kasumi_dh_set_dentry_ops(dn, res, false);
				if (dop_ret) {
					/* The alias became visible after DEL/CLEAR began.
					 * Unhash it so the next lookup reaches orig_iop. */
					d_drop(res);
					dput(res);
					return ERR_PTR(dop_ret == -ENOENT ||
						       dop_ret == -ESHUTDOWN ?
						       -EAGAIN : dop_ret);
				}
			}
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
		if (is_child && !IS_ERR(res) &&
		    kasumi_dh_set_dentry_ops(dn, res ? res : dentry, false))
			/* Do not leave an ungoverned result cached: the current
			 * non-seeing lookup may use it, but the next observer must
			 * resolve through our lookup gate again. */
			d_drop(res ? res : dentry);
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
		struct kasumi_dh_child *c;

		rcu_read_lock();
		c = kasumi_dh_find_child(p->dir, name, (u16)namelen, hash);
		/* Suppress the real entry only for names dirhijack itself emits
		 * (inject / hide).  A lookup_only child leaves readdir to the
		 * overlay filldir, which already emits and dedups the name, so it
		 * must pass through here untouched. */
		injected = c && !c->lookup_only;
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
		u32 cur;
		u8 dt;

		if (c->hide || c->lookup_only)
			continue;	/* suppress-only, or readdir owned by the
					 * overlay filldir: occupies no readdir slot */
		cur = idx++;
		if (cur < want)
			continue;
		ctx->pos = kasumi_dh_pack_pos(cur);
		dt = (c->flags & KASUMI_VNODE_F_DIR) ? DT_DIR :
		     (c->flags & KASUMI_VNODE_F_LNK) ? DT_LNK : DT_REG;
		if (!dir_emit(ctx, c->name, c->name_len, (u64)c->v_ino, dt))
			break;
		ctx->pos = kasumi_dh_pack_pos(cur + 1);
	}
	rcu_read_unlock();
}

static int KASUMI_NOCFI
kasumi_dh_iterate_inner(struct file *file, struct dir_context *ctx,
			const struct file_operations *orig,
			struct kasumi_dh_dir *dn)
{
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

static int kasumi_dh_iterate(struct file *file, struct dir_context *ctx,
			     const struct file_operations *orig, void *data)
{
	struct kasumi_dh_dir *dir = data;
	int ret;
	int idx = srcu_read_lock(&kasumi_dh_srcu);

	ret = kasumi_dh_iterate_inner(file, ctx, orig, dir);
	srcu_read_unlock(&kasumi_dh_srcu, idx);
	return ret;
}

/* ---- per-observer d_revalidate (SRCU-wrapped) -------------------------- */

#define KASUMI_DH_DOP_FLAGS	(DCACHE_OP_HASH | DCACHE_OP_COMPARE | \
				 DCACHE_OP_REVALIDATE | \
				 DCACHE_OP_WEAK_REVALIDATE | \
				 DCACHE_OP_DELETE | DCACHE_OP_PRUNE | \
				 DCACHE_OP_REAL)

static struct kasumi_dh_dop_meta *
kasumi_dh_dop_lookup_rcu(const struct dentry *dentry)
{
	struct kasumi_dh_dop_meta *m;

	hash_for_each_possible_rcu(kasumi_dh_dops, m, node,
				   (unsigned long)dentry) {
		if (m->dentry == dentry)
			return m;
	}
	return NULL;
}

static struct kasumi_dh_dop_meta *
kasumi_dh_dop_lookup_locked(const struct dentry *dentry)
{
	struct kasumi_dh_dop_meta *m;

	hash_for_each_possible(kasumi_dh_dops, m, node,
			       (unsigned long)dentry) {
		if (m->dentry == dentry)
			return m;
	}
	return NULL;
}

/*
 * A stale per-observer dentry is about to be invalidated by the VFS.  The
 * meta's dget must not keep that now-unhashed object (and a possible vnode)
 * alive until DEL/CLEAR.  d_revalidate can run in LOOKUP_RCU, so it may only
 * mark the preallocated meta and queue sleepable retirement here.
 */
static void kasumi_dh_queue_dop_retire(struct kasumi_dh_dop_meta *m)
{
	if (!test_and_set_bit(KASUMI_DH_DOP_AUTO_RETIRE, &m->state))
		schedule_work(&kasumi_dh_reap_dops_work);
}

static int KASUMI_NOCFI
kasumi_dh_revalidate_inner(struct kasumi_dh_dop_meta *dm,
			   struct inode *dir, const struct qstr *name,
			   struct dentry *dentry, unsigned int flags,
			   bool *chain_orig)
{
	struct kasumi_dh_dir *dn = dm ? READ_ONCE(dm->dir) : NULL;
	struct inode *inode;
	bool is_virtual;
	bool governed = false;
	bool child_hide = false;
	bool synthetic_negative;
	bool sees;

	*chain_orig = false;
	inode = READ_ONCE(dentry->d_inode);
	is_virtual = inode && kasumi_vnode_is_ours(inode);
	synthetic_negative = !inode && READ_ONCE(dm->synthetic_negative);
	if (!dn || READ_ONCE(dn->retiring))
		return 0;
	sees = dn && kasumi_dh_current_sees();

	/* A rename can leave the held dentry carrying our shadow outside the
	 * directory where it was installed.  It is no longer governed there. */
	if (dir && dir == dn->dir_inode) {
		struct kasumi_dh_child *c;

		rcu_read_lock();
		c = kasumi_dh_find_child(dn, name->name, (u16)name->len,
					 full_name_hash(dir, name->name,
							name->len));
		if (c) {
			governed = true;
			child_hide = c->hide;
		}
		rcu_read_unlock();
	}

	(void)flags;

	/*
	 * Decide, per current observer, whether the cached dentry still matches
	 * what a fresh lookup would yield; return 0 to force re-resolution.  Only
	 * 0/1 is returned and nothing sleeps, so this is rcu-walk safe.
	 *
	 * Not governed: no rule touches this name.  Keep a real/negative dentry;
	 * invalidate a stale virtual left by a since-deleted rule so the name
	 * drops back to its real entry.
	 *
	 * Inject rule: a seeing observer must resolve to the virtual inode, so a
	 * cached real/negative is stale; a non-seeing observer must resolve to
	 * the real entry, so a cached virtual is stale.
	 *
	 * Hide rule: a seeing observer must resolve to a negative (hidden), so a
	 * cached real or virtual dentry is stale; a non-seeing observer (e.g.
	 * root) must resolve to the real entry, so a negative cached by a seeing
	 * observer -- and any stray virtual -- is stale.  This is the §5.2
	 * cross-observer mirror: a correctly hidden negative must not leak to an
	 * observer the rule does not target, which still has to see the file.
	 */
	if (!governed) {
		if (is_virtual || synthetic_negative)
			return 0;
		*chain_orig = true;
		return 1;
	}
	if (!child_hide) {				/* inject */
		if (sees)
			return is_virtual ? 1 : 0;
		if (is_virtual)
			return 0;
		*chain_orig = true;
		return 1;
	}
	/* hide */
	if (sees) {
		if (inode)
			return 0;
		if (!synthetic_negative)
			*chain_orig = true;
		return 1;				/* valid negative */
	}
	if (inode && !is_virtual) {
		*chain_orig = true;
		return 1;				/* positive-real */
	}
	if (!inode && !synthetic_negative) {
		*chain_orig = true;
		return 1;				/* negative-real */
	}
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
static int KASUMI_NOCFI
kasumi_dh_revalidate(struct inode *dir, const struct qstr *name,
			 struct dentry *dentry, unsigned int flags)
{
	struct kasumi_dh_dop_meta *dm;
	bool chain_orig;
	int ret;
	/* srcu_read_lock() is non-sleeping and the inner never sleeps, so this is
	 * safe in rcu-walk; it also pins the meta against a concurrent clear(). */
	int idx = srcu_read_lock(&kasumi_dh_srcu);

	rcu_read_lock();
	dm = kasumi_dh_dop_lookup_rcu(dentry);
	rcu_read_unlock();
	if (!dm) {
		ret = 0;
		goto out;
	}
	ret = kasumi_dh_revalidate_inner(dm, dir, name, dentry, flags,
					 &chain_orig);
	if (ret > 0 && chain_orig && dm->orig_dop &&
	    dm->orig_dop->d_revalidate)
		ret = dm->orig_dop->d_revalidate(dir, name, dentry, flags);
	if (ret == 0)
		kasumi_dh_queue_dop_retire(dm);
out:
	srcu_read_unlock(&kasumi_dh_srcu, idx);
	return ret;
}
#else
static int KASUMI_NOCFI
kasumi_dh_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct kasumi_dh_dop_meta *dm;
	struct inode *dir = d_inode(READ_ONCE(dentry->d_parent));
	const struct qstr *name = &dentry->d_name;
	bool chain_orig;
	int ret;
	int idx = srcu_read_lock(&kasumi_dh_srcu);

	rcu_read_lock();
	dm = kasumi_dh_dop_lookup_rcu(dentry);
	rcu_read_unlock();
	if (!dm) {
		ret = 0;
		goto out;
	}
	ret = kasumi_dh_revalidate_inner(dm, dir, name, dentry, flags,
					 &chain_orig);
	if (ret > 0 && chain_orig && dm->orig_dop &&
	    dm->orig_dop->d_revalidate)
		/* Preserve the original callback's LOOKUP_RCU result verbatim,
		 * including -ECHILD when it needs a ref-walk retry. */
		ret = dm->orig_dop->d_revalidate(dentry, flags);
	if (ret == 0)
		kasumi_dh_queue_dop_retire(dm);
out:
	srcu_read_unlock(&kasumi_dh_srcu, idx);
	return ret;
}
#endif

static int kasumi_dh_set_dentry_ops(struct kasumi_dh_dir *dir,
				    struct dentry *dentry,
				    bool synthetic_negative)
{
	struct kasumi_dh_dop_meta *m, *existing;
	const struct dentry_operations *orig;
	const char *name;
	u32 hash;
	u16 len;
	bool governed;
	int ret = 0;

	if (!dir || !dir->dir_inode || !dentry ||
	    dentry->d_name.len > NAME_MAX)
		return -EINVAL;
	name = dentry->d_name.name;
	len = (u16)dentry->d_name.len;
	hash = full_name_hash(dir->dir_inode, name, len);

	m = kzalloc(sizeof(*m) + len + 1, GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	m->dentry = dget(dentry);
	m->dir = dir;
	m->name_hash = hash;
	m->name_len = len;
	m->synthetic_negative = synthetic_negative;
	INIT_LIST_HEAD(&m->retire_node);
	memcpy(m->name, name, len);
	m->name[len] = '\0';

	mutex_lock(&kasumi_dh_lock);
	if (READ_ONCE(dir->retiring)) {
		ret = -ESHUTDOWN;
		goto out_unlock;
	}
	/* DEL removes the child while holding this mutex.  Recheck here so a
	 * lookup that copied the rule just before DEL cannot publish a late d_op. */
	rcu_read_lock();
	governed = kasumi_dh_find_child(dir, m->name, len, hash) != NULL;
	rcu_read_unlock();
	if (!governed) {
		ret = -ENOENT;
		goto out_unlock;
	}

	existing = kasumi_dh_dop_lookup_locked(dentry);
	if (existing) {
		spin_lock(&dentry->d_lock);
		if (dentry->d_op != &existing->shadow_dop ||
		    existing->dir != dir || existing->name_hash != hash ||
		    existing->name_len != len ||
		    memcmp(existing->name, name, len))
			ret = -EBUSY;
		else
			WRITE_ONCE(existing->synthetic_negative,
				   synthetic_negative);
		spin_unlock(&dentry->d_lock);
		goto out_unlock;
	}

	spin_lock(&dentry->d_lock);
	orig = READ_ONCE(dentry->d_op);
	m->orig_dop = orig;
	if (orig)
		m->shadow_dop = *orig;
	m->shadow_dop.d_revalidate = kasumi_dh_revalidate;
	m->orig_op_flags = READ_ONCE(dentry->d_flags) & KASUMI_DH_DOP_FLAGS;
	hash_add_rcu(kasumi_dh_dops, &m->node, (unsigned long)dentry);
	/* Publish the initialized/hash-visible meta before pathwalk can observe
	 * DCACHE_OP_REVALIDATE and enter the shadow callback. */
	smp_wmb();
	WRITE_ONCE(dentry->d_op, &m->shadow_dop);
	WRITE_ONCE(dentry->d_flags,
		   READ_ONCE(dentry->d_flags) | DCACHE_OP_REVALIDATE);
	spin_unlock(&dentry->d_lock);
	mutex_unlock(&kasumi_dh_lock);
	return 0;

out_unlock:
	mutex_unlock(&kasumi_dh_lock);
	dput(m->dentry);
	kfree(m);
	return ret;
}

/* Caller holds kasumi_dh_lock.  The dget in @m remains live across the SRCU
 * drain; this prevents d_release/free while an old shadow callback can run. */
static void kasumi_dh_retire_dop_locked(struct kasumi_dh_dop_meta *m,
					struct list_head *retired)
{
	struct dentry *dentry = m->dentry;

	spin_lock(&dentry->d_lock);
	if (dentry->d_op == &m->shadow_dop) {
		unsigned int flags = READ_ONCE(dentry->d_flags);

		WRITE_ONCE(dentry->d_flags,
			   (flags & ~KASUMI_DH_DOP_FLAGS) |
			   m->orig_op_flags);
		/* The shadow cloned every original callback, so temporarily
		 * publishing fewer operation flags while it remains installed is
		 * safe.  Publishing orig_dop first could expose an old REVALIDATE
		 * flag beside an original vector with a NULL d_revalidate. */
		smp_wmb();
		WRITE_ONCE(dentry->d_op, m->orig_dop);
	}
	spin_unlock(&dentry->d_lock);

	hash_del_rcu(&m->node);
	list_add_tail(&m->retire_node, retired);
	/* Restore first, then unhash.  External refs can keep the dentry alive,
	 * but no subsequent cache lookup may enter Kasumi through this object. */
	d_drop(dentry);
}

/* synchronize_srcu(kasumi_dh_srcu) must have completed after retirement. */
static void kasumi_dh_free_retired_dops(struct list_head *retired)
{
	struct kasumi_dh_dop_meta *m, *tmp;

	list_for_each_entry_safe(m, tmp, retired, retire_node) {
		list_del(&m->retire_node);
		dput(m->dentry);
		kfree(m);
	}
}

/*
 * Retire every dentry that a revalidation declared stale.  The mutex
 * serializes ownership with DEL/CLEAR: whichever side removes a meta from the
 * hash owns its eventual dput/free, while the other side can no longer find
 * it.  No post-unlock step dereferences m->dir, so a concurrent last-child DEL
 * may safely detach and later free the directory metadata.
 */
static void kasumi_dh_reap_dops_workfn(struct work_struct *work)
{
	struct kasumi_dh_dop_meta *m;
	struct hlist_node *tmp;
	LIST_HEAD(retired_dops);
	int bkt;

	(void)work;
	mutex_lock(&kasumi_dh_lock);
	hash_for_each_safe(kasumi_dh_dops, bkt, tmp, m, node) {
		if (test_bit(KASUMI_DH_DOP_AUTO_RETIRE, &m->state))
			kasumi_dh_retire_dop_locked(m, &retired_dops);
	}
	mutex_unlock(&kasumi_dh_lock);

	if (list_empty(&retired_dops))
		return;

	/* Close a stale d_op load, drain callbacks that already published their
	 * meta through SRCU, then cover both the wrapper epilogue and hash readers
	 * before dropping the lifetime pin.
	 */
	kasumi_synchronize_rcu_tasks();
	synchronize_srcu(&kasumi_dh_srcu);
	kasumi_synchronize_rcu_tasks();
	synchronize_rcu();
	kasumi_dh_free_retired_dops(&retired_dops);

	/* The dput above may release the final vnode after the directory's last
	 * rule was concurrently deleted.  Give the shared s_op owner a chance to
	 * retire now that both its client and vnode counts can be zero.
	 */
	kasumi_sop_shadow_reap();
}

/* ---- virtual-inode reclaim leaf functions ------------------------------
 * Called by the unified super_operations owner (kasumi_sop_shadow) from its
 * destroy/evict/drop_inode trampolines, with @orig (the sb's original s_op)
 * already resolved under RCU.  The trampoline owns the active-counter drain, so
 * these bodies may early-return freely.  Behavior is identical to the former
 * SRCU-wrapped s_op callbacks; only the meta lookup + drain moved to the owner.
 */
void KASUMI_NOCFI kasumi_dh_reclaim_destroy_inode(struct inode *inode,
					const struct super_operations *orig)
{
	if (kasumi_vnode_is_ours(inode))
		kasumi_vnode_free_info(inode);
	if (orig && orig->destroy_inode)
		orig->destroy_inode(inode);
}

void KASUMI_NOCFI kasumi_dh_reclaim_free_inode(struct inode *inode,
				       const struct super_operations *orig)
{
	if (kasumi_vnode_is_ours(inode))
		kasumi_vnode_free_info(inode);
	if (orig && orig->free_inode)
		orig->free_inode(inode);
	else if (kasumi_free_inode_nonrcu_ptr)
		kasumi_free_inode_nonrcu_ptr(inode);
}

void KASUMI_NOCFI kasumi_dh_reclaim_evict_inode(struct inode *inode,
					const struct super_operations *orig)
{
	if (kasumi_vnode_is_ours(inode)) {
		truncate_inode_pages_final(&inode->i_data);
		clear_inode(inode);
		return;
	}
	if (orig && orig->evict_inode) {
		orig->evict_inode(inode);
	} else {
		truncate_inode_pages_final(&inode->i_data);
		clear_inode(inode);
	}
}

int KASUMI_NOCFI kasumi_dh_reclaim_drop_inode(struct inode *inode,
					const struct super_operations *orig)
{
	if (kasumi_vnode_is_ours(inode))
		return !inode->i_nlink || inode_unhashed(inode);
	if (orig && orig->drop_inode)
		return orig->drop_inode(inode);
	return !inode->i_nlink || inode_unhashed(inode);
}

/* ---- install ----------------------------------------------------------- */

/* Install (or, on a dir already carrying our lookup shadow, upgrade to add) the
 * iterate_shared shadow so readdir runs through kasumi_dh_iterate.  Only inject
 * and hide children need it; lookup_only (merge) children leave readdir to the
 * overlay filldir, so their dir is installed iop-only and never gets this shadow
 * — lookup (i_op) and iterate (i_fop) are independent inode fields, so the two
 * layers never contend when dirhijack only owns lookup. */
static int kasumi_dh_install_iterate(struct inode *inode,
				     struct kasumi_dh_dir *dir)
{
	int ret;

	if (dir->iterate_bound)
		return 0;
	ret = kasumi_fop_install(inode);
	if (ret)
		return ret;
	ret = kasumi_fop_bind_iterate_client(inode, kasumi_dh_iterate, dir);
	if (ret)
		return ret;
	dir->iterate_bound = true;
	return 0;
}

static struct kasumi_dh_dir *kasumi_dh_install_dir(struct inode *inode,
						   bool need_iterate,
						   bool sop_registered,
						   int *errp)
{
	struct kasumi_dh_iop *iop_meta = kasumi_dh_iop_of(inode);
	struct kasumi_dh_iop *im;
	struct kasumi_dh_dir *dir;
	const struct inode_operations *orig_iop;
	int ret = 0;

	if (iop_meta) {
		if (need_iterate)
			ret = kasumi_dh_install_iterate(inode, iop_meta->dir);
		if (errp)
			*errp = ret;
		if (ret)
			return NULL;
		return iop_meta->dir;
	}
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
	dir->sop_client = sop_registered;

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

	if (need_iterate) {
		ret = kasumi_dh_install_iterate(inode, dir);
		if (ret) {
			kfree(im);
			iput(dir->dir_inode);
			kfree(dir);
			if (errp)
				*errp = ret;
			return NULL;
		}
	}
	list_add_tail(&dir->list, &kasumi_dh_dirs);
	smp_store_release(&inode->i_op, &im->fake_iop);
	if (errp)
		*errp = 0;
	return dir;
}

/* Roll back a just-published, still-empty directory after child allocation
 * failed.  Publication is withdrawn under kasumi_dh_lock; the sleepable drain
 * and owner release happen afterwards in kasumi_dh_release_detached_dir(). */
static void kasumi_dh_detach_dir_locked(struct kasumi_dh_dir *dir)
{
	struct inode *inode;

	if (!dir)
		return;
	inode = dir->dir_inode;
	WRITE_ONCE(dir->retiring, true);
	if (inode && dir->iop_meta &&
	    READ_ONCE(inode->i_op) == &dir->iop_meta->fake_iop)
		smp_store_release(&inode->i_op, dir->iop_meta->orig_iop);
	if (inode && dir->iterate_bound) {
		kasumi_fop_unbind_iterate_client(inode, dir);
		dir->iterate_bound = false;
	}
	if (!list_empty(&dir->list))
		list_del_init(&dir->list);
}

static void kasumi_dh_release_detached_dir(struct kasumi_dh_dir *dir)
{
	struct kasumi_dh_child *c;
	struct hlist_node *tmp;
	struct inode *inode;
	struct super_block *sb;

	if (!dir)
		return;
	/* Cover a stale i_op fetch, callbacks already inside the dirhijack SRCU
	 * domain, and an iterate client that acquired @dir before unbind. */
	kasumi_synchronize_rcu_tasks();
	synchronize_srcu(&kasumi_dh_srcu);
	kasumi_fop_synchronize_iterate_clients();
	kasumi_synchronize_rcu_tasks();

	hlist_for_each_entry_safe(c, tmp, &dir->children, node) {
		hlist_del(&c->node);
		kasumi_dh_child_free(c);
	}
	inode = dir->dir_inode;
	sb = inode ? inode->i_sb : NULL;
	/* Keep the s_op client's s_active pin until the parent inode reference is
	 * gone.  A concurrent late-vnode reap may otherwise drop the final active
	 * superblock reference and start shutdown while iput still uses it.
	 */
	dir->dir_inode = NULL;
	if (inode)
		iput(inode);
	if (dir->sop_client && sb) {
		kasumi_sop_shadow_unregister_dh(sb);
		dir->sop_client = false;
	}
	kfree(dir->iop_meta);
	kfree(dir);
	kasumi_sop_shadow_reap();
}

/* ---- child index ------------------------------------------------------- */

static void kasumi_dh_child_free_rcu(struct rcu_head *rcu)
{
	struct kasumi_dh_child *c = container_of(rcu, struct kasumi_dh_child, rcu);

	/* RCU callback context cannot run path_put()/dput(). Move the object to a
	 * lockless queue and finish its sleepable teardown on the system workqueue.
	 */
	llist_add(&c->free_node, &kasumi_dh_free_children);
	schedule_work(&kasumi_dh_free_children_work);
}

static void kasumi_dh_child_free(struct kasumi_dh_child *c)
{
	if (c->source.dentry)
		kasumi_path_put(&c->source);
	kfree(c->vpath);
	kfree(c);
}

static void kasumi_dh_free_children_workfn(struct work_struct *work)
{
	struct llist_node *head, *node, *next;

	(void)work;
	while ((head = llist_del_all(&kasumi_dh_free_children)) != NULL) {
		llist_for_each_safe(node, next, head) {
			struct kasumi_dh_child *c = container_of(
				node, struct kasumi_dh_child, free_node);

			kasumi_dh_child_free(c);
		}
	}
}

static int kasumi_dh_dir_add_child(struct kasumi_dh_dir *dir, const char *name,
				   u16 len, const struct path *source,
				   unsigned long v_ino, u8 flags, bool hide,
				   bool lookup_only, const char *vpath)
{
	struct kasumi_dh_child *c, *old;
	u32 hash = full_name_hash(dir->dir_inode, name, len);

	c = kmalloc(sizeof(*c) + len + 1, GFP_KERNEL);
	if (!c)
		return -ENOMEM;
	c->vpath = NULL;
	if (vpath) {
		c->vpath = kstrdup(vpath, GFP_KERNEL);
		if (!c->vpath) {
			kfree(c);
			return -ENOMEM;
		}
	}
	memset(&c->source, 0, sizeof(c->source));
	if (source && source->dentry) {
		c->source = *source;
		kasumi_path_get(&c->source);
	}
	c->v_ino = v_ino;
	c->name_hash = hash;
	c->name_len = len;
	c->flags = flags;
	c->hide = hide ? 1 : 0;
	c->lookup_only = lookup_only ? 1 : 0;
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

/*
 * Slice 4c-v2: register a rule whose visible path has missing intermediate
 * directories.  Walk up @visible_path's parent chain to the deepest existing
 * real directory R, then register the first missing segment s1 at R as a
 * F_VIRTUAL_DIR child (visible path R/s1).  That synthesized directory resolves
 * everything below it — deeper virtual dirs and the leaf — dynamically from the
 * rule table (kasumi_rule_vpath_*), so only the top segment needs registering.
 * The child is shared across all rules under R/s1.
 */
static int kasumi_dh_register_vtopo(const char *visible_path)
{
	char *pparent = NULL;
	char *probe;
	char *seg = NULL;
	char *vpath = NULL;
	const char *leaf;
	const char *after;
	const char *slash;
	struct path rpath;
	struct inode *rinode;
	struct kasumi_dh_dir *dir = NULL;
	struct kasumi_dh_dir *rollback_dir = NULL;
	size_t rlen, seg_len;
	bool sop_registered = false;
	int ret;

	ret = kasumi_dh_split_parent(visible_path, &pparent, &leaf);
	if (ret)
		return ret;
	probe = kstrdup(pparent, GFP_KERNEL);
	kfree(pparent);
	if (!probe)
		return -ENOMEM;

	/* Walk up to the deepest existing real directory. */
	for (;;) {
		char *ls;

		ret = kasumi_kern_path(probe, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
				       &rpath);
		if (ret == 0)
			break;
		if (ret != -ENOENT) {
			kfree(probe);
			return ret;
		}
		ls = strrchr(probe, '/');
		if (!ls) {
			kfree(probe);
			return -ENOENT;
		}
		if (ls == probe) {
			if (probe[1]) {	/* collapse "/x" -> "/" and retry root */
				probe[1] = '\0';
				continue;
			}
			kfree(probe);	/* even "/" did not resolve */
			return -ENOENT;
		}
		*ls = '\0';
	}
	rinode = d_inode(rpath.dentry);
	if (!rinode || !S_ISDIR(rinode->i_mode)) {
		kasumi_path_put(&rpath);
		kfree(probe);
		return -ENOTDIR;
	}
	rlen = (strcmp(probe, "/") == 0) ? 0 : strlen(probe);
	kfree(probe);

	/* First segment of @visible_path after R, and the virtual dir path R/s1. */
	after = visible_path + rlen + 1;
	slash = strchr(after, '/');
	seg_len = slash ? (size_t)(slash - after) : strlen(after);
	if (!seg_len || seg_len > NAME_MAX) {
		kasumi_path_put(&rpath);
		return -EINVAL;
	}
	seg = kstrndup(after, seg_len, GFP_KERNEL);
	vpath = kstrndup(visible_path, rlen + 1 + seg_len, GFP_KERNEL);
	if (!seg || !vpath) {
		kfree(seg);
		kfree(vpath);
		kasumi_path_put(&rpath);
		return -ENOMEM;
	}

	mutex_lock(&kasumi_dh_lock);
	if (!kasumi_dh_iop_of(rinode)) {
		ret = kasumi_sop_shadow_register_dh(rpath.dentry->d_sb);
		if (ret)
			goto out;
		sop_registered = true;
	}
	dir = kasumi_dh_install_dir(rinode, true, sop_registered, &ret);
	if (!dir) {
		if (!ret)
			ret = -ENOMEM;
		if (sop_registered)
			kasumi_sop_shadow_unregister_dh(rpath.dentry->d_sb);
		goto out;
	}
	ret = kasumi_dh_dir_add_child(dir, seg, (u16)seg_len, NULL,
				      kasumi_vnode_vpath_ino(vpath),
				      KASUMI_VNODE_F_DIR | KASUMI_VNODE_F_VIRTUAL_DIR,
				      false, false, vpath);
	if (ret) {
		if (sop_registered) {
			kasumi_dh_detach_dir_locked(dir);
			rollback_dir = dir;
		}
		goto out;
	}
	{
		struct qstr qn;
		struct dentry *cached;

		qn.name = seg;
		qn.len = (u32)seg_len;
		qn.hash = full_name_hash(rpath.dentry, seg, seg_len);
		cached = d_lookup(rpath.dentry, &qn);
		if (cached) {
			d_drop(cached);
			dput(cached);
		}
	}
out:
	mutex_unlock(&kasumi_dh_lock);
	if (rollback_dir)
		kasumi_dh_release_detached_dir(rollback_dir);
	else if (ret && sop_registered && !dir)
		kasumi_sop_shadow_reap();
	kasumi_path_put(&rpath);
	pr_info("Kasumi: dirhijack_vtopo visible=%s vdir=%s ret=%d\n",
		visible_path, vpath, ret);
	kfree(seg);
	kfree(vpath);
	return ret;
}

static int kasumi_dh_register(const char *visible_path, const struct path *source,
			      unsigned long v_ino, u8 flags, bool hide,
			      bool lookup_only)
{
	char *parent = NULL;
	const char *child = NULL;
	struct path ppath;
	struct inode *pinode;
	struct kasumi_dh_dir *dir = NULL;
	struct kasumi_dh_dir *rollback_dir = NULL;
	struct dentry *cached;
	struct qstr qname;
	size_t child_len;
	bool sop_registered = false;
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
		/* Missing intermediate directory: synthesize virtual topology so a
		 * deep visible path still resolves.  Only for backed inject/dir-source
		 * rules — a hide or merge-shadow with a missing parent is meaningless. */
		if (ret == -ENOENT && !hide && !lookup_only)
			return kasumi_dh_register_vtopo(visible_path);
		return ret;
	}
	pinode = d_inode(ppath.dentry);
	if (!pinode || !S_ISDIR(pinode->i_mode)) {
		kasumi_path_put(&ppath);
		kfree(parent);
		return -ENOTDIR;
	}

	mutex_lock(&kasumi_dh_lock);
	if (!kasumi_dh_iop_of(pinode)) {
		ret = kasumi_sop_shadow_register_dh(ppath.dentry->d_sb);
		if (ret)
			goto out;
		sop_registered = true;
	}
	dir = kasumi_dh_install_dir(pinode, !lookup_only, sop_registered, &ret);
	if (!dir) {
		if (!ret)
			ret = -ENOMEM;
		if (sop_registered)
			kasumi_sop_shadow_unregister_dh(ppath.dentry->d_sb);
		goto out;
	}
	ret = kasumi_dh_dir_add_child(dir, child, (u16)child_len, source, v_ino,
				      flags, hide, lookup_only, NULL);
	if (ret) {
		if (sop_registered) {
			kasumi_dh_detach_dir_locked(dir);
			rollback_dir = dir;
		}
		goto out;
	}

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
	if (rollback_dir)
		kasumi_dh_release_detached_dir(rollback_dir);
	else if (ret && sop_registered && !dir)
		kasumi_sop_shadow_reap();
	kasumi_path_put(&ppath);
	pr_info("Kasumi: dirhijack_%s visible=%s child=%s ret=%d\n",
		hide ? "hide" : lookup_only ? "shadow" : "add",
		visible_path, child ? child : "(null)", ret);
	kfree(parent);
	return ret;
}

int kasumi_dirhijack_add(const char *visible_path, const struct path *source,
			 unsigned long v_ino, u8 flags)
{
	return kasumi_dh_register(visible_path, source, v_ino, flags, false,
				  false);
}

/*
 * Register a lookup-only child at @visible_path backed by @source: VFS lookup
 * resolves it to a Kasumi vnode (open/stat/readlink), but dirhijack does not
 * touch this dir's readdir — the overlay filldir injection owns emit and dedup
 * for the name.  Used to sink a merge-materialized file's lookup axis onto the
 * VFS layer (Slice 4a) without double-injecting the entry into getdents.
 * Sleepable context only.
 */
int kasumi_dirhijack_add_shadow(const char *visible_path,
				const struct path *source,
				unsigned long v_ino, u8 flags)
{
	return kasumi_dh_register(visible_path, source, v_ino, flags, false,
				  true);
}

/*
 * Register a suppress-only child at @visible_path: VFS lookup returns a negative
 * dentry (-ENOENT) and readdir omits the name for view-target observers, while
 * non-target observers keep resolving the real entry.  Sinks a hide rule off
 * the TSR path routes.  Sleepable context only.  Returns 0 or a negative errno.
 */
int kasumi_dirhijack_hide(const char *visible_path)
{
	return kasumi_dh_register(visible_path, NULL, 0, 0, true, false);
}

int kasumi_dirhijack_del(const char *visible_path)
{
	char *parent = NULL;
	const char *child = NULL;
	struct path ppath;
	struct kasumi_dh_iop *m;
	struct kasumi_dh_child *c = NULL;
	struct kasumi_dh_dir *dead_dir = NULL;
	struct kasumi_dh_dop_meta *dm;
	struct hlist_node *htmp;
	LIST_HEAD(retired_dops);
	size_t child_len;
	bool had_dops;
	int bkt;
	int ret;

	if (!kasumi_kern_path)
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
		/* A deep-virtual rule's parent does not exist as a real dir; it
		 * was registered via the vtopo path, so ENOENT is not an error. */
		return ret == -ENOENT ? 0 : ret;
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
		if (c && hlist_empty(&m->dir->children))
			dead_dir = m->dir;
		spin_unlock(&m->dir->lock);
		if (c)
			call_rcu(&c->rcu, kasumi_dh_child_free_rcu);

		/* A d_splice_alias path can leave more than one held dentry for the
		 * same governed name.  Retire every matching shadow, not only the
		 * object currently returned by d_lookup(). */
			hash_for_each_safe(kasumi_dh_dops, bkt, htmp, dm, node) {
			if (dm->dir == m->dir && dm->name_len == child_len &&
			    dm->name_hash == full_name_hash(m->dir->dir_inode,
							 child, child_len) &&
			    !memcmp(dm->name, child, child_len))
				kasumi_dh_retire_dop_locked(dm, &retired_dops);
		}
		if (dead_dir)
			kasumi_dh_detach_dir_locked(dead_dir);
	}
	if (c) {
		/* Drop any dentry cached under this name so the next resolution
		 * runs the now child-free real lookup.  Essential for a hide: the
		 * cached negative that made the name -ENOENT for a view observer
		 * must be dropped, else the name stays "hidden" after its rule is
		 * gone (revalidate treats an ungoverned negative as a genuine
		 * absence and keeps it). */
		struct qstr qname;
		struct dentry *cached;

		qname.name = child;
		qname.len = (u32)child_len;
		qname.hash = full_name_hash(ppath.dentry, child, child_len);
		cached = d_lookup(ppath.dentry, &qname);
		if (cached) {
			d_drop(cached);
			dput(cached);
		}
	}
	mutex_unlock(&kasumi_dh_lock);
	had_dops = !list_empty(&retired_dops);
	if (had_dops) {
		/* Close the d_op-load-to-callback-entry window first, then drain
		 * callbacks that published their dm through the SRCU wrapper. */
		kasumi_synchronize_rcu_tasks();
		synchronize_srcu(&kasumi_dh_srcu);
		/* Cover the wrapper epilogue after srcu_read_unlock(). */
		kasumi_synchronize_rcu_tasks();
		synchronize_rcu();
		kasumi_dh_free_retired_dops(&retired_dops);
	}
	if (dead_dir) {
		/* An auto-retire worker may already own a matching dm which DEL no
		 * longer found in the hash. Drain its dget before release_detached_dir()
		 * drops the final s_op client/s_active reference for this directory.
		 */
		flush_work(&kasumi_dh_reap_dops_work);
	}
	if (c || had_dops)
		shrink_dcache_sb(ppath.dentry->d_sb);
	if (dead_dir)
		kasumi_dh_release_detached_dir(dead_dir);
	kasumi_path_put(&ppath);
	kfree(parent);
	return c ? 0 : -ENOENT;
}

static void kasumi_dh_shrink_dead_sbs(struct list_head *dead_dirs)
{
	struct kasumi_dh_dir *dir;

	list_for_each_entry(dir, dead_dirs, list) {
		struct kasumi_dh_dir *prior;
		struct super_block *sb;
		bool seen = false;

		if (!dir->dir_inode)
			continue;
		sb = dir->dir_inode->i_sb;
		list_for_each_entry(prior, dead_dirs, list) {
			if (prior == dir)
				break;
			if (prior->dir_inode && prior->dir_inode->i_sb == sb) {
				seen = true;
				break;
			}
		}
		if (!seen)
			shrink_dcache_sb(sb);
	}
}

void kasumi_dirhijack_clear(void)
{
	struct kasumi_dh_dir *dir, *dtmp;
	struct kasumi_dh_dop_meta *dm;
	struct hlist_node *htmp;
	LIST_HEAD(dead_dirs);
	LIST_HEAD(retired_dops);
	int bkt;

	mutex_lock(&kasumi_dh_lock);

	/* Phase 1: stop late installs, restore the dir i_op vector and withdraw the
	 * shared f_op iterate client so no NEW lookup/iterate callback acquires dir
	 * metadata.  The s_op client is released only after these callbacks drain. */
	list_for_each_entry_safe(dir, dtmp, &kasumi_dh_dirs, list) {
		struct inode *inode = dir->dir_inode;

		WRITE_ONCE(dir->retiring, true);
		if (inode && dir->iop_meta)
			smp_store_release(&inode->i_op, dir->iop_meta->orig_iop);
		if (inode && dir->iterate_bound) {
			kasumi_fop_unbind_iterate_client(inode, dir);
			dir->iterate_bound = false;
		}
		list_move(&dir->list, &dead_dirs);
	}
	/* Restore each real filesystem d_op and its exact operation flags while the
	 * dget-held dentry is still alive, then unhash it. */
	hash_for_each_safe(kasumi_dh_dops, bkt, htmp, dm, node)
		kasumi_dh_retire_dop_locked(dm, &retired_dops);
	mutex_unlock(&kasumi_dh_lock);

	/* Phase 2: first close the d_op-load-to-callback-entry window, then drain
	 * every lookup/iterate/revalidate that entered before the restores above.
	 * Retain every dentry/meta dget through both windows so an old callback
	 * cannot race d_release or metadata free. */
	if (!list_empty(&dead_dirs) || !list_empty(&retired_dops))
		kasumi_synchronize_rcu_tasks();
	synchronize_srcu(&kasumi_dh_srcu);
	kasumi_fop_synchronize_iterate_clients();
	if (!list_empty(&dead_dirs) || !list_empty(&retired_dops))
		kasumi_synchronize_rcu_tasks();
	if (!list_empty(&retired_dops))
		synchronize_rcu();
	kasumi_dh_free_retired_dops(&retired_dops);
	/* No shadow callback can enqueue retirement after the drains above.  Wait
	 * for a worker that won ownership of an auto-retired meta before freeing
	 * its directory or allowing module text to go away.
	 */
	flush_work(&kasumi_dh_reap_dops_work);

	/* Drop other cached aliases/negatives after explicit d_op restoration.  Do
	 * this once per affected superblock; shrink alone is not the safety proof. */
	kasumi_dh_shrink_dead_sbs(&dead_dirs);

	/* Phase 3: no callback can reference the metas now — free them. */
	list_for_each_entry_safe(dir, dtmp, &dead_dirs, list) {
		struct kasumi_dh_child *c;
		struct hlist_node *ctmp;
		struct inode *inode = dir->dir_inode;
		struct super_block *sb = inode ? inode->i_sb : NULL;

		hlist_for_each_entry_safe(c, ctmp, &dir->children, node) {
			hlist_del(&c->node);
			kasumi_dh_child_free(c);
		}
		list_del(&dir->list);
		/* dh_clients owns the s_active pin that makes this final parent
		 * iput safe; publish that the dir no longer owns the inode before
		 * allowing the shared s_op meta to reap.
		 */
		dir->dir_inode = NULL;
		if (inode)
			iput(inode);
		if (dir->sop_client && sb) {
			kasumi_sop_shadow_unregister_dh(sb);
			dir->sop_client = false;
		}
		kfree(dir->iop_meta);
		kfree(dir);
	}
	kasumi_sop_shadow_reap();

	/* Cover every per-child RCU bridge, then drain the sleepable path_put work
	 * before PREPARE/exit can release the module lifecycle pin.
	 */
	rcu_barrier();
	flush_work(&kasumi_dh_free_children_work);
}

int kasumi_dirhijack_init(void)
{
	hash_init(kasumi_dh_dops);
	WRITE_ONCE(kasumi_dh_ready, true);
	pr_info("Kasumi: dirhijack initialized (param=%d)\n",
		READ_ONCE(kasumi_dirhijack_param));
	return 0;
}

void kasumi_dirhijack_stop_new(void)
{
	WRITE_ONCE(kasumi_dh_ready, false);
}

void kasumi_dirhijack_exit(void)
{
	kasumi_dirhijack_stop_new();
	kasumi_dirhijack_clear();
	pr_info("Kasumi: dirhijack exited\n");
}
