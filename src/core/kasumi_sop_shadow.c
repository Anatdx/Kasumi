/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - explicitly retired per-superblock super_operations owner.
 *
 * A shadowed superblock carries an extra s_active reference. A userspace
 * umount may therefore detach the mount, but generic_shutdown_super() cannot
 * poison busy Kasumi inodes while a rule or vnode still needs our reclaim
 * callbacks. CLEAR/PREPARE withdraw every client, wait for vnode reclaim,
 * restore s_op outside callback context, drain stale dispatches, and only then
 * release the superblock and module references.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include "kasumi_sop_shadow.h"
#include "kasumi_dirhijack.h"
#include "kasumi_runtime.h"

#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#define KASUMI_SOP_HASH_BITS 8

struct kasumi_sop_meta {
	struct super_block *sb;
	const struct super_operations *orig_sop;
	struct super_operations shadow_sop;
	atomic_t vnode_live;
	atomic_t callback_active;
	unsigned int dh_clients;
	bool accepting_vnodes;
	bool restoring;
	bool sb_active_held;
	bool module_pin_held;
	struct hlist_node node;
};

static DEFINE_HASHTABLE(kasumi_sop_table, KASUMI_SOP_HASH_BITS);
/* Leaf lock: never allocate, wait, take s_umount, or deactivate under it. */
static DEFINE_SPINLOCK(kasumi_sop_lock);
/* Serializes install and the sleepable restore/drain/release sequence. */
static DEFINE_MUTEX(kasumi_sop_manage_lock);
static atomic_t kasumi_sop_active = ATOMIC_INIT(0);
static atomic_t kasumi_sop_live = ATOMIC_INIT(0);
static atomic_t kasumi_sop_vnodes = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(kasumi_sop_wait);
static bool kasumi_sop_ready;
static bool kasumi_sop_reap_work_enabled;

static void kasumi_sop_reap_workfn(struct work_struct *work);
static DECLARE_WORK(kasumi_sop_reap_work, kasumi_sop_reap_workfn);

static struct kasumi_sop_meta *kasumi_sop_lookup_rcu(struct super_block *sb)
{
	struct kasumi_sop_meta *m;

	hash_for_each_possible_rcu(kasumi_sop_table, m, node,
				   (unsigned long)sb) {
		if (m->sb == sb)
			return m;
	}
	return NULL;
}

static struct kasumi_sop_meta *kasumi_sop_lookup_locked(struct super_block *sb)
{
	struct kasumi_sop_meta *m;

	hash_for_each_possible(kasumi_sop_table, m, node,
				 (unsigned long)sb) {
		if (m->sb == sb)
			return m;
	}
	return NULL;
}

/* The hash entry stays published until after pointer restore + double
 * Tasks-RCU, so every stale callback can still resolve its original vector. */
static struct kasumi_sop_meta *
kasumi_sop_callback_enter(struct super_block *sb,
			  const struct super_operations **orig)
{
	struct kasumi_sop_meta *m;

	*orig = NULL;
	atomic_inc(&kasumi_sop_active);
	rcu_read_lock();
	m = kasumi_sop_lookup_rcu(sb);
	if (m) {
		atomic_inc(&m->callback_active);
		*orig = m->orig_sop;
	}
	rcu_read_unlock();
	return m;
}

static void kasumi_sop_callback_exit(struct kasumi_sop_meta *m)
{
	if (m && atomic_dec_and_test(&m->callback_active))
		wake_up_all(&kasumi_sop_wait);
	if (atomic_dec_and_test(&kasumi_sop_active))
		wake_up_all(&kasumi_sop_wait);
}

KASUMI_NOCFI static void kasumi_sop_destroy_inode(struct inode *inode)
{
	struct kasumi_sop_meta *m;
	const struct super_operations *orig;

	m = kasumi_sop_callback_enter(inode ? inode->i_sb : NULL, &orig);
	kasumi_dh_reclaim_destroy_inode(inode, orig);
	kasumi_sop_callback_exit(m);
}

KASUMI_NOCFI static void kasumi_sop_evict_inode(struct inode *inode)
{
	struct kasumi_sop_meta *m;
	const struct super_operations *orig;

	m = kasumi_sop_callback_enter(inode ? inode->i_sb : NULL, &orig);
	kasumi_dh_reclaim_evict_inode(inode, orig);
	kasumi_sop_callback_exit(m);
}

KASUMI_NOCFI static int kasumi_sop_drop_inode(struct inode *inode)
{
	struct kasumi_sop_meta *m;
	const struct super_operations *orig;
	int ret;

	m = kasumi_sop_callback_enter(inode ? inode->i_sb : NULL, &orig);
	ret = kasumi_dh_reclaim_drop_inode(inode, orig);
	kasumi_sop_callback_exit(m);
	return ret;
}

static void kasumi_sop_drop_install_refs(struct super_block *sb,
					 bool active_held,
					 bool module_held)
{
	/* A control fd plus the bootstrap lifecycle pin remains held while this
	 * helper runs, so module_put() cannot unmap the function returning here. */
	if (active_held)
		deactivate_super(sb);
	if (module_held)
		module_put(THIS_MODULE);
}

int kasumi_sop_shadow_register_dh(struct super_block *sb)
{
	struct kasumi_sop_meta *m, *spare;
	const struct super_operations *orig;
	bool active_held = false;
	bool module_held = false;
	int ret = 0;

	if (!sb || !READ_ONCE(sb->s_op))
		return -EINVAL;
	if (!READ_ONCE(kasumi_sop_ready))
		return -ESHUTDOWN;

	spare = kzalloc(sizeof(*spare), GFP_KERNEL);
	if (!spare)
		return -ENOMEM;

	mutex_lock(&kasumi_sop_manage_lock);
	spin_lock(&kasumi_sop_lock);
	m = kasumi_sop_lookup_locked(sb);
	if (m) {
		if (!READ_ONCE(kasumi_sop_ready) || m->restoring ||
		    READ_ONCE(sb->s_op) != &m->shadow_sop) {
			ret = -ESHUTDOWN;
		} else {
			m->dh_clients++;
			m->accepting_vnodes = true;
		}
		spin_unlock(&kasumi_sop_lock);
		goto out_unlock;
	}
	spin_unlock(&kasumi_sop_lock);

	/* s_umount excludes a concurrent shutdown transition while the extra
	 * s_active reference is acquired. The caller still owns a live path. */
	down_read(&sb->s_umount);
	if (!READ_ONCE(kasumi_sop_ready) ||
	    !(READ_ONCE(sb->s_flags) & SB_BORN) ||
	    !atomic_inc_not_zero(&sb->s_active)) {
		ret = -ESHUTDOWN;
		goto out_s_umount;
	}
	active_held = true;
	if (!try_module_get(THIS_MODULE)) {
		ret = -ESHUTDOWN;
		goto out_s_umount;
	}
	module_held = true;

	orig = READ_ONCE(sb->s_op);
	if (!orig) {
		ret = -EINVAL;
		goto out_s_umount;
	}
	spare->sb = sb;
	spare->orig_sop = orig;
	spare->shadow_sop = *orig;
	atomic_set(&spare->vnode_live, 0);
	atomic_set(&spare->callback_active, 0);
	spare->dh_clients = 1;
	spare->accepting_vnodes = true;
	spare->sb_active_held = true;
	spare->module_pin_held = true;

	if (!orig->destroy_inode && !orig->free_inode &&
	    !kasumi_free_inode_nonrcu_ptr) {
		ret = -EOPNOTSUPP;
		goto out_s_umount;
	}
	/* Since Linux 5.10, VFS invokes ->destroy_inode synchronously and, when
	 * ->free_inode is also present, records that callback in the inode before
	 * queueing its own RCU callback.  Always use the synchronous stage for the
	 * sleepable vnode cleanup, while leaving a filesystem's original deferred
	 * container deallocator untouched.  For the generic-inode case, supplying
	 * free_inode_nonrcu makes VFS queue the same generic free it would have used
	 * without our newly-added destroy callback.  No module-owned callback is
	 * ever stored in inode->free_inode.
	 */
	spare->shadow_sop.destroy_inode = kasumi_sop_destroy_inode;
	if (!orig->destroy_inode && !orig->free_inode)
		spare->shadow_sop.free_inode = kasumi_free_inode_nonrcu_ptr;
	spare->shadow_sop.evict_inode = kasumi_sop_evict_inode;
	spare->shadow_sop.drop_inode = kasumi_sop_drop_inode;

	spin_lock(&kasumi_sop_lock);
	if (!READ_ONCE(kasumi_sop_ready) || READ_ONCE(sb->s_op) != orig ||
	    kasumi_sop_lookup_locked(sb)) {
		ret = -EAGAIN;
	} else {
		hash_add_rcu(kasumi_sop_table, &spare->node,
			     (unsigned long)sb);
		atomic_inc(&kasumi_sop_live);
		smp_wmb();
		smp_store_release(&sb->s_op, &spare->shadow_sop);
		spare = NULL;
		active_held = false;
		module_held = false;
	}
	spin_unlock(&kasumi_sop_lock);

out_s_umount:
	up_read(&sb->s_umount);
	if (ret)
		kasumi_sop_drop_install_refs(sb, active_held, module_held);
out_unlock:
	mutex_unlock(&kasumi_sop_manage_lock);
	kfree(spare);
	if (!ret)
		kasumi_log("sop_shadow: client registered on sb %p\n", sb);
	return ret;
}

void kasumi_sop_shadow_unregister_dh(struct super_block *sb)
{
	struct kasumi_sop_meta *m;

	if (!sb)
		return;
	spin_lock(&kasumi_sop_lock);
	m = kasumi_sop_lookup_locked(sb);
	if (m) {
		if (WARN_ON_ONCE(!m->dh_clients)) {
			m->accepting_vnodes = false;
		} else if (!--m->dh_clients) {
			m->accepting_vnodes = false;
		}
	}
	spin_unlock(&kasumi_sop_lock);
	wake_up_all(&kasumi_sop_wait);
}

bool kasumi_sop_vnode_get(struct super_block *sb)
{
	struct kasumi_sop_meta *m;
	bool got = false;

	if (!sb)
		return false;
	spin_lock(&kasumi_sop_lock);
	m = kasumi_sop_lookup_locked(sb);
	if (m && m->accepting_vnodes && !m->restoring) {
		atomic_inc(&m->vnode_live);
		atomic_inc(&kasumi_sop_vnodes);
		got = true;
	}
	spin_unlock(&kasumi_sop_lock);
	return got;
}

void kasumi_sop_vnode_put(struct super_block *sb)
{
	struct kasumi_sop_meta *m;

	if (!sb)
		return;
	spin_lock(&kasumi_sop_lock);
	m = kasumi_sop_lookup_locked(sb);
	if (WARN_ON_ONCE(!m || atomic_read(&m->vnode_live) <= 0)) {
		spin_unlock(&kasumi_sop_lock);
		return;
	}
	if (atomic_dec_and_test(&m->vnode_live) && !m->dh_clients &&
	    !m->restoring && kasumi_sop_reap_work_enabled) {
		/* schedule_work() is atomic-safe; queueing under this lock pairs
		 * with exit's disable-before-cancel sequence.
		 */
		schedule_work(&kasumi_sop_reap_work);
	}
	atomic_dec(&kasumi_sop_vnodes);
	spin_unlock(&kasumi_sop_lock);
	/* vnode_put() runs from the synchronous destroy_inode trampoline.  Reaping
	 * takes s_umount, waits for callbacks, synchronizes RCU and may deactivate
	 * the superblock, so only request it here and do the work in process
	 * context.
	 */
	wake_up_all(&kasumi_sop_wait);
}

static struct kasumi_sop_meta *kasumi_sop_take_reap_candidate(void)
{
	struct kasumi_sop_meta *m;
	int bkt;

	spin_lock(&kasumi_sop_lock);
	hash_for_each(kasumi_sop_table, bkt, m, node) {
		if (!m->restoring && !m->dh_clients &&
		    !atomic_read(&m->vnode_live)) {
			m->accepting_vnodes = false;
			m->restoring = true;
			spin_unlock(&kasumi_sop_lock);
			return m;
		}
	}
	spin_unlock(&kasumi_sop_lock);
	return NULL;
}

static void kasumi_sop_reap_meta(struct kasumi_sop_meta *m)
{
	struct super_block *sb = m->sb;
	bool active_held;
	bool module_held;

	/* The retained s_active reference means shutdown cannot be in progress.
	 * Take s_umount read-side anyway so the publication contract is explicit. */
	down_read(&sb->s_umount);
	spin_lock(&kasumi_sop_lock);
	if (READ_ONCE(sb->s_op) == &m->shadow_sop)
		smp_store_release(&sb->s_op, m->orig_sop);
	else
		WARN_ON_ONCE(READ_ONCE(sb->s_op) != m->orig_sop);
	spin_unlock(&kasumi_sop_lock);
	up_read(&sb->s_umount);

	/* A caller may have loaded shadow_sop just before the restore. */
	kasumi_synchronize_rcu_tasks();
	wait_event(kasumi_sop_wait, !atomic_read(&m->callback_active));
	/* Cover callback epilogues after their active count reached zero. */
	kasumi_synchronize_rcu_tasks();

	spin_lock(&kasumi_sop_lock);
	WARN_ON_ONCE(m->dh_clients || atomic_read(&m->vnode_live));
	hash_del_rcu(&m->node);
	atomic_dec(&kasumi_sop_live);
	active_held = m->sb_active_held;
	module_held = m->module_pin_held;
	m->sb_active_held = false;
	m->module_pin_held = false;
	spin_unlock(&kasumi_sop_lock);
	synchronize_rcu();

	kasumi_log("sop_shadow: retired sb %p\n", sb);
	kfree(m);
	/* May run the original generic_shutdown_super() if userspace detached the
	 * last mount while Kasumi held the extra active reference. */
	kasumi_sop_drop_install_refs(sb, active_held, module_held);
	wake_up_all(&kasumi_sop_wait);
}

void kasumi_sop_shadow_reap(void)
{
	struct kasumi_sop_meta *m;

	mutex_lock(&kasumi_sop_manage_lock);
	while ((m = kasumi_sop_take_reap_candidate()) != NULL)
		kasumi_sop_reap_meta(m);
	mutex_unlock(&kasumi_sop_manage_lock);
}

static void kasumi_sop_reap_workfn(struct work_struct *work)
{
	(void)work;
	kasumi_sop_shadow_reap();
}

int kasumi_sop_shadow_init(void)
{
	hash_init(kasumi_sop_table);
	atomic_set(&kasumi_sop_active, 0);
	atomic_set(&kasumi_sop_live, 0);
	atomic_set(&kasumi_sop_vnodes, 0);
	WRITE_ONCE(kasumi_sop_reap_work_enabled, true);
	WRITE_ONCE(kasumi_sop_ready, true);
	pr_info("Kasumi: sop_shadow initialized\n");
	return 0;
}

bool kasumi_sop_shadow_available(void)
{
	return READ_ONCE(kasumi_sop_ready);
}

unsigned int kasumi_sop_shadow_installed(void)
{
	return (unsigned int)atomic_read(&kasumi_sop_live);
}

unsigned int kasumi_sop_shadow_active(void)
{
	return (unsigned int)atomic_read(&kasumi_sop_active);
}

void kasumi_sop_shadow_stop_new(void)
{
	struct kasumi_sop_meta *m;
	int bkt;

	WRITE_ONCE(kasumi_sop_ready, false);
	spin_lock(&kasumi_sop_lock);
	hash_for_each(kasumi_sop_table, bkt, m, node)
		m->accepting_vnodes = false;
	spin_unlock(&kasumi_sop_lock);
	kasumi_sop_shadow_reap();
	/* Pair with a late final vnode_put() that may have queued the sleepable
	 * reap while stop_new() was scanning the table.
	 */
	flush_work(&kasumi_sop_reap_work);
}

bool kasumi_sop_shadow_quiesced(void)
{
	if (READ_ONCE(kasumi_sop_ready))
		return false;
	kasumi_sop_shadow_reap();
	flush_work(&kasumi_sop_reap_work);
	/* The worker may have waited behind the synchronous pass.  Scan once more
	 * so the result reflects every candidate visible before the flush.
	 */
	kasumi_sop_shadow_reap();
	return !atomic_read(&kasumi_sop_live) &&
	       !atomic_read(&kasumi_sop_active) &&
	       !atomic_read(&kasumi_sop_vnodes);
}

void kasumi_sop_shadow_exit(void)
{
	kasumi_sop_shadow_stop_new();
	/* No live owner may remain at module exit (each one pins THIS_MODULE).
	 * Disable new requests under the same lock used by vnode_put(), then drain
	 * the reusable static work item before module text can disappear.
	 */
	spin_lock(&kasumi_sop_lock);
	WRITE_ONCE(kasumi_sop_reap_work_enabled, false);
	spin_unlock(&kasumi_sop_lock);
	cancel_work_sync(&kasumi_sop_reap_work);
	kasumi_sop_shadow_reap();
	WARN_ON_ONCE(atomic_read(&kasumi_sop_live));
	WARN_ON_ONCE(atomic_read(&kasumi_sop_active));
	WARN_ON_ONCE(atomic_read(&kasumi_sop_vnodes));
	synchronize_rcu();
	pr_info("Kasumi: sop_shadow exited\n");
}
