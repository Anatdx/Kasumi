/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - lookup-time inode_operations shadow installation for fast getattr spoofing.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include "kasumi_entrypoints.h"
#include "kasumi_iop_override.h"
#include "kasumi_runtime.h"

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/version.h>
#include <linux/namei.h>

#define KASUMI_IOP_HASH_BITS 10

struct kasumi_iop_meta {
	struct inode *inode;                          /* hash key */
	const struct inode_operations *orig_iop;      /* what i_op pointed to before */
	struct inode_operations shadow_iop;           /* our copy with .getattr patched */
	struct hlist_node node;
	struct list_head retire_node;
	struct rcu_head rcu;
};

static DEFINE_HASHTABLE(kasumi_iop_table, KASUMI_IOP_HASH_BITS);
static DEFINE_SPINLOCK(kasumi_iop_lock);
static atomic_t kasumi_iop_active_callbacks = ATOMIC_INIT(0);
static atomic_t kasumi_iop_live = ATOMIC_INIT(0);
static DEFINE_MUTEX(kasumi_iop_quiesce_lock);
static DECLARE_WAIT_QUEUE_HEAD(kasumi_iop_quiesce_wait);
static bool kasumi_iop_ready;
static bool kasumi_iop_first_tasks_sync;
static bool kasumi_iop_callbacks_quiesced;

/* ------------------------------------------------------------------ */
/* hash table helpers                                                  */
/* ------------------------------------------------------------------ */

static struct kasumi_iop_meta *kasumi_iop_lookup_rcu(struct inode *inode)
{
	struct kasumi_iop_meta *m;

	hash_for_each_possible_rcu(kasumi_iop_table, m, node, (unsigned long)inode) {
		if (m->inode == inode)
			return m;
	}
	return NULL;
}

static void kasumi_iop_meta_free_rcu(struct rcu_head *rcu)
{
	struct kasumi_iop_meta *m = container_of(rcu, struct kasumi_iop_meta, rcu);
	kfree(m);
}

/* ------------------------------------------------------------------ */
/* shadow getattr - signature varies across kernel versions             */
/* ------------------------------------------------------------------ */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0))
KASUMI_NOCFI static int kasumi_shadow_getattr(struct mnt_idmap *idmap,
					  const struct path *path,
					  struct kstat *stat,
					  u32 request_mask,
					  unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct kasumi_iop_meta *m;
	const struct inode_operations *orig = NULL;
	int ret;

	atomic_inc(&kasumi_iop_active_callbacks);
	atomic64_inc(&kasumi_hook_stats.iop_getattr_entries);
	rcu_read_lock();
	m = kasumi_iop_lookup_rcu(inode);
	if (m)
		orig = m->orig_iop;
	rcu_read_unlock();

	if (orig && orig->getattr)
		ret = orig->getattr(idmap, path, stat, request_mask, query_flags);
	else {
		generic_fillattr(idmap, request_mask, inode, stat);
		ret = 0;
	}

	if (ret == 0 && inode && inode->i_mapping &&
	    test_bit(AS_FLAGS_KASUMI_SPOOF_KSTAT, &inode->i_mapping->flags)) {
		kasumi_apply_kstat_spoof(inode, stat);
		atomic64_inc(&kasumi_hook_stats.iop_getattr_spoofs);
	}
	if (atomic_dec_and_test(&kasumi_iop_active_callbacks))
		wake_up_all(&kasumi_iop_quiesce_wait);
	return ret;
}
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
KASUMI_NOCFI static int kasumi_shadow_getattr(struct user_namespace *userns,
					  const struct path *path,
					  struct kstat *stat,
					  u32 request_mask,
					  unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct kasumi_iop_meta *m;
	const struct inode_operations *orig = NULL;
	int ret;

	atomic_inc(&kasumi_iop_active_callbacks);
	atomic64_inc(&kasumi_hook_stats.iop_getattr_entries);
	rcu_read_lock();
	m = kasumi_iop_lookup_rcu(inode);
	if (m)
		orig = m->orig_iop;
	rcu_read_unlock();

	if (orig && orig->getattr)
		ret = orig->getattr(userns, path, stat, request_mask, query_flags);
	else {
		generic_fillattr(userns, inode, stat);
		ret = 0;
	}

	if (ret == 0 && inode && inode->i_mapping &&
	    test_bit(AS_FLAGS_KASUMI_SPOOF_KSTAT, &inode->i_mapping->flags)) {
		kasumi_apply_kstat_spoof(inode, stat);
		atomic64_inc(&kasumi_hook_stats.iop_getattr_spoofs);
	}
	if (atomic_dec_and_test(&kasumi_iop_active_callbacks))
		wake_up_all(&kasumi_iop_quiesce_wait);
	return ret;
}
#else
KASUMI_NOCFI static int kasumi_shadow_getattr(const struct path *path,
					  struct kstat *stat,
					  u32 request_mask,
					  unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct kasumi_iop_meta *m;
	const struct inode_operations *orig = NULL;
	int ret;

	atomic_inc(&kasumi_iop_active_callbacks);
	atomic64_inc(&kasumi_hook_stats.iop_getattr_entries);
	rcu_read_lock();
	m = kasumi_iop_lookup_rcu(inode);
	if (m)
		orig = m->orig_iop;
	rcu_read_unlock();

	if (orig && orig->getattr)
		ret = orig->getattr(path, stat, request_mask, query_flags);
	else {
		generic_fillattr(inode, stat);
		ret = 0;
	}

	if (ret == 0 && inode && inode->i_mapping &&
	    test_bit(AS_FLAGS_KASUMI_SPOOF_KSTAT, &inode->i_mapping->flags)) {
		kasumi_apply_kstat_spoof(inode, stat);
		atomic64_inc(&kasumi_hook_stats.iop_getattr_spoofs);
	}
	if (atomic_dec_and_test(&kasumi_iop_active_callbacks))
		wake_up_all(&kasumi_iop_quiesce_wait);
	return ret;
}
#endif

/* ------------------------------------------------------------------ */
/* install / uninstall                                                  */
/* ------------------------------------------------------------------ */

KASUMI_NOCFI int kasumi_iop_install(struct inode *inode)
{
	struct kasumi_iop_meta *m, *existing;
	const struct inode_operations *orig;

	if (!READ_ONCE(kasumi_iop_ready))
		return -ESHUTDOWN;
	if (!inode || !inode->i_op)
		return -EINVAL;
	if (!inode->i_mapping)
		return -EINVAL;
	if (!inode->i_sb)
		return -EINVAL;

	if (test_bit(AS_FLAGS_KASUMI_IOP_INSTALLED, &inode->i_mapping->flags))
		return 0;
	if (!kasumi_ihold)
		return -EOPNOTSUPP;

	orig = inode->i_op;

	m = kzalloc(sizeof(*m), GFP_ATOMIC);
	if (!m)
		return -ENOMEM;

	m->inode = inode;
	m->orig_iop = orig;
	memcpy(&m->shadow_iop, orig, sizeof(struct inode_operations));
	m->shadow_iop.getattr = kasumi_shadow_getattr;
	INIT_LIST_HEAD(&m->retire_node);
	kasumi_ihold(inode);

	spin_lock(&kasumi_iop_lock);
	if (!READ_ONCE(kasumi_iop_ready)) {
		spin_unlock(&kasumi_iop_lock);
		iput(inode);
		kfree(m);
		return -ESHUTDOWN;
	}
	/* Race: another CPU may have installed concurrently. */
	existing = kasumi_iop_lookup_rcu(inode);
	if (existing) {
		spin_unlock(&kasumi_iop_lock);
		iput(inode);
		kfree(m);
		return 0;
	}
	if (READ_ONCE(inode->i_op) != orig) {
		spin_unlock(&kasumi_iop_lock);
		iput(inode);
		kfree(m);
		return -EAGAIN;
	}
	hash_add_rcu(kasumi_iop_table, &m->node, (unsigned long)inode);
	atomic_inc(&kasumi_iop_live);
	/* Publish: set flag THEN swap pointer so readers seeing new i_op
	 * also see the flag. */
	set_bit(AS_FLAGS_KASUMI_IOP_INSTALLED, &inode->i_mapping->flags);
	smp_wmb();
	WRITE_ONCE(inode->i_op, &m->shadow_iop);
	spin_unlock(&kasumi_iop_lock);

	kasumi_log("iop_override: installed on inode %p (orig=%p)\n", inode, orig);
	return 0;
}

int kasumi_iop_mark_spoof(struct inode *inode)
{
	int ret;

	if (!inode || !inode->i_mapping)
		return -EINVAL;
	if (!READ_ONCE(kasumi_iop_ready))
		return -ESHUTDOWN;
	set_bit(AS_FLAGS_KASUMI_SPOOF_KSTAT, &inode->i_mapping->flags);
	ret = kasumi_iop_install(inode);
	if (ret)
		clear_bit(AS_FLAGS_KASUMI_SPOOF_KSTAT,
			  &inode->i_mapping->flags);
	return ret;
}

/*
 * Internal uninstall (called from super_operations destroy_inode and from exit).
 * Restores original i_op pointer and frees metadata after RCU grace period.
 * Safe to call when not installed.
 */
static struct kasumi_iop_meta *
kasumi_iop_uninstall_locked(struct inode *inode)
{
	struct kasumi_iop_meta *m;

	m = kasumi_iop_lookup_rcu(inode);
	if (!m)
		return NULL;

	/* Restore original first so any in-flight reader either sees old or
	 * shadow (both valid until RCU grace ends). */
	if (inode->i_op == &m->shadow_iop)
		WRITE_ONCE(inode->i_op, m->orig_iop);

	hash_del_rcu(&m->node);
	if (inode->i_mapping)
		clear_bit(AS_FLAGS_KASUMI_IOP_INSTALLED, &inode->i_mapping->flags);

	return m;
}

void kasumi_iop_cleanup_inode(struct inode *inode)
{
	struct kasumi_iop_meta *m;

	if (!inode)
		return;

	spin_lock(&kasumi_iop_lock);
	m = kasumi_iop_uninstall_locked(inode);
	spin_unlock(&kasumi_iop_lock);
	if (m) {
		atomic_dec(&kasumi_iop_live);
		iput(m->inode);
		call_rcu(&m->rcu, kasumi_iop_meta_free_rcu);
	}
}

/* ------------------------------------------------------------------ */
/* init / exit                                                          */
/* ------------------------------------------------------------------ */

int kasumi_iop_override_init(void)
{
	hash_init(kasumi_iop_table);
	atomic_set(&kasumi_iop_active_callbacks, 0);
	atomic_set(&kasumi_iop_live, 0);
	kasumi_iop_first_tasks_sync = false;
	kasumi_iop_callbacks_quiesced = false;
	WRITE_ONCE(kasumi_iop_ready, true);
	pr_info("Kasumi: iop_override initialized\n");
	return 0;
}

void kasumi_iop_override_stop_new(void)
{
	struct kasumi_iop_meta *m;
	int bkt;

	mutex_lock(&kasumi_iop_quiesce_lock);
	WRITE_ONCE(kasumi_iop_ready, false);
	spin_lock(&kasumi_iop_lock);
	hash_for_each(kasumi_iop_table, bkt, m, node) {
		if (m->inode && m->inode->i_op == &m->shadow_iop)
			WRITE_ONCE(m->inode->i_op, m->orig_iop);
		if (m->inode && m->inode->i_mapping)
			clear_bit(AS_FLAGS_KASUMI_IOP_INSTALLED,
				  &m->inode->i_mapping->flags);
	}
	spin_unlock(&kasumi_iop_lock);
	synchronize_rcu();
	if (!atomic_read(&kasumi_iop_live)) {
		kasumi_iop_callbacks_quiesced = true;
	} else if (!kasumi_iop_first_tasks_sync) {
		/* Close the load-pointer-to-callback-entry window for ownerless
		 * inode_operations before the control fd can be released.
		 */
		kasumi_synchronize_rcu_tasks();
		kasumi_iop_first_tasks_sync = true;
	}
	mutex_unlock(&kasumi_iop_quiesce_lock);
}

unsigned int kasumi_iop_override_active(void)
{
	return (unsigned int)atomic_read(&kasumi_iop_active_callbacks);
}

bool kasumi_iop_override_quiesced(void)
{
	bool quiesced;

	mutex_lock(&kasumi_iop_quiesce_lock);
	if (!kasumi_iop_callbacks_quiesced &&
	    kasumi_iop_first_tasks_sync &&
	    !atomic_read(&kasumi_iop_active_callbacks)) {
		/* The first Tasks-RCU grace period forced every stale pre-entry
		 * caller into the wrapper.  This second one covers the wrapper
		 * epilogue after its active count reaches zero.
		 */
		kasumi_synchronize_rcu_tasks();
		kasumi_iop_callbacks_quiesced = true;
	}
	quiesced = kasumi_iop_callbacks_quiesced;
	mutex_unlock(&kasumi_iop_quiesce_lock);
	return quiesced;
}

void kasumi_iop_override_exit(void)
{
	struct kasumi_iop_meta *m;
	struct hlist_node *tmp;
	LIST_HEAD(retired);
	int bkt;

	kasumi_iop_override_stop_new();
	if (!kasumi_iop_override_quiesced()) {
		wait_event(kasumi_iop_quiesce_wait,
			   !atomic_read(&kasumi_iop_active_callbacks));
		WARN_ON_ONCE(!kasumi_iop_override_quiesced());
	}
	spin_lock(&kasumi_iop_lock);
	hash_for_each_safe(kasumi_iop_table, bkt, tmp, m, node) {
		hash_del_rcu(&m->node);
		list_add_tail(&m->retire_node, &retired);
	}
	spin_unlock(&kasumi_iop_lock);
	synchronize_rcu();
	while (!list_empty(&retired)) {
		m = list_first_entry(&retired, struct kasumi_iop_meta,
				     retire_node);
		list_del(&m->retire_node);
		atomic_dec(&kasumi_iop_live);
		iput(m->inode);
		kfree(m);
	}

	rcu_barrier();
	pr_info("Kasumi: iop_override exited\n");
}
