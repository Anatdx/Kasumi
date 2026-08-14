/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - directory file_operations shadow installation for fast readdir hooks.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include "kasumi_entrypoints.h"
#include "kasumi_fop_bridge.h"
#include "kasumi_fop_override.h"
#include "kasumi_runtime.h"
#include "kasumi_vfs_hooks.h"

#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#define KASUMI_FOP_HASH_BITS 10

struct kasumi_fop_meta {
	struct inode *inode;
	const struct file_operations *orig_fop;
	struct file_operations ingress_fop;
	struct file_operations shadow_fop;
	struct kasumi_fop_bridge_entry bridge;
	struct hlist_node node;
	struct list_head retire_node;
};

static DEFINE_HASHTABLE(kasumi_fop_table, KASUMI_FOP_HASH_BITS);
static DEFINE_SPINLOCK(kasumi_fop_lock);
static bool kasumi_fop_override_ready;

static struct kasumi_fop_meta *kasumi_fop_lookup_rcu(struct inode *inode)
{
	struct kasumi_fop_meta *m;

	hash_for_each_possible_rcu(kasumi_fop_table, m, node, (unsigned long)inode) {
		if (m->inode == inode)
			return m;
	}
	return NULL;
}

static void kasumi_fop_put_orig(const struct file_operations *fop)
{
	if (fop && fop->owner)
		module_put(fop->owner);
}

static void kasumi_fop_meta_free(struct kasumi_fop_meta *m)
{
	if (!m)
		return;
	if (m->inode)
		iput(m->inode);
	kasumi_fop_put_orig(m->orig_fop);
	kfree(m);
}

static const struct file_operations *
kasumi_fop_installed_table(const struct kasumi_fop_meta *m)
{
	return m->bridge.registered ? &m->ingress_fop : &m->shadow_fop;
}

KASUMI_NOCFI static int kasumi_shadow_iterate_shared(struct file *file,
						 struct dir_context *ctx)
{
	struct kasumi_filldir_wrapper *wrapper;
	struct kasumi_fop_meta *m;
	const struct file_operations *orig = NULL;
	int ret;

	if (!file)
		return -EINVAL;

	rcu_read_lock();
	m = kasumi_fop_lookup_rcu(file_inode(file));
	if (m)
		orig = m->orig_fop;
	rcu_read_unlock();

	if (!orig || !orig->iterate_shared)
		return -ENOTDIR;

	atomic64_inc(&kasumi_hook_stats.iterate_fop_entries);

	wrapper = kasumi_iterate_prepare_wrapper(file, ctx);
	if (!wrapper)
		return orig->iterate_shared(file, ctx);

	atomic64_inc(&kasumi_hook_stats.iterate_fop_wrapped);
	ret = orig->iterate_shared(file, &wrapper->wrap_ctx);
	kasumi_iterate_finish_wrapper(wrapper);
	return ret;
}

bool kasumi_fop_file_is_shadowed(const struct file *file)
{
	struct kasumi_fop_meta *m;
	bool shadowed = false;

	if (!file)
		return false;

	rcu_read_lock();
	m = kasumi_fop_lookup_rcu(file_inode(file));
	if (m && READ_ONCE(file->f_op) == &m->shadow_fop)
		shadowed = true;
	rcu_read_unlock();

	return shadowed;
}

int kasumi_fop_install(struct inode *inode)
{
	struct kasumi_fop_meta *m, *existing;
	const struct file_operations *orig;

	if (!READ_ONCE(kasumi_fop_override_ready))
		return -EOPNOTSUPP;
	if (!inode || !inode->i_mapping || !S_ISDIR(inode->i_mode))
		return -EINVAL;
	if (!inode->i_sb)
		return -EINVAL;
	if (!kasumi_ihold)
		return -EOPNOTSUPP;
	if (test_bit(AS_FLAGS_KASUMI_FOP_INSTALLED, &inode->i_mapping->flags))
		return 0;

	orig = READ_ONCE(inode->i_fop);
	if (!orig || !orig->iterate_shared)
		return -EOPNOTSUPP;
	if (orig->owner && !try_module_get(orig->owner))
		return -ENODEV;

	m = kzalloc(sizeof(*m), GFP_ATOMIC);
	if (!m) {
		kasumi_fop_put_orig(orig);
		return -ENOMEM;
	}

	m->inode = inode;
	m->orig_fop = orig;
	INIT_LIST_HEAD(&m->retire_node);
	memcpy(&m->shadow_fop, orig, sizeof(struct file_operations));
	m->shadow_fop.owner = THIS_MODULE;
	m->shadow_fop.iterate_shared = kasumi_shadow_iterate_shared;
	memcpy(&m->ingress_fop, orig, sizeof(struct file_operations));
	kasumi_ihold(inode);

	spin_lock(&kasumi_fop_lock);
	if (!READ_ONCE(kasumi_fop_override_ready)) {
		spin_unlock(&kasumi_fop_lock);
		kasumi_fop_meta_free(m);
		return -EOPNOTSUPP;
	}
	existing = kasumi_fop_lookup_rcu(inode);
	if (existing) {
		spin_unlock(&kasumi_fop_lock);
		kasumi_fop_meta_free(m);
		return 0;
	}
	if (READ_ONCE(inode->i_fop) != orig) {
		spin_unlock(&kasumi_fop_lock);
		kasumi_fop_meta_free(m);
		return -EAGAIN;
	}

	hash_add_rcu(kasumi_fop_table, &m->node, (unsigned long)inode);
	(void)kasumi_fop_bridge_register(&m->bridge, &m->ingress_fop,
					 &m->shadow_fop, m->orig_fop);
	set_bit(AS_FLAGS_KASUMI_FOP_INSTALLED, &inode->i_mapping->flags);
	smp_wmb();
	WRITE_ONCE(inode->i_fop, kasumi_fop_installed_table(m));
	spin_unlock(&kasumi_fop_lock);

	kasumi_log("fop_override: installed on inode %p (orig=%p)\n", inode, orig);
	return 0;
}

static struct kasumi_fop_meta *
kasumi_fop_uninstall_locked(struct inode *inode)
{
	struct kasumi_fop_meta *m;

	m = kasumi_fop_lookup_rcu(inode);
	if (!m)
		return NULL;

	if (inode->i_fop == kasumi_fop_installed_table(m))
		WRITE_ONCE(inode->i_fop, m->orig_fop);

	hash_del_rcu(&m->node);
	if (inode->i_mapping)
		clear_bit(AS_FLAGS_KASUMI_FOP_INSTALLED, &inode->i_mapping->flags);
	return m;
}

void kasumi_fop_cleanup_inode(struct inode *inode)
{
	struct kasumi_fop_meta *m;

	if (!inode)
		return;

	spin_lock(&kasumi_fop_lock);
	m = kasumi_fop_uninstall_locked(inode);
	spin_unlock(&kasumi_fop_lock);
	if (!m)
		return;

	if (m->bridge.registered)
		kasumi_synchronize_rcu_tasks();
	kasumi_fop_bridge_unregister(&m->bridge);
	synchronize_rcu();
	kasumi_fop_meta_free(m);
}

int kasumi_fop_override_init(void)
{
	hash_init(kasumi_fop_table);
	WRITE_ONCE(kasumi_fop_override_ready, true);
	pr_info("Kasumi: fop_override initialized\n");
	return 0;
}

void kasumi_fop_override_stop_new(void)
{
	struct kasumi_fop_meta *m;
	bool had_meta = false;
	int bkt;

	WRITE_ONCE(kasumi_fop_override_ready, false);

	spin_lock(&kasumi_fop_lock);
	hash_for_each(kasumi_fop_table, bkt, m, node) {
		had_meta = true;
		if (m->inode && m->inode->i_fop ==
					kasumi_fop_installed_table(m))
			WRITE_ONCE(m->inode->i_fop, m->orig_fop);
		if (m->inode && m->inode->i_mapping)
			clear_bit(AS_FLAGS_KASUMI_FOP_INSTALLED,
				  &m->inode->i_mapping->flags);
	}
	spin_unlock(&kasumi_fop_lock);
	/* do_dentry_open() can fetch inode->i_fop before fops_get() pins its
	 * owner.  Tasks-RCU forces every such stale fetch through fops_get (and
	 * therefore into module_refcount) before PREPARE may report READY.
	 */
	if (had_meta)
		kasumi_synchronize_rcu_tasks();
}

void kasumi_fop_override_exit(void)
{
	LIST_HEAD(retired);
	struct kasumi_fop_meta *m, *next;
	struct hlist_node *tmp;
	int bkt;

	kasumi_fop_override_stop_new();

	spin_lock(&kasumi_fop_lock);
	hash_for_each_safe(kasumi_fop_table, bkt, tmp, m, node) {
		hash_del_rcu(&m->node);
		kasumi_fop_bridge_unregister(&m->bridge);
		list_add_tail(&m->retire_node, &retired);
	}
	spin_unlock(&kasumi_fop_lock);

	synchronize_rcu();
	list_for_each_entry_safe(m, next, &retired, retire_node) {
		list_del(&m->retire_node);
		kasumi_fop_meta_free(m);
	}
	pr_info("Kasumi: fop_override exited\n");
}
