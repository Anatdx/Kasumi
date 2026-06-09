/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - SELinux inode SID overrides for trap-free security.selinux spoofing.
 *
 * Android's security.selinux getxattr path is handled by SELinux's in-core
 * inode SID, not by the filesystem xattr handler while SELinux is active.
 * Copying the source SID into the target inode makes vfs_getxattr return the
 * spoofed context without a kprobe on vfs_getxattr.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include "kasumi_xattr_sid_override.h"
#include "kasumi_root_detection.h"
#include "kasumi_runtime.h"

#include <linux/hashtable.h>
#include <linux/lsm_hooks.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#define KASUMI_XATTR_SID_HASH_BITS 10

enum kasumi_selinux_label_state {
	KASUMI_LABEL_INVALID,
	KASUMI_LABEL_INITIALIZED,
	KASUMI_LABEL_PENDING,
};

struct kasumi_selinux_inode_security {
	struct inode *inode;
	struct list_head list;
	u32 task_sid;
	u32 sid;
	u16 sclass;
	unsigned char initialized;
	spinlock_t lock;
};

struct kasumi_xattr_sid_meta {
	struct inode *inode;
	u32 orig_sid;
	u32 spoof_sid;
	unsigned int refs;
	struct hlist_node node;
	struct rcu_head rcu;
};

static DEFINE_HASHTABLE(kasumi_xattr_sid_table, KASUMI_XATTR_SID_HASH_BITS);
static DEFINE_SPINLOCK(kasumi_xattr_sid_lock);
static bool kasumi_xattr_sid_ready;
static int kasumi_selinux_inode_offset = -1;

static struct kasumi_xattr_sid_meta *kasumi_xattr_sid_lookup_rcu(struct inode *inode)
{
	struct kasumi_xattr_sid_meta *m;

	hash_for_each_possible_rcu(kasumi_xattr_sid_table, m, node, (unsigned long)inode) {
		if (m->inode == inode)
			return m;
	}
	return NULL;
}

static struct kasumi_selinux_inode_security *kasumi_selinux_isec(struct inode *inode)
{
	if (!inode || !inode->i_security || kasumi_selinux_inode_offset < 0)
		return NULL;
	return (void *)inode->i_security + kasumi_selinux_inode_offset;
}

static bool kasumi_selinux_read_sid(struct inode *inode, u32 *sid)
{
	struct kasumi_selinux_inode_security *isec = kasumi_selinux_isec(inode);
	unsigned long flags;

	if (!isec || !sid)
		return false;
	spin_lock_irqsave(&isec->lock, flags);
	if (isec->initialized != KASUMI_LABEL_INITIALIZED || !isec->sid) {
		spin_unlock_irqrestore(&isec->lock, flags);
		return false;
	}
	*sid = isec->sid;
	spin_unlock_irqrestore(&isec->lock, flags);
	return true;
}

static bool kasumi_selinux_write_sid(struct inode *inode, u32 sid)
{
	struct kasumi_selinux_inode_security *isec = kasumi_selinux_isec(inode);
	unsigned long flags;

	if (!isec || !sid)
		return false;
	spin_lock_irqsave(&isec->lock, flags);
	if (isec->initialized != KASUMI_LABEL_INITIALIZED) {
		spin_unlock_irqrestore(&isec->lock, flags);
		return false;
	}
	WRITE_ONCE(isec->sid, sid);
	spin_unlock_irqrestore(&isec->lock, flags);
	return true;
}

static int kasumi_source_sid_from_path(const char *source_path, u32 *sid)
{
	char *try_path;
	size_t len;
	int ret = -ENOENT;

	if (!source_path || !sid || !kasumi_kern_path)
		return -EINVAL;

	try_path = kstrdup(source_path, GFP_KERNEL);
	if (!try_path)
		return -ENOMEM;

	atomic_long_set(&kasumi_xattr_source_tgid, (long)task_tgid_vnr(current));
	len = strlen(try_path);
	while (len > 1) {
		struct path p;

		if (kasumi_kern_path(try_path, LOOKUP_FOLLOW, &p) == 0) {
			if (p.dentry && d_inode(p.dentry) &&
			    kasumi_selinux_read_sid(d_inode(p.dentry), sid))
				ret = 0;
			kasumi_path_put(&p);
			if (!ret)
				break;
		}

		{
			char *slash = strrchr(try_path, '/');

			if (!slash || slash == try_path)
				break;
			*slash = '\0';
			len = slash - try_path;
		}
	}
	atomic_long_set(&kasumi_xattr_source_tgid, 0);

	kfree(try_path);
	return ret;
}

static void kasumi_xattr_sid_meta_free_rcu(struct rcu_head *rcu)
{
	struct kasumi_xattr_sid_meta *m = container_of(rcu, struct kasumi_xattr_sid_meta, rcu);

	kfree(m);
}

static int kasumi_xattr_sid_install_sid(struct inode *target_inode, u32 source_sid)
{
	struct kasumi_xattr_sid_meta *m, *existing;
	u32 orig_sid;

	if (!READ_ONCE(kasumi_xattr_sid_ready))
		return -EOPNOTSUPP;
	if (!kasumi_root_allows_spoofing())
		return -EOPNOTSUPP;
	if (!target_inode || !source_sid)
		return -EINVAL;
	if (!kasumi_ihold)
		return -EOPNOTSUPP;

	if (!kasumi_selinux_read_sid(target_inode, &orig_sid))
		return -ENOENT;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	m->inode = target_inode;
	m->orig_sid = orig_sid;
	m->spoof_sid = source_sid;
	m->refs = 1;
	kasumi_ihold(target_inode);

	spin_lock(&kasumi_xattr_sid_lock);
	existing = kasumi_xattr_sid_lookup_rcu(target_inode);
	if (existing) {
		existing->spoof_sid = source_sid;
		existing->refs++;
		spin_unlock(&kasumi_xattr_sid_lock);
		iput(m->inode);
		kfree(m);
		if (!kasumi_selinux_write_sid(target_inode, source_sid)) {
			spin_lock(&kasumi_xattr_sid_lock);
			if (existing->refs > 0)
				existing->refs--;
			spin_unlock(&kasumi_xattr_sid_lock);
			return -ENOENT;
		}
		atomic64_inc(&kasumi_hook_stats.xattr_sid_overrides);
		return 0;
	}

	hash_add_rcu(kasumi_xattr_sid_table, &m->node, (unsigned long)target_inode);
	spin_unlock(&kasumi_xattr_sid_lock);

	if (!kasumi_selinux_write_sid(target_inode, source_sid)) {
		spin_lock(&kasumi_xattr_sid_lock);
		hash_del_rcu(&m->node);
		spin_unlock(&kasumi_xattr_sid_lock);
		iput(target_inode);
		call_rcu(&m->rcu, kasumi_xattr_sid_meta_free_rcu);
		return -ENOENT;
	}

	atomic64_inc(&kasumi_hook_stats.xattr_sid_overrides);
	kasumi_log("xattr_sid: inode %p sid %u -> %u\n", target_inode, orig_sid, source_sid);
	return 0;
}

int kasumi_xattr_sid_install(struct inode *target_inode, const char *source_path)
{
	u32 source_sid;
	int ret;

	if (!target_inode || !source_path)
		return -EINVAL;
	ret = kasumi_source_sid_from_path(source_path, &source_sid);
	if (ret)
		return ret;
	return kasumi_xattr_sid_install_sid(target_inode, source_sid);
}

static struct kasumi_xattr_sid_meta *kasumi_xattr_sid_uninstall_locked(struct inode *inode)
{
	struct kasumi_xattr_sid_meta *m;

	m = kasumi_xattr_sid_lookup_rcu(inode);
	if (!m)
		return NULL;
	if (m->refs > 1) {
		m->refs--;
		return NULL;
	}
	hash_del_rcu(&m->node);
	return m;
}

static int kasumi_xattr_sid_uninstall_inode(struct inode *inode)
{
	struct kasumi_xattr_sid_meta *m;

	if (!inode)
		return -EINVAL;

	spin_lock(&kasumi_xattr_sid_lock);
	m = kasumi_xattr_sid_uninstall_locked(inode);
	spin_unlock(&kasumi_xattr_sid_lock);

	if (!m)
		return 0;

	(void)kasumi_selinux_write_sid(m->inode, m->orig_sid);
	iput(m->inode);
	call_rcu(&m->rcu, kasumi_xattr_sid_meta_free_rcu);
	return 0;
}

static void kasumi_source_path_parent_or_anchor(char *path)
{
	char *slash;

	if (!path || path[0] != '/')
		return;
	slash = strrchr(path, '/');
	if (!slash || slash == path)
		return;
	*slash = '\0';
}

int kasumi_xattr_sid_uninstall_path(const char *path)
{
	struct path p;
	int ret;

	if (!path || !kasumi_kern_path)
		return -EINVAL;
	ret = kasumi_kern_path(path, LOOKUP_FOLLOW, &p);
	if (ret)
		return ret;
	if (!p.dentry || !d_inode(p.dentry)) {
		kasumi_path_put(&p);
		return -ENOENT;
	}

	ret = kasumi_xattr_sid_uninstall_inode(d_inode(p.dentry));
	kasumi_path_put(&p);
	return ret;
}

int kasumi_xattr_sid_install_path_ancestors(const char *target_path, const char *source_path)
{
	struct dentry *dentry;
	struct path p;
	char *source_walk;
	int installed = 0;
	int first_ret = 0;
	int ret;

	if (!target_path || !source_path || !kasumi_kern_path)
		return -EINVAL;
	source_walk = kstrdup(source_path, GFP_KERNEL);
	if (!source_walk)
		return -ENOMEM;
	ret = kasumi_kern_path(target_path, LOOKUP_FOLLOW, &p);
	if (ret) {
		kfree(source_walk);
		return ret;
	}

	for (dentry = p.dentry; dentry; dentry = dentry->d_parent) {
		struct inode *inode = d_inode(dentry);
		u32 source_sid;

		if (inode) {
			ret = kasumi_source_sid_from_path(source_walk, &source_sid);
			if (!ret)
				ret = kasumi_xattr_sid_install_sid(inode, source_sid);
			if (!ret) {
				installed++;
			} else if (!first_ret) {
				first_ret = ret;
			}
		}
		kasumi_source_path_parent_or_anchor(source_walk);
		if (dentry == p.mnt->mnt_root || dentry == dentry->d_parent)
			break;
	}

	kasumi_path_put(&p);
	kfree(source_walk);
	return installed ? 0 : (first_ret ?: -ENOENT);
}

int kasumi_xattr_sid_uninstall_path_ancestors(const char *target_path)
{
	struct dentry *dentry;
	struct path p;
	int ret;

	if (!target_path || !kasumi_kern_path)
		return -EINVAL;
	ret = kasumi_kern_path(target_path, LOOKUP_FOLLOW, &p);
	if (ret)
		return ret;

	for (dentry = p.dentry; dentry; dentry = dentry->d_parent) {
		if (d_inode(dentry))
			(void)kasumi_xattr_sid_uninstall_inode(d_inode(dentry));
		if (dentry == p.mnt->mnt_root || dentry == dentry->d_parent)
			break;
	}

	kasumi_path_put(&p);
	return 0;
}

int kasumi_xattr_sid_override_init(void)
{
	struct lsm_blob_sizes *selinux_blobs;

	hash_init(kasumi_xattr_sid_table);
	selinux_blobs = (void *)kasumi_lookup_name("selinux_blob_sizes");
	if (!kasumi_valid_kernel_addr((unsigned long)selinux_blobs)) {
		pr_info("Kasumi: xattr_sid disabled (selinux_blob_sizes unavailable)\n");
		return 0;
	}
	kasumi_selinux_inode_offset = READ_ONCE(selinux_blobs->lbs_inode);
	if (kasumi_selinux_inode_offset < 0) {
		pr_info("Kasumi: xattr_sid disabled (bad SELinux inode offset %d)\n",
			kasumi_selinux_inode_offset);
		kasumi_selinux_inode_offset = -1;
		return 0;
	}
	WRITE_ONCE(kasumi_xattr_sid_ready, true);
	pr_info("Kasumi: xattr_sid initialized (selinux inode offset=%d)\n",
		kasumi_selinux_inode_offset);
	return 0;
}

void kasumi_xattr_sid_override_exit(void)
{
	struct kasumi_xattr_sid_meta *m;
	struct hlist_node *tmp;
	HLIST_HEAD(free_list);
	int bkt;

	WRITE_ONCE(kasumi_xattr_sid_ready, false);

	spin_lock(&kasumi_xattr_sid_lock);
	hash_for_each_safe(kasumi_xattr_sid_table, bkt, tmp, m, node) {
		hash_del_rcu(&m->node);
		hlist_add_head(&m->node, &free_list);
	}
	spin_unlock(&kasumi_xattr_sid_lock);

	hlist_for_each_entry_safe(m, tmp, &free_list, node) {
		hlist_del(&m->node);
		(void)kasumi_selinux_write_sid(m->inode, m->orig_sid);
		iput(m->inode);
		call_rcu(&m->rcu, kasumi_xattr_sid_meta_free_rcu);
	}

	rcu_barrier();
	pr_info("Kasumi: xattr_sid exited\n");
}
