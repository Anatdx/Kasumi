/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - scoped selinuxfs transaction filtering for hidden-app views.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include "kasumi_fake_selinuxfs_access.h"
#include "kasumi_entrypoints.h"
#include "kasumi_path_policy.h"
#include "kasumi_runtime.h"
#include "kasumi_sop_override.h"

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#define KASUMI_SELINUXFS_ACCESS_PATH     "/sys/fs/selinux/access"
#define KASUMI_SELINUXFS_ALT_ACCESS_PATH "/sys/kernel/security/selinux/access"
#define KASUMI_SELINUXFS_CONTEXT_PATH     "/sys/fs/selinux/context"
#define KASUMI_SELINUXFS_ALT_CONTEXT_PATH "/sys/kernel/security/selinux/context"
#define KASUMI_SELINUXFS_QUERY_MAX       512
#define KASUMI_SELINUXFS_MAGIC           0x4b534d53454c4156ULL

/*
 * selinuxfs/access returns:
 *   allowed decided auditallow auditdeny seqno flags
 * Mark the requested permission as decided-but-not-allowed. libselinux then
 * treats the active probe as a normal policy miss instead of an I/O failure.
 */
#define KASUMI_SELINUXFS_DENY_DECISION "0 ffffffff 0 ffffffff 0 0"

struct kasumi_selinuxfs_fake_txn {
	u64 magic;
	size_t len;
	char decision[sizeof(KASUMI_SELINUXFS_DENY_DECISION)];
};

enum kasumi_selinuxfs_txn_kind {
	KASUMI_SELINUXFS_ACCESS,
	KASUMI_SELINUXFS_CONTEXT,
};

struct kasumi_selinuxfs_txn_meta {
	struct inode *inode;
	enum kasumi_selinuxfs_txn_kind kind;
	const struct file_operations *orig_fop;
	struct file_operations shadow_fop;
	struct rcu_head rcu;
};

static struct kasumi_selinuxfs_txn_meta __rcu *kasumi_selinuxfs_access_meta;
static struct kasumi_selinuxfs_txn_meta __rcu *kasumi_selinuxfs_context_meta;
static DEFINE_SPINLOCK(kasumi_selinuxfs_lock);
static bool kasumi_selinuxfs_ready;

static bool kasumi_selinuxfs_marker_match(const char *ctx)
{
	static const char * const markers[] = {
		":magisk:",
		":ksu:",
		":su:",
		"magisk_file",
		"magisk_log_file",
		"ksu_file",
		"kernelsu",
		"apatch",
		"kernelpatch",
		"lsposed_file",
		"xposed_data",
		"adbroot",
		"adb_data_file",
	};
	size_t i;

	if (!ctx)
		return false;

	for (i = 0; i < ARRAY_SIZE(markers); i++) {
		if (strstr(ctx, markers[i]))
			return true;
	}
	return false;
}

static bool kasumi_selinuxfs_system_execmem_probe(const char *scon,
						  const char *tcon,
						  const char *tclass,
						  const char *perm)
{
	if (!scon || !tcon || !tclass)
		return false;
	if (strcmp(scon, "u:r:system_server:s0") ||
	    strcmp(tcon, "u:r:system_server:s0"))
		return false;
	if (strcmp(tclass, "process") && strcmp(tclass, "2"))
		return false;

	/*
	 * selinuxfs/access returns an av_decision for the whole class; libselinux
	 * applies the requested bit after reading it. Accept both direct string
	 * form and the numeric forms seen through libselinux/kernel policy maps.
	 */
	if (!perm || !*perm)
		return true;
	return !strcmp(perm, "execmem") ||
	       !strcmp(perm, "26") ||
	       !strcmp(perm, "1a") ||
	       !strcmp(perm, "0x1a") ||
	       !strcmp(perm, "2000000") ||
	       !strcmp(perm, "0x2000000");
}

static bool kasumi_selinuxfs_sensitive_context(char *context)
{
	char *ctx;

	if (!context)
		return false;

	ctx = strim(context);
	return kasumi_fake_selinuxfs_context_is_sensitive(ctx);
}

bool kasumi_fake_selinuxfs_context_is_sensitive(const char *context)
{
	return kasumi_selinuxfs_marker_match(context);
}

static bool kasumi_selinuxfs_query_is_probe(char *query)
{
	char *p = query;
	char *scon, *tcon, *tclass, *perm;

	if (!p)
		return false;

	p = strim(p);
	scon = strsep(&p, " \t\r\n");
	tcon = strsep(&p, " \t\r\n");
	tclass = strsep(&p, " \t\r\n");
	perm = strsep(&p, " \t\r\n");
	if (!scon || !tcon || !*scon || !*tcon)
		return false;

	return kasumi_selinuxfs_marker_match(scon) ||
	       kasumi_selinuxfs_marker_match(tcon) ||
	       kasumi_selinuxfs_system_execmem_probe(scon, tcon, tclass, perm);
}

static bool kasumi_selinuxfs_fake_txn(void *priv)
{
	struct kasumi_selinuxfs_fake_txn *txn = priv;

	return txn && READ_ONCE(txn->magic) == KASUMI_SELINUXFS_MAGIC;
}

static void kasumi_selinuxfs_lookup(struct inode *inode,
				    const struct file_operations **orig,
				    enum kasumi_selinuxfs_txn_kind *kind)
{
	struct kasumi_selinuxfs_txn_meta *m;

	if (orig)
		*orig = NULL;

	rcu_read_lock();
	m = rcu_dereference(kasumi_selinuxfs_access_meta);
	if (!m || m->inode != inode)
		m = rcu_dereference(kasumi_selinuxfs_context_meta);
	if (m && m->inode == inode) {
		if (orig)
			*orig = m->orig_fop;
		if (kind)
			*kind = m->kind;
	}
	rcu_read_unlock();
}

KASUMI_NOCFI static ssize_t kasumi_selinuxfs_access_write(struct file *file,
							  const char __user *buf,
							  size_t count,
							  loff_t *ppos)
{
	const struct file_operations *orig;
	enum kasumi_selinuxfs_txn_kind kind = KASUMI_SELINUXFS_ACCESS;
	struct kasumi_selinuxfs_fake_txn *txn = NULL;
	void *old_priv;
	char *query;
	bool should_fake = false;

	kasumi_selinuxfs_lookup(file_inode(file), &orig, &kind);
	if (!orig || !orig->write)
		return -EIO;

	if (kind == KASUMI_SELINUXFS_ACCESS)
		atomic64_inc(&kasumi_hook_stats.selinuxfs_access_queries);
	else
		atomic64_inc(&kasumi_hook_stats.selinuxfs_context_queries);

	if (!(kasumi_feature_enabled_mask & KSM_FEATURE_SELINUX_FIX) ||
	    !kasumi_current_is_selinux_guard_target() ||
	    !buf || count == 0 || count >= KASUMI_SELINUXFS_QUERY_MAX)
		return orig->write(file, buf, count, ppos);

	query = kmalloc(count + 1, GFP_KERNEL);
	if (!query)
		return -ENOMEM;
	if (copy_from_user(query, buf, count)) {
		kfree(query);
		return -EFAULT;
	}
	query[count] = '\0';

	if (kind == KASUMI_SELINUXFS_ACCESS)
		should_fake = kasumi_selinuxfs_query_is_probe(query);
	else
		should_fake = kasumi_selinuxfs_sensitive_context(query);
	kfree(query);

	if (!should_fake)
		return orig->write(file, buf, count, ppos);

	if (kind == KASUMI_SELINUXFS_CONTEXT) {
		atomic64_inc(&kasumi_hook_stats.selinuxfs_context_spoofs);
		kasumi_log("fake_selinuxfs: rejected context query pid=%d uid=%u comm=%s\n",
			   task_tgid_vnr(current), __kuid_val(current_uid()), current->comm);
		return -EINVAL;
	}

	old_priv = READ_ONCE(file->private_data);
	if (old_priv && !kasumi_selinuxfs_fake_txn(old_priv))
		return orig->write(file, buf, count, ppos);

	txn = kzalloc(sizeof(*txn), GFP_KERNEL);
	if (!txn)
		return -ENOMEM;

	txn->magic = KASUMI_SELINUXFS_MAGIC;
	memcpy(txn->decision, KASUMI_SELINUXFS_DENY_DECISION,
	       sizeof(KASUMI_SELINUXFS_DENY_DECISION));
	txn->len = strlen(txn->decision);

	WRITE_ONCE(file->private_data, txn);
	if (old_priv)
		kfree(old_priv);

	if (ppos)
		*ppos += count;
	atomic64_inc(&kasumi_hook_stats.selinuxfs_access_spoofs);
	kasumi_log("fake_selinuxfs: denied access query pid=%d uid=%u comm=%s\n",
		   task_tgid_vnr(current), __kuid_val(current_uid()), current->comm);
	return count;
}

KASUMI_NOCFI static ssize_t kasumi_selinuxfs_access_read(struct file *file,
							 char __user *buf,
							 size_t count,
							 loff_t *ppos)
{
	const struct file_operations *orig;
	struct kasumi_selinuxfs_fake_txn *txn;
	loff_t pos;
	size_t left;

	txn = READ_ONCE(file->private_data);
	if (kasumi_selinuxfs_fake_txn(txn)) {
		pos = ppos ? *ppos : file->f_pos;
		if (pos < 0)
			return -EINVAL;
		if (pos >= txn->len)
			return 0;

		left = txn->len - pos;
		if (count > left)
			count = left;
		if (copy_to_user(buf, txn->decision + pos, count))
			return -EFAULT;
		if (ppos)
			*ppos = pos + count;
		else
			file->f_pos = pos + count;
		return count;
	}

	kasumi_selinuxfs_lookup(file_inode(file), &orig, NULL);
	if (!orig || !orig->read)
		return -EIO;
	return orig->read(file, buf, count, ppos);
}

KASUMI_NOCFI static int kasumi_selinuxfs_access_release(struct inode *inode,
							struct file *file)
{
	const struct file_operations *orig;
	struct kasumi_selinuxfs_fake_txn *txn;

	txn = READ_ONCE(file->private_data);
	if (kasumi_selinuxfs_fake_txn(txn)) {
		WRITE_ONCE(file->private_data, NULL);
		WRITE_ONCE(txn->magic, 0);
		kfree(txn);
		return 0;
	}

	kasumi_selinuxfs_lookup(file_inode(file), &orig, NULL);
	if (orig && orig->release)
		return orig->release(inode, file);
	return 0;
}

static void kasumi_selinuxfs_meta_free_rcu(struct rcu_head *rcu)
{
	struct kasumi_selinuxfs_txn_meta *m =
		container_of(rcu, struct kasumi_selinuxfs_txn_meta, rcu);

	if (m->orig_fop && m->orig_fop->owner)
		module_put(m->orig_fop->owner);
	kfree(m);
}

static int kasumi_fake_selinuxfs_install_path(const char *path,
					     enum kasumi_selinuxfs_txn_kind kind)
{
	struct kasumi_selinuxfs_txn_meta __rcu **slot;
	struct kasumi_selinuxfs_txn_meta *m;
	const struct file_operations *orig;
	struct path p = {};
	struct inode *inode;
	int ret;

	if (!kasumi_kern_path)
		return -EOPNOTSUPP;

	slot = kind == KASUMI_SELINUXFS_ACCESS ? &kasumi_selinuxfs_access_meta :
						 &kasumi_selinuxfs_context_meta;

	ret = kasumi_kern_path(path, LOOKUP_FOLLOW, &p);
	if (ret)
		return ret;

	inode = d_inode(p.dentry);
	if (!inode || !inode->i_sb || !S_ISREG(inode->i_mode)) {
		ret = -EINVAL;
		goto out_path;
	}
	if (kasumi_sop_install(inode->i_sb)) {
		ret = -EOPNOTSUPP;
		goto out_path;
	}

	orig = READ_ONCE(inode->i_fop);
	if (!orig || !orig->write || !orig->read) {
		ret = -EOPNOTSUPP;
		goto out_path;
	}
	if (orig->owner && !try_module_get(orig->owner)) {
		ret = -ENODEV;
		goto out_path;
	}

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m) {
		if (orig->owner)
			module_put(orig->owner);
		ret = -ENOMEM;
		goto out_path;
	}

	m->inode = inode;
	m->kind = kind;
	m->orig_fop = orig;
	memcpy(&m->shadow_fop, orig, sizeof(m->shadow_fop));
	m->shadow_fop.owner = THIS_MODULE;
	m->shadow_fop.write = kasumi_selinuxfs_access_write;
	m->shadow_fop.read = kasumi_selinuxfs_access_read;
	m->shadow_fop.release = kasumi_selinuxfs_access_release;

	spin_lock(&kasumi_selinuxfs_lock);
	if (rcu_dereference_protected(*slot,
				      lockdep_is_held(&kasumi_selinuxfs_lock))) {
		spin_unlock(&kasumi_selinuxfs_lock);
		if (orig->owner)
			module_put(orig->owner);
		kfree(m);
		ret = 0;
		goto out_path;
	}
	if (READ_ONCE(inode->i_fop) != orig) {
		spin_unlock(&kasumi_selinuxfs_lock);
		if (orig->owner)
			module_put(orig->owner);
		kfree(m);
		ret = -EAGAIN;
		goto out_path;
	}

	rcu_assign_pointer(*slot, m);
	smp_wmb();
	WRITE_ONCE(inode->i_fop, &m->shadow_fop);
	WRITE_ONCE(kasumi_selinuxfs_ready, true);
	spin_unlock(&kasumi_selinuxfs_lock);

	pr_info("Kasumi: fake_selinuxfs installed on %s\n", path);
	ret = 0;

out_path:
	kasumi_path_put(&p);
	return ret;
}

bool kasumi_fake_selinuxfs_access_active(void)
{
	return READ_ONCE(kasumi_selinuxfs_ready) &&
	       (rcu_access_pointer(kasumi_selinuxfs_access_meta) ||
		rcu_access_pointer(kasumi_selinuxfs_context_meta));
}

int kasumi_fake_selinuxfs_access_init(void)
{
	int access_ret, context_ret;

	access_ret = kasumi_fake_selinuxfs_install_path(KASUMI_SELINUXFS_ACCESS_PATH,
						       KASUMI_SELINUXFS_ACCESS);
	if (access_ret)
		access_ret = kasumi_fake_selinuxfs_install_path(KASUMI_SELINUXFS_ALT_ACCESS_PATH,
								KASUMI_SELINUXFS_ACCESS);

	context_ret = kasumi_fake_selinuxfs_install_path(KASUMI_SELINUXFS_CONTEXT_PATH,
							KASUMI_SELINUXFS_CONTEXT);
	if (context_ret)
		context_ret = kasumi_fake_selinuxfs_install_path(KASUMI_SELINUXFS_ALT_CONTEXT_PATH,
								 KASUMI_SELINUXFS_CONTEXT);

	if (access_ret || context_ret)
		pr_warn("Kasumi: fake_selinuxfs partial install (access=%d context=%d)\n",
			access_ret, context_ret);
	return kasumi_fake_selinuxfs_access_active() ? 0 :
	       (access_ret ? access_ret : context_ret);
}

static void kasumi_fake_selinuxfs_uninstall_slot(struct kasumi_selinuxfs_txn_meta __rcu **slot)
{
	struct kasumi_selinuxfs_txn_meta *m;

	m = rcu_dereference_protected(*slot, lockdep_is_held(&kasumi_selinuxfs_lock));
	if (!m)
		return;

	if (m->inode && READ_ONCE(m->inode->i_fop) == &m->shadow_fop)
		WRITE_ONCE(m->inode->i_fop, m->orig_fop);
	RCU_INIT_POINTER(*slot, NULL);
	call_rcu(&m->rcu, kasumi_selinuxfs_meta_free_rcu);
}

void kasumi_fake_selinuxfs_access_exit(void)
{
	WRITE_ONCE(kasumi_selinuxfs_ready, false);

	spin_lock(&kasumi_selinuxfs_lock);
	kasumi_fake_selinuxfs_uninstall_slot(&kasumi_selinuxfs_access_meta);
	kasumi_fake_selinuxfs_uninstall_slot(&kasumi_selinuxfs_context_meta);
	spin_unlock(&kasumi_selinuxfs_lock);

	rcu_barrier();
	pr_info("Kasumi: fake_selinuxfs exited\n");
}
