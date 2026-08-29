/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - proc read filtering for mountinfo, maps, and statfs spoofing.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/fcntl.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/seq_file.h>
#include <linux/srcu.h>
#include <linux/spinlock.h>
#include <linux/statfs.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/ctype.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/namei.h>
#include <linux/bitops.h>
#include <linux/pid.h>
#include <linux/poll.h>
#include <uapi/linux/magic.h>
#include "kasumi_runtime.h"
#include "kasumi_root_detection.h"
#include "kasumi_store.h"
#include "kasumi_entrypoints.h"
#include "kasumi_path_policy.h"
#include "kasumi_proc_hooks.h"
#include "kasumi_fake_mountinfo.h"
#include "kasumi_vnode.h"

/* ======================================================================
 * /proc mount map hiding: kprobe pre_handler on show_vfsmnt / show_mountinfo
 * Hide overlay mounts so /proc/mounts and /proc/pid/mountinfo show no overlay.
 * Defeats "OverlayFS detected but no overlay in mountinfo" style detectors.
 * ====================================================================== */

static int kasumi_mount_hide_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct vfsmount *mnt;
	struct super_block *sb;
	struct file_system_type *fstype;

	if (!(kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE))
		return 0;
	if (!kasumi_policy_current_is_spoof_target())
		return 0;

#if defined(__aarch64__)
	mnt = (struct vfsmount *)regs->regs[1];
#elif defined(__x86_64__)
	mnt = (struct vfsmount *)regs->si;
#else
	return 0;
#endif
	if (!mnt || !kasumi_valid_kernel_addr((unsigned long)mnt))
		return 0;
	sb = mnt->mnt_sb;
	if (!sb || !kasumi_valid_kernel_addr((unsigned long)sb))
		return 0;
	fstype = sb->s_type;
	if (!fstype || !kasumi_valid_kernel_addr((unsigned long)fstype) || !fstype->name)
		return 0;
	if (strcmp(fstype->name, "overlay") != 0)
		return 0;

	/* Skip this line: do not call original, return 0 */
#if defined(__aarch64__)
	instruction_pointer_set(regs, regs->regs[30]);
	regs->regs[0] = 0;
#elif defined(__x86_64__)
	instruction_pointer_set(regs, *(unsigned long *)regs->sp);
	regs->sp += sizeof(unsigned long);
	regs->ax = 0;
#endif
	return 1;
}

static struct kprobe kasumi_kp_show_vfsmnt = {
	.pre_handler = kasumi_mount_hide_pre,
};
static struct kprobe kasumi_kp_show_mountinfo = {
	.pre_handler = kasumi_mount_hide_pre,
};

#define KASUMI_READ_MOUNT_FILTER_BUF 65536
#define KASUMI_PROC_STREAM_MEMORY_BUDGET (16 * 1024 * 1024)
#define KASUMI_PROC_STREAM_ALLOCATION (KASUMI_READ_MOUNT_FILTER_BUF + 1)
#define KASUMI_PROC_STREAM_MAX (1024 * 1024)

static int kasumi_filter_maps_lines(const char *src, size_t len,
				    char *dst, size_t dst_size, size_t *written,
				    bool *changed, bool *valid,
				    enum kasumi_policy_scope scope);

enum kasumi_proc_proxy_kind {
	KASUMI_PROC_PROXY_NONE = 0,
	KASUMI_PROC_PROXY_MOUNTINFO,
	KASUMI_PROC_PROXY_MOUNTS,
	KASUMI_PROC_PROXY_MAPS,
};

/*
 * Pinned proxy lifecycle:
 *   - .owner = THIS_MODULE makes the VFS hold the module from fops_get() until
 *     __fput() calls fops_put() after ->release. Therefore module exit cannot
 *     race a dispatch that already selected proxy_fops.
 *   - Every install adds the proxy to kasumi_proxy_list under
 *     kasumi_proxy_list_lock. Natural close removes it, runs the original
 *     ->release, and transfers the file's module reference to a static closed
 *     fops before freeing the per-file object. __fput() can then safely call
 *     fops_put(file->f_op) after our ->release returns.
 *   - Module exit can run only after all proxy fds close and their fops_put()
 *     calls drop the module references. No callback into module text is
 *     queued and the proxy list is empty by construction.
 */

#define KASUMI_PROXY_STATE_OPEN      0
#define KASUMI_PROXY_STATE_RELEASED  1

struct kasumi_mount_file_proxy {
	const struct file_operations *orig_fops;
	struct file_operations proxy_fops;
	enum kasumi_proc_proxy_kind kind;
	enum kasumi_policy_scope scope;
	fmode_t orig_f_mode;
	struct list_head node;
	atomic_t state;
	atomic_t filter_invalidated;
	struct mutex stream_lock;
	char *stream_raw;
	size_t stream_raw_capacity;
	char *stream_filtered;
	size_t stream_filtered_capacity;
	size_t stream_raw_len;
	size_t stream_tail_off;
	size_t stream_out_len;
	size_t stream_out_off;
	loff_t stream_orig_pos;
	loff_t stream_user_pos;
	u64 stream_generation;
	bool stream_eof;
	bool stream_failed;
	bool stream_produced;		/* whole-file (MOUNTINFO/MOUNTS) view built once */
};

static LIST_HEAD(kasumi_proxy_list);
static DEFINE_SPINLOCK(kasumi_proxy_list_lock);
DEFINE_STATIC_SRCU(kasumi_proxy_srcu);
static atomic_t kasumi_proxy_shutdown = ATOMIC_INIT(0);
static atomic_t kasumi_proxy_live = ATOMIC_INIT(0);
static atomic_long_t kasumi_stream_memory_used = ATOMIC_LONG_INIT(0);

#define KASUMI_CANONICAL_OBSERVERS 8
struct kasumi_canonical_observer_view {
	struct pid *tgid;
	char *mountinfo;
	size_t mountinfo_len;
	char *mounts;
	size_t mounts_len;
	u64 generation;
	unsigned long last_used;
};

static struct kasumi_canonical_observer_view
	kasumi_canonical_observers[KASUMI_CANONICAL_OBSERVERS];
static DEFINE_MUTEX(kasumi_canonical_observers_lock);

typedef int (*kasumi_proc_mount_show_fn)(struct seq_file *,
					 struct vfsmount *);

/* Stable prefix of fs/mount.h::proc_mounts on Android 12/5.10 through
 * Android 16/6.12.  Older kernels append a cursor; only this prefix is used. */
struct kasumi_proc_mounts_prefix {
	struct mnt_namespace *ns;
	struct path root;
	kasumi_proc_mount_show_fn show;
};

static kasumi_proc_mount_show_fn kasumi_show_mountinfo;
static kasumi_proc_mount_show_fn kasumi_show_vfsmnt;

static struct kprobe kasumi_kp_fd_install;
static bool kasumi_fd_install_registered;
static u32 kasumi_ns_id_seed;
static int kasumi_mount_proxy_install_file(
	struct file *file, enum kasumi_proc_proxy_kind kind,
	enum kasumi_policy_scope scope);

struct kasumi_vfs_readlink_ri_data {
	char __user *buffer;
	int buflen;
	bool candidate;
};

static u32 kasumi_fake_mnt_ns_id(void)
{
	u32 uid = (u32)__kuid_val(current_uid());
	u32 tgid = (u32)task_tgid_vnr(current);
	u32 hash = jhash_2words(uid, tgid, READ_ONCE(kasumi_ns_id_seed));

	/* Keep the synthetic inode in the conventional namespace range and stable
	 * for this process while the module remains loaded.
	 */
	return 0xf0001000U + (hash & 0x0007ffffU);
}

static bool kasumi_current_inherits_root_parent_mnt_ns(void)
{
	struct task_struct *parent;
	struct nsproxy *current_nsproxy = current->nsproxy;
	bool inherited = false;

	if (!kasumi_policy_current_is_isolated() || !current_nsproxy)
		return false;

	rcu_read_lock();
	parent = rcu_dereference(current->real_parent);
	if (parent) {
		task_lock(parent);
		inherited = __kuid_val(task_uid(parent)) == 0 &&
			parent->nsproxy &&
			parent->nsproxy->mnt_ns == current_nsproxy->mnt_ns;
		task_unlock(parent);
	}
	rcu_read_unlock();
	return inherited;
}

static int kasumi_vfs_readlink_entry(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	struct kasumi_vfs_readlink_ri_data *d = (void *)ri->data;
	struct dentry *dentry;

	d->buffer = NULL;
	d->buflen = 0;
	d->candidate = false;

	if (READ_ONCE(kasumi_mount_hide_mode) !=
		    KSM_MOUNT_HIDE_MODE_AGGRESSIVE ||
	    !(READ_ONCE(kasumi_feature_enabled_mask) &
	      KSM_FEATURE_MOUNT_HIDE) ||
	    !kasumi_fake_mi_active() ||
	    !kasumi_policy_current_is_spoof_target() ||
	    !kasumi_current_inherits_root_parent_mnt_ns())
		return 0;

#if defined(__aarch64__)
	dentry = (struct dentry *)regs->regs[0];
	d->buffer = (char __user *)regs->regs[1];
	d->buflen = (int)regs->regs[2];
#elif defined(__x86_64__)
	dentry = (struct dentry *)regs->di;
	d->buffer = (char __user *)regs->si;
	d->buflen = (int)regs->dx;
#else
	return 0;
#endif
	if (!dentry || !dentry->d_sb ||
	    dentry->d_sb->s_magic != PROC_SUPER_MAGIC ||
	    !d->buffer || d->buflen <= 0) {
		d->buffer = NULL;
		return 0;
	}

	d->candidate = true;
	return 0;
}

static KASUMI_NOCFI int kasumi_vfs_readlink_ret(
	struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kasumi_vfs_readlink_ri_data *d = (void *)ri->data;
	char original_prefix[sizeof("mnt:[") - 1];
	char projected[32];
	long ret;
	int len;

	if (!d->candidate || !d->buffer)
		return 0;
#if defined(__aarch64__)
	ret = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret = (long)regs->ax;
#else
	return 0;
#endif
	if (ret < (long)sizeof(original_prefix) ||
	    !kasumi_copy_from_user_nofault || !kasumi_copy_to_user_nofault ||
	    kasumi_copy_from_user_nofault(original_prefix, d->buffer,
					 sizeof(original_prefix)) ||
	    memcmp(original_prefix, "mnt:[", sizeof(original_prefix)) != 0)
		return 0;

	len = scnprintf(projected, sizeof(projected), "mnt:[%u]",
			kasumi_fake_mnt_ns_id());
	len = min(len, d->buflen);
	if (kasumi_copy_to_user_nofault(d->buffer, projected, len))
		ret = -EFAULT;
	else
		ret = len;
#if defined(__aarch64__)
	regs->regs[0] = (unsigned long)ret;
#elif defined(__x86_64__)
	regs->ax = (unsigned long)ret;
#endif
	return 0;
}

static struct kretprobe kasumi_krp_vfs_readlink = {
	.entry_handler = kasumi_vfs_readlink_entry,
	.handler = kasumi_vfs_readlink_ret,
	.data_size = sizeof(struct kasumi_vfs_readlink_ri_data),
	.maxactive = 64,
};

static enum kasumi_proc_proxy_kind
kasumi_proc_proxy_kind_for_file(struct file *file,
				enum kasumi_policy_scope *scope_out)
{
	const struct qstr *name;
	enum kasumi_policy_scope scope;
	bool spoof;

	if (!file || !file->f_path.dentry || !file->f_inode ||
	    !file->f_inode->i_sb || file->f_inode->i_sb->s_magic != PROC_SUPER_MAGIC)
		return KASUMI_PROC_PROXY_NONE;

	scope = kasumi_policy_current_scope();
	if (scope_out)
		*scope_out = scope;
	spoof = scope == KASUMI_POLICY_SCOPE_SPOOF;
	if (scope == KASUMI_POLICY_SCOPE_NONE)
		return KASUMI_PROC_PROXY_NONE;

	name = &file->f_path.dentry->d_name;
	if (spoof && (kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE) &&
	    ((name->len == 9 && !memcmp(name->name, "mountinfo", 9)) ||
	     (name->len == 6 && !memcmp(name->name, "mounts", 6)))) {
		return name->len == 9 ? KASUMI_PROC_PROXY_MOUNTINFO :
			KASUMI_PROC_PROXY_MOUNTS;
	}
	if ((spoof && (kasumi_feature_enabled_mask & KSM_FEATURE_MAPS_SPOOF)) &&
	    ((name->len == 4 && !memcmp(name->name, "maps", 4)) ||
	     (name->len == 5 && !memcmp(name->name, "smaps", 5)) ||
	     (name->len == 12 && !memcmp(name->name, "smaps_rollup", 12))))
		return KASUMI_PROC_PROXY_MAPS;
	return KASUMI_PROC_PROXY_NONE;
}

static int kasumi_fd_install_pre(struct kprobe *kp, struct pt_regs *regs)
{
	enum kasumi_proc_proxy_kind kind;
	enum kasumi_policy_scope scope;
	struct file *file;

	(void)kp;
#if defined(__aarch64__)
	file = (struct file *)regs->regs[1];
#elif defined(__x86_64__)
	file = (struct file *)regs->si;
#else
	return 0;
#endif
	if (!READ_ONCE(kasumi_enabled))
		return 0;
	if (kasumi_fake_mi_is_internal_read())
		return 0;
	/* fd_install normally receives a private, freshly opened file. Refuse an
	 * already-shared object rather than replacing f_op for other holders.
	 */
	if (file_count(file) != 1)
		return 0;
	kind = kasumi_proc_proxy_kind_for_file(file, &scope);
	if (kind == KASUMI_PROC_PROXY_NONE)
		return 0;
	/* fd_install has not published this freshly opened file yet. Installing
	 * its proxy here avoids an fd-reuse window and needs no sleeping path
	 * lookup; procfs magic plus the final dentry name already identify every
	 * supported view.
	 */
	(void)kasumi_mount_proxy_install_file(file, kind, scope);
	return 0;
}

/* __fput() dereferences file->f_op after ->release returns. The live proxy's
 * owner reference is transferred to this permanent fops object while the
 * per-file proxy is reclaimed.
 */
static const struct file_operations kasumi_closed_proxy_fops = {
	.owner = THIS_MODULE,
};

static bool kasumi_mount_proxy_filter_active(
	struct kasumi_mount_file_proxy *proxy)
{
	enum kasumi_policy_scope scope = kasumi_policy_current_scope();
	bool active = false;

	if (atomic_read(&proxy->filter_invalidated))
		return false;
	if (!READ_ONCE(kasumi_enabled) || scope != proxy->scope)
		goto invalidate;
	if (proxy->kind == KASUMI_PROC_PROXY_MOUNTINFO ||
	    proxy->kind == KASUMI_PROC_PROXY_MOUNTS)
		active = scope == KASUMI_POLICY_SCOPE_SPOOF &&
			 (kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE);
	else if (proxy->kind == KASUMI_PROC_PROXY_MAPS)
		active = scope == KASUMI_POLICY_SCOPE_SPOOF &&
			 (kasumi_feature_enabled_mask & KSM_FEATURE_MAPS_SPOOF);
	if (active)
		return true;

invalidate:
	atomic_set(&proxy->filter_invalidated, 1);
	return false;
}

static KASUMI_NOCFI ssize_t kasumi_mount_proxy_orig_read_iter(
	struct kasumi_mount_file_proxy *proxy, struct kiocb *iocb,
	struct iov_iter *to)
{
	if (proxy->orig_fops->read_iter)
		return proxy->orig_fops->read_iter(iocb, to);

	/* maps/smaps used ->read = seq_read on older kernels. All proc views
	 * proxied here are seq_files, so seq_read_iter is the safe kernel-buffer
	 * equivalent and avoids ever placing unfiltered bytes in userspace.
	 */
	return kasumi_seq_read_iter(iocb, to);
}

static bool kasumi_mount_proxy_stream_reserve(size_t bytes)
{
	long used;

	used = atomic_long_add_return(bytes,
				      &kasumi_stream_memory_used);
	if (used <= KASUMI_PROC_STREAM_MEMORY_BUDGET)
		return true;
	atomic_long_sub(bytes, &kasumi_stream_memory_used);
	return false;
}

static void kasumi_mount_proxy_stream_free(
	struct kasumi_mount_file_proxy *proxy)
{
	if (!proxy->stream_raw)
		goto free_filtered;
	kvfree(proxy->stream_raw);
	atomic_long_sub(proxy->stream_raw_capacity,
			&kasumi_stream_memory_used);
	proxy->stream_raw = NULL;
	proxy->stream_raw_capacity = 0;

free_filtered:
	if (!proxy->stream_filtered)
		return;
	kvfree(proxy->stream_filtered);
	atomic_long_sub(proxy->stream_filtered_capacity,
			&kasumi_stream_memory_used);
	proxy->stream_filtered = NULL;
	proxy->stream_filtered_capacity = 0;
}

static int kasumi_mount_proxy_stream_alloc(
	struct kasumi_mount_file_proxy *proxy)
{
	char *raw;

	if (proxy->stream_raw)
		return 0;
	if (!kasumi_mount_proxy_stream_reserve(KASUMI_PROC_STREAM_ALLOCATION))
		return -ENOMEM;
	raw = kvmalloc(KASUMI_PROC_STREAM_ALLOCATION, GFP_KERNEL);
	if (!raw)
		goto out_unreserve;
	proxy->stream_raw = raw;
	proxy->stream_raw_capacity = KASUMI_PROC_STREAM_ALLOCATION;
	return 0;

out_unreserve:
	atomic_long_sub(KASUMI_PROC_STREAM_ALLOCATION,
			&kasumi_stream_memory_used);
	return -ENOMEM;
}

static int kasumi_mount_proxy_stream_grow_raw(
	struct kasumi_mount_file_proxy *proxy)
{
	char *raw;
	size_t old_capacity = proxy->stream_raw_capacity;
	size_t new_capacity;
	size_t delta;

	if (old_capacity >= KASUMI_PROC_STREAM_MAX)
		return -EFBIG;
	new_capacity = min_t(size_t, old_capacity * 2,
				    KASUMI_PROC_STREAM_MAX);
	delta = new_capacity - old_capacity;
	if (!kasumi_mount_proxy_stream_reserve(delta))
		return -ENOMEM;
	raw = kvmalloc(new_capacity, GFP_KERNEL);
	if (!raw) {
		atomic_long_sub(delta, &kasumi_stream_memory_used);
		return -ENOMEM;
	}
	memcpy(raw, proxy->stream_raw, proxy->stream_raw_len);
	kvfree(proxy->stream_raw);
	proxy->stream_raw = raw;
	proxy->stream_raw_capacity = new_capacity;
	return 0;
}

static int kasumi_mount_proxy_stream_alloc_filtered(
	struct kasumi_mount_file_proxy *proxy)
{
	char *filtered;

	if (proxy->stream_filtered)
		return 0;
	if (!kasumi_mount_proxy_stream_reserve(KASUMI_PROC_STREAM_ALLOCATION))
		return -ENOMEM;
	filtered = kvmalloc(KASUMI_PROC_STREAM_ALLOCATION, GFP_KERNEL);
	if (!filtered) {
		atomic_long_sub(KASUMI_PROC_STREAM_ALLOCATION,
				&kasumi_stream_memory_used);
		return -ENOMEM;
	}
	proxy->stream_filtered = filtered;
	proxy->stream_filtered_capacity = KASUMI_PROC_STREAM_ALLOCATION;
	return 0;
}

static int kasumi_mount_proxy_stream_grow_filtered(
	struct kasumi_mount_file_proxy *proxy)
{
	char *filtered;
	size_t old_capacity = proxy->stream_filtered_capacity;
	size_t new_capacity;
	size_t delta;

	if (old_capacity >= KASUMI_PROC_STREAM_MAX)
		return -ENOSPC;
	new_capacity = min_t(size_t, old_capacity * 2,
				    KASUMI_PROC_STREAM_MAX);
	delta = new_capacity - old_capacity;
	if (!kasumi_mount_proxy_stream_reserve(delta))
		return -ENOMEM;
	filtered = kvmalloc(new_capacity, GFP_KERNEL);
	if (!filtered) {
		atomic_long_sub(delta, &kasumi_stream_memory_used);
		return -ENOMEM;
	}
	kvfree(proxy->stream_filtered);
	proxy->stream_filtered = filtered;
	proxy->stream_filtered_capacity = new_capacity;
	return 0;
}

static void kasumi_mount_proxy_stream_compact(
	struct kasumi_mount_file_proxy *proxy)
{
	size_t tail_len;

	if (!proxy->stream_out_len)
		return;
	tail_len = proxy->stream_raw_len - proxy->stream_tail_off;
	if (tail_len)
		memmove(proxy->stream_raw,
			proxy->stream_raw + proxy->stream_tail_off, tail_len);
	proxy->stream_raw_len = tail_len;
	proxy->stream_tail_off = 0;
	proxy->stream_out_len = 0;
	proxy->stream_out_off = 0;
}

static ssize_t kasumi_mount_proxy_stream_fill(
	struct kasumi_mount_file_proxy *proxy, struct file *file)
{
	struct kiocb shadow_iocb;
	struct iov_iter kernel_iter;
	struct kvec kvec;
	size_t complete_len;
	size_t tail_len;
	size_t new_len;
	bool maps_changed;
	bool maps_valid;
	ssize_t ret;

	for (;;) {
		kasumi_mount_proxy_stream_compact(proxy);
		complete_len = proxy->stream_raw_len;
		while (complete_len > 0 &&
		       proxy->stream_raw[complete_len - 1] != '\n')
			complete_len--;

		if (complete_len > 0) {
			if (proxy->kind == KASUMI_PROC_PROXY_MAPS) {
				ret = kasumi_mount_proxy_stream_alloc_filtered(proxy);
				if (ret)
					return ret;
				for (;;) {
					maps_changed = false;
					maps_valid = true;
					ret = kasumi_filter_maps_lines(
						proxy->stream_raw, complete_len,
						proxy->stream_filtered,
						proxy->stream_filtered_capacity,
						&new_len, &maps_changed, &maps_valid,
						proxy->scope);
					if (ret != -ENOSPC)
						break;
					ret = kasumi_mount_proxy_stream_grow_filtered(proxy);
					if (ret)
						return ret;
				}
				if (ret < 0 || !maps_valid)
					return ret < 0 ? ret : -EIO;
			} else {
				/* MOUNTINFO/MOUNTS are served whole-file via
				 * kasumi_mount_proxy_serve_whole(); only MAPS uses
				 * this incremental line-chunk path. */
				return -EIO;
			}

			tail_len = proxy->stream_raw_len - complete_len;
			proxy->stream_tail_off = complete_len;
			proxy->stream_out_off = 0;
			proxy->stream_out_len = new_len;
			if (new_len)
				return 1;
			if (tail_len)
				memmove(proxy->stream_raw,
					proxy->stream_raw + complete_len, tail_len);
			proxy->stream_raw_len = tail_len;
			proxy->stream_tail_off = 0;
			continue;
		}

		if (proxy->stream_eof)
			return proxy->stream_raw_len ? -EIO : 0;
		if (proxy->stream_raw_len + 1 >= proxy->stream_raw_capacity) {
			ret = kasumi_mount_proxy_stream_grow_raw(proxy);
			if (ret)
				return ret;
		}

		kvec.iov_base = proxy->stream_raw + proxy->stream_raw_len;
		kvec.iov_len = proxy->stream_raw_capacity - 1 -
			proxy->stream_raw_len;
		iov_iter_kvec(&kernel_iter, READ, &kvec, 1, kvec.iov_len);
		init_sync_kiocb(&shadow_iocb, file);
		shadow_iocb.ki_pos = proxy->stream_orig_pos;
		ret = kasumi_mount_proxy_orig_read_iter(proxy, &shadow_iocb,
							 &kernel_iter);
		if (ret < 0)
			return ret;
		if (!ret) {
			proxy->stream_eof = true;
			continue;
		}
		if ((size_t)ret > kvec.iov_len)
			return -EIO;
		proxy->stream_raw_len += (size_t)ret;
		proxy->stream_orig_pos = shadow_iocb.ki_pos;
		proxy->stream_raw[proxy->stream_raw_len] = '\0';
	}
}

/* Read the proxied file's ORIGINAL producer whole into stream_raw. The proxied
 * struct file keeps its original seq producer (install swaps only f_op/f_mode),
 * bound to the TARGET pid's mnt_ns at open, so this yields the TARGET's real
 * table. Process/sleepable context (called from the proxy ->read/->read_iter). */
static int kasumi_mount_proxy_slurp_orig(
	struct kasumi_mount_file_proxy *proxy, struct file *file)
{
	struct kvec kvec;
	struct iov_iter kernel_iter;
	struct kiocb shadow_iocb;
	ssize_t r;
	int ret;

	for (;;) {
		if (proxy->stream_raw_len + 1 >= proxy->stream_raw_capacity) {
			ret = kasumi_mount_proxy_stream_grow_raw(proxy);
			if (ret)
				return ret;
		}
		kvec.iov_base = proxy->stream_raw + proxy->stream_raw_len;
		kvec.iov_len = proxy->stream_raw_capacity - 1 -
			       proxy->stream_raw_len;
		iov_iter_kvec(&kernel_iter, READ, &kvec, 1, kvec.iov_len);
		init_sync_kiocb(&shadow_iocb, file);
		shadow_iocb.ki_pos = proxy->stream_orig_pos;
		r = kasumi_mount_proxy_orig_read_iter(proxy, &shadow_iocb,
						      &kernel_iter);
		if (r < 0)
			return (int)r;
		if (r == 0)
			break;
		if ((size_t)r > kvec.iov_len)
			return -EIO;
		proxy->stream_raw_len += (size_t)r;
		proxy->stream_orig_pos = shadow_iocb.ki_pos;
		proxy->stream_raw[proxy->stream_raw_len] = '\0';
	}
	return 0;
}

static struct kasumi_proc_mounts_prefix *
kasumi_mount_proxy_proc_mounts(struct file *file)
{
	struct seq_file *seq;
	struct kasumi_proc_mounts_prefix *p;

	if (!file || !file->private_data || !kasumi_show_mountinfo ||
	    !kasumi_show_vfsmnt)
		return NULL;
	seq = file->private_data;
	p = seq->private;
	if (!p || !p->ns || !p->root.dentry || !p->root.mnt || !p->show)
		return NULL;
	if (p->show != kasumi_show_mountinfo && p->show != kasumi_show_vfsmnt)
		return NULL;
	return p;
}

static int kasumi_mount_proxy_reset_seq(
	struct kasumi_mount_file_proxy *proxy, struct file *file,
	kasumi_proc_mount_show_fn show)
{
	struct kasumi_proc_mounts_prefix *p;
	loff_t ret;

	p = kasumi_mount_proxy_proc_mounts(file);
	if (!p || !show || !proxy->orig_fops->llseek)
		return -EOPNOTSUPP;
	WRITE_ONCE(p->show, show);
	ret = proxy->orig_fops->llseek(file, 0, SEEK_SET);
	if (ret < 0)
		return (int)ret;
	proxy->stream_orig_pos = 0;
	proxy->stream_raw_len = 0;
	return 0;
}

static int kasumi_mount_proxy_restore_seq(
	struct kasumi_mount_file_proxy *proxy, struct file *file,
	kasumi_proc_mount_show_fn show)
{
	struct kasumi_proc_mounts_prefix *p;
	loff_t ret;

	p = kasumi_mount_proxy_proc_mounts(file);
	if (!p || !show || !proxy->orig_fops->llseek)
		return -EOPNOTSUPP;
	WRITE_ONCE(p->show, show);
	ret = proxy->orig_fops->llseek(file, 0, SEEK_SET);
	if (ret < 0)
		return (int)ret;
	proxy->stream_orig_pos = 0;
	return 0;
}

static size_t kasumi_mount_proxy_line_count(const char *buf, size_t len)
{
	size_t count = 0;
	size_t i;

	for (i = 0; i < len; i++)
		if (buf[i] == '\n')
			count++;
	if (len && buf[len - 1] != '\n')
		count++;
	return count;
}

static bool kasumi_mount_proxy_line_token(const char *line, size_t len,
					  unsigned int ordinal,
					  const char **token,
					  size_t *token_len)
{
	size_t pos = 0;
	unsigned int token_index = 0;

	if (!line || !token || !token_len)
		return false;
	while (pos < len) {
		size_t start;

		while (pos < len && line[pos] == ' ')
			pos++;
		if (pos >= len)
			break;
		start = pos;
		while (pos < len && line[pos] != ' ')
			pos++;
		if (token_index++ == ordinal) {
			*token = line + start;
			*token_len = pos - start;
			return true;
		}
	}
	return false;
}

/* mountinfo's fifth token and mounts' second token are the same escaped
 * mountpoint.  Comparing them by ordinal closes the residual window where a
 * topology reorder preserves the line count between the two seq snapshots. */
static bool kasumi_mount_proxy_pair_mountpoints_match(
	const char *mountinfo, size_t mountinfo_len,
	const char *mounts, size_t mounts_len)
{
	size_t mi_pos = 0;
	size_t mounts_pos = 0;

	while (mi_pos < mountinfo_len && mounts_pos < mounts_len) {
		const char *mi_target;
		const char *mounts_target;
		size_t mi_line_start = mi_pos;
		size_t mounts_line_start = mounts_pos;
		size_t mi_target_len;
		size_t mounts_target_len;

		while (mi_pos < mountinfo_len && mountinfo[mi_pos] != '\n')
			mi_pos++;
		while (mounts_pos < mounts_len && mounts[mounts_pos] != '\n')
			mounts_pos++;
		if (!kasumi_mount_proxy_line_token(
				mountinfo + mi_line_start, mi_pos - mi_line_start,
				4, &mi_target, &mi_target_len) ||
		    !kasumi_mount_proxy_line_token(
				mounts + mounts_line_start,
				mounts_pos - mounts_line_start,
				1, &mounts_target, &mounts_target_len) ||
		    mi_target_len != mounts_target_len ||
		    memcmp(mi_target, mounts_target, mi_target_len))
			return false;
		if (mi_pos < mountinfo_len)
			mi_pos++;
		if (mounts_pos < mounts_len)
			mounts_pos++;
	}
	return mi_pos == mountinfo_len && mounts_pos == mounts_len;
}

static int kasumi_filter_mounts_by_ordinal(char *buf, size_t len,
					   const unsigned long *visible,
					   size_t expected_lines,
					   size_t *out_len)
{
	size_t in = 0;
	size_t out = 0;
	size_t ordinal = 0;

	if (!buf || !visible || !out_len)
		return -EINVAL;
	while (in < len) {
		size_t line_start = in;
		size_t line_len;
		bool has_nl;

		while (in < len && buf[in] != '\n')
			in++;
		line_len = in - line_start;
		has_nl = in < len;
		if (ordinal >= expected_lines)
			return -EAGAIN;
		if (test_bit(ordinal, visible)) {
			if (out != line_start)
				memmove(buf + out, buf + line_start, line_len);
			out += line_len;
			if (has_nl)
				buf[out++] = '\n';
		}
		ordinal++;
		if (has_nl)
			in++;
	}
	if (ordinal != expected_lines)
		return -EAGAIN;
	*out_len = out;
	return 0;
}

static void kasumi_canonical_observer_release(
	struct kasumi_canonical_observer_view *view)
{
	if (view->mountinfo) {
		kvfree(view->mountinfo);
		atomic_long_sub(view->mountinfo_len,
				&kasumi_stream_memory_used);
	}
	if (view->mounts) {
		kvfree(view->mounts);
		atomic_long_sub(view->mounts_len,
				&kasumi_stream_memory_used);
	}
	if (view->tgid)
		put_pid(view->tgid);
	memset(view, 0, sizeof(*view));
}

/* Pin one canonical mountinfo/mounts pair to the observer process, not to the
 * /proc/<pid> target. Cross-PID readers can otherwise compare private mount
 * topologies after the root-owned lines have been removed and infer exactly
 * which processes had hidden mounts. Both renderings must move together or a
 * detector can instead compare the two proc formats for the same target. */
static int kasumi_mount_proxy_canonicalize_observer(
	struct kasumi_mount_file_proxy *proxy, size_t *mountinfo_len,
	size_t *mounts_len)
{
	struct kasumi_canonical_observer_view *view = NULL;
	struct kasumi_canonical_observer_view *victim = NULL;
	struct pid *owner = task_tgid(current);
	unsigned long oldest = ULONG_MAX;
	u64 generation = kasumi_fake_mi_generation();
	char *mountinfo_copy;
	char *mounts_copy;
	size_t reserve_len;
	int i;
	int ret = 0;

	if (!proxy || !proxy->stream_filtered || !proxy->stream_raw ||
	    !mountinfo_len || !*mountinfo_len || !mounts_len || !*mounts_len ||
	    !owner || check_add_overflow(*mountinfo_len, *mounts_len,
					   &reserve_len))
		return -EINVAL;

	mutex_lock(&kasumi_canonical_observers_lock);
	for (i = 0; i < KASUMI_CANONICAL_OBSERVERS; i++) {
		struct kasumi_canonical_observer_view *candidate =
			&kasumi_canonical_observers[i];

		if (candidate->tgid == owner &&
		    candidate->generation == generation) {
			view = candidate;
			break;
		}
		if (!candidate->tgid) {
			victim = candidate;
			break;
		} else if (!victim ||
			   time_before(candidate->last_used, oldest)) {
			victim = candidate;
			oldest = candidate->last_used;
		}
	}

	if (view) {
		while (proxy->stream_filtered_capacity < view->mountinfo_len) {
			ret = kasumi_mount_proxy_stream_grow_filtered(proxy);
			if (ret)
				goto out_unlock;
		}
		while (proxy->stream_raw_capacity < view->mounts_len) {
			ret = kasumi_mount_proxy_stream_grow_raw(proxy);
			if (ret)
				goto out_unlock;
		}
		memcpy(proxy->stream_filtered, view->mountinfo,
		       view->mountinfo_len);
		memcpy(proxy->stream_raw, view->mounts, view->mounts_len);
		*mountinfo_len = view->mountinfo_len;
		*mounts_len = view->mounts_len;
		view->last_used = jiffies;
		goto out_unlock;
	}

	if (!victim) {
		ret = -ENOMEM;
		goto out_unlock;
	}
	if (!kasumi_mount_proxy_stream_reserve(reserve_len)) {
		ret = -ENOMEM;
		goto out_unlock;
	}
	mountinfo_copy = kvmalloc(*mountinfo_len, GFP_KERNEL);
	mounts_copy = kvmalloc(*mounts_len, GFP_KERNEL);
	if (!mountinfo_copy || !mounts_copy) {
		kvfree(mountinfo_copy);
		kvfree(mounts_copy);
		atomic_long_sub(reserve_len, &kasumi_stream_memory_used);
		ret = -ENOMEM;
		goto out_unlock;
	}
	memcpy(mountinfo_copy, proxy->stream_filtered, *mountinfo_len);
	memcpy(mounts_copy, proxy->stream_raw, *mounts_len);
	kasumi_canonical_observer_release(victim);
	victim->tgid = get_pid(owner);
	victim->mountinfo = mountinfo_copy;
	victim->mountinfo_len = *mountinfo_len;
	victim->mounts = mounts_copy;
	victim->mounts_len = *mounts_len;
	victim->generation = generation;
	victim->last_used = jiffies;

out_unlock:
	mutex_unlock(&kasumi_canonical_observers_lock);
	return ret;
}

static void kasumi_canonical_observers_clear(void)
{
	int i;

	mutex_lock(&kasumi_canonical_observers_lock);
	for (i = 0; i < KASUMI_CANONICAL_OBSERVERS; i++)
		kasumi_canonical_observer_release(
			&kasumi_canonical_observers[i]);
	mutex_unlock(&kasumi_canonical_observers_lock);
}

/*
 * Produce the whole TARGET-ns filtered view exactly once (latched by
 * stream_produced). MOUNTINFO: classify+renumber the target's real 11-field
 * mountinfo into stream_filtered (served from there). MOUNTS: build the
 * target's filtered mountinfo into stream_filtered as the visible-set oracle,
 * then drop from the target's real mounts (stream_raw, in place) exactly the
 * mountpoints hidden there — so mounts == mountinfo by construction (served
 * from stream_raw). Fails closed — on any error the proxy is marked failed and
 * returns an errno; it never serves real (unhidden) bytes.
 */
static int kasumi_mount_proxy_produce_whole(
	struct kasumi_mount_file_proxy *proxy, struct file *file)
{
	struct kasumi_proc_mounts_prefix *pm;
	kasumi_proc_mount_show_fn orig_show;
	u64 production_generation;
	u64 published_generation = 0;
	int ret;

	if (proxy->stream_produced)
		return 0;
	if (proxy->stream_failed)
		return -EIO;
	production_generation = kasumi_fake_mi_generation();

	ret = kasumi_mount_proxy_stream_alloc_filtered(proxy);
	if (ret)
		goto fail;
	pm = kasumi_mount_proxy_proc_mounts(file);
	if (!pm) {
		ret = -EOPNOTSUPP;
		goto fail;
	}
	orig_show = READ_ONCE(pm->show);

	if (proxy->kind == KASUMI_PROC_PROXY_MOUNTINFO ||
	    proxy->kind == KASUMI_PROC_PROXY_MOUNTS) {
		struct seq_file *seq = file->private_data;
		unsigned long *visible = NULL;
		char *pair_mountinfo = NULL;
		size_t pair_mountinfo_len = 0;
		size_t visible_bits = 0;
		size_t mi_len = 0;
		size_t mounts_len = 0;
		int attempt;

		if ((proxy->kind == KASUMI_PROC_PROXY_MOUNTINFO &&
		     orig_show != kasumi_show_mountinfo) ||
		    (proxy->kind == KASUMI_PROC_PROXY_MOUNTS &&
		     orig_show != kasumi_show_vfsmnt)) {
			ret = -EIO;
			goto fail;
		}
		ret = -EAGAIN;
		for (attempt = 0; attempt < 3 && ret == -EAGAIN; attempt++) {
			size_t raw_lines;
			size_t built_lines = 0;
			unsigned long event_before;

			kvfree(visible);
			visible = NULL;
			if (pair_mountinfo) {
				kvfree(pair_mountinfo);
				atomic_long_sub(pair_mountinfo_len,
						&kasumi_stream_memory_used);
				pair_mountinfo = NULL;
				pair_mountinfo_len = 0;
			}
			proxy->stream_out_len = 0;
			mi_len = 0;
			mounts_len = 0;
			if (proxy->orig_fops->poll)
				(void)proxy->orig_fops->poll(file, NULL);
			event_before = READ_ONCE(seq->poll_event);

			ret = kasumi_mount_proxy_reset_seq(
				proxy, file, kasumi_show_mountinfo);
			if (ret)
				break;
			ret = kasumi_mount_proxy_slurp_orig(proxy, file);
			if (ret)
				break;
			raw_lines = kasumi_mount_proxy_line_count(
				proxy->stream_raw, proxy->stream_raw_len);
			if (!raw_lines) {
				ret = -EIO;
				break;
			}
			visible_bits = raw_lines;
			visible = kvcalloc(BITS_TO_LONGS(visible_bits),
					   sizeof(*visible), GFP_KERNEL);
			if (!visible) {
				ret = -ENOMEM;
				break;
			}
			for (;;) {
				ret = kasumi_fake_mi_build_from_raw_visible(
					proxy->stream_raw, proxy->stream_raw_len,
					proxy->stream_filtered,
					proxy->stream_filtered_capacity, &mi_len,
					visible, visible_bits, &built_lines);
				if (ret != -ENOSPC)
					break;
				ret = kasumi_mount_proxy_stream_grow_filtered(proxy);
				if (ret)
					break;
			}
			if (ret)
				break;
			if (built_lines != raw_lines) {
				ret = -EAGAIN;
				continue;
			}
			pair_mountinfo_len = proxy->stream_raw_len;
			if (!kasumi_mount_proxy_stream_reserve(pair_mountinfo_len)) {
				ret = -ENOMEM;
				break;
			}
			pair_mountinfo = kvmalloc(pair_mountinfo_len, GFP_KERNEL);
			if (!pair_mountinfo) {
				atomic_long_sub(pair_mountinfo_len,
						&kasumi_stream_memory_used);
				pair_mountinfo_len = 0;
				ret = -ENOMEM;
				break;
			}
			memcpy(pair_mountinfo, proxy->stream_raw, pair_mountinfo_len);

			ret = kasumi_mount_proxy_reset_seq(
				proxy, file, kasumi_show_vfsmnt);
			if (ret)
				break;
			ret = kasumi_mount_proxy_slurp_orig(proxy, file);
			if (ret)
				break;
			if (proxy->orig_fops->poll)
				(void)proxy->orig_fops->poll(file, NULL);
			if (event_before != READ_ONCE(seq->poll_event)) {
				ret = -EAGAIN;
				continue;
			}
			if (!kasumi_mount_proxy_pair_mountpoints_match(
					pair_mountinfo, pair_mountinfo_len,
					proxy->stream_raw,
					proxy->stream_raw_len)) {
				ret = -EAGAIN;
				continue;
			}
			ret = kasumi_filter_mounts_by_ordinal(
				proxy->stream_raw, proxy->stream_raw_len,
				visible, built_lines, &mounts_len);
			if (!ret) {
				proxy->stream_raw_len = mounts_len;
				proxy->stream_out_len = mounts_len;
				ret = kasumi_fake_mi_publish_current_snapshot(
					pair_mountinfo, pair_mountinfo_len,
					proxy->stream_filtered, mi_len,
					pm->ns, &pm->root,
					&published_generation);
			}
		}
		kvfree(visible);
		if (pair_mountinfo) {
			kvfree(pair_mountinfo);
			atomic_long_sub(pair_mountinfo_len,
					&kasumi_stream_memory_used);
		}
		if (ret)
			goto fail_restore;
		ret = kasumi_mount_proxy_canonicalize_observer(
			proxy, &mi_len, &mounts_len);
		if (ret)
			goto fail_restore;
		proxy->stream_raw_len = mounts_len;
		proxy->stream_out_len =
			proxy->kind == KASUMI_PROC_PROXY_MOUNTINFO ?
			mi_len : mounts_len;
	} else {
		ret = -EIO;
		goto fail_restore;
	}

	ret = kasumi_mount_proxy_restore_seq(proxy, file, orig_show);
	if (ret)
		goto fail;
	proxy->stream_out_off = 0;
	/* A publisher returns the generation of the exact cache commit it made.
	 * Non-current open-bound views never publish, so retain the generation from
	 * before production and let poll expose any concurrent invalidation.
	 */
	WRITE_ONCE(proxy->stream_generation, published_generation ?
		   published_generation : production_generation);
	/* Publish the completed bytes/generation before poll can treat this stream
	 * as produced. If invalidation woke waiters before this flag became visible,
	 * close that lost-wakeup window explicitly after publication.
	 */
	smp_store_release(&proxy->stream_produced, true);
	if (READ_ONCE(proxy->stream_generation) !=
	    kasumi_fake_mi_generation())
		kasumi_fake_mi_poll_wake();
	kasumi_log("mount_proxy: produced kind=%d pid=%d raw=%zu out=%zu\n",
		 proxy->kind, task_pid_nr(current), proxy->stream_raw_len,
		 proxy->stream_out_len);
	return 0;

fail_restore:
	(void)kasumi_mount_proxy_restore_seq(proxy, file, orig_show);
fail:
	proxy->stream_failed = true;
	return ret < 0 ? ret : -EIO;
}

/* Serve sequential chunks from the once-produced whole-file stream_filtered,
 * for both ->read (userbuf) and ->read_iter (to). */
static ssize_t kasumi_mount_proxy_serve_whole(
	struct kasumi_mount_file_proxy *proxy, struct file *file,
	char __user *userbuf, struct iov_iter *to, size_t count, loff_t *ppos)
{
	const char *outbuf;
	size_t available;
	size_t copied;
	ssize_t ret;

	if (!ppos || *ppos < 0)
		return -EINVAL;
	if (!count)
		return 0;

	/* Keep the reader-ns g_cache fresh for the atomic consumers (cp_statx
	 * mnt_id projection etc.), preserving the side effect the old
	 * fake_mi_serve/mounts-prepare path had. Sleepable; outside stream_lock. */
	kasumi_fake_mi_prepare(false);

	mutex_lock(&proxy->stream_lock);
	if (proxy->stream_failed || *ppos != proxy->stream_user_pos) {
		proxy->stream_failed = true;
		ret = -EIO;
		goto out_unlock;
	}
	ret = kasumi_mount_proxy_stream_alloc(proxy);
	if (ret) {
		proxy->stream_failed = true;
		goto out_unlock;
	}
	ret = kasumi_mount_proxy_produce_whole(proxy, file);
	if (ret)
		goto out_unlock;
	if (proxy->stream_out_off >= proxy->stream_out_len) {
		ret = 0;			/* EOF */
		goto out_unlock;
	}
	/* MOUNTINFO is built into stream_filtered; MOUNTS is filtered in place in
	 * stream_raw (the kernel's real /proc/mounts bytes, minus hidden lines). */
	outbuf = (proxy->kind == KASUMI_PROC_PROXY_MOUNTINFO) ?
		proxy->stream_filtered : proxy->stream_raw;
	available = min_t(size_t, count,
			  proxy->stream_out_len - proxy->stream_out_off);
	if (to)
		copied = copy_to_iter(outbuf + proxy->stream_out_off,
				      available, to);
	else
		copied = available - copy_to_user(
			userbuf, outbuf + proxy->stream_out_off, available);
	if (!copied) {
		ret = -EFAULT;
		goto out_unlock;
	}
	proxy->stream_out_off += copied;
	proxy->stream_user_pos += copied;
	*ppos = proxy->stream_user_pos;
	ret = (ssize_t)copied;

out_unlock:
	mutex_unlock(&proxy->stream_lock);
	return ret;
}

static ssize_t kasumi_mount_proxy_filtered_read(
	struct kasumi_mount_file_proxy *proxy, struct file *file,
	char __user *userbuf, struct iov_iter *to, size_t count, loff_t *ppos)
{
	const char *outbuf;
	size_t available;
	size_t copied;
	ssize_t ret;

	if (!ppos || *ppos < 0)
		return -EINVAL;
	if (!count)
		return 0;
	mutex_lock(&proxy->stream_lock);
	if (proxy->stream_failed || *ppos != proxy->stream_user_pos) {
		ret = -EIO;
		goto out_unlock;
	}
	ret = kasumi_mount_proxy_stream_alloc(proxy);
	if (ret) {
		proxy->stream_failed = true;
		goto out_unlock;
	}

	while (proxy->stream_out_off == proxy->stream_out_len) {
		ret = kasumi_mount_proxy_stream_fill(proxy, file);
		if (ret <= 0)
			goto out_fail;
	}
	outbuf = proxy->kind == KASUMI_PROC_PROXY_MAPS ?
		proxy->stream_filtered : proxy->stream_raw;
	if (!outbuf) {
		ret = -EIO;
		goto out_fail;
	}
	available = min_t(size_t, count,
			  proxy->stream_out_len - proxy->stream_out_off);
	if (to)
		copied = copy_to_iter(outbuf + proxy->stream_out_off,
				      available, to);
	else
		copied = available - copy_to_user(
			userbuf, outbuf + proxy->stream_out_off, available);
	if (!copied) {
		ret = -EFAULT;
		goto out_unlock;
	}
	proxy->stream_out_off += copied;
	proxy->stream_user_pos += copied;
	*ppos = proxy->stream_user_pos;
	ret = (ssize_t)copied;
	goto out_unlock;

out_fail:
	if (ret < 0)
		proxy->stream_failed = true;

out_unlock:
	mutex_unlock(&proxy->stream_lock);
	return ret;
}

static ssize_t kasumi_mount_proxy_read(struct file *file, char __user *buf,
					 size_t count, loff_t *ppos)
{
	struct kasumi_mount_file_proxy *proxy =
		container_of(file->f_op, struct kasumi_mount_file_proxy, proxy_fops);
	ssize_t ret;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&kasumi_proxy_srcu);
	if (!kasumi_mount_proxy_filter_active(proxy)) {
		ret = -EIO;
		goto out;
	}

	if (proxy->kind == KASUMI_PROC_PROXY_MOUNTINFO ||
	    proxy->kind == KASUMI_PROC_PROXY_MOUNTS) {
		loff_t *posp = ppos ? ppos : &file->f_pos;

		ret = kasumi_mount_proxy_serve_whole(proxy, file, buf, NULL,
						     count, posp);
		/* An active fake view never falls back to the real table. */
		goto out;
	}

	if (proxy->kind == KASUMI_PROC_PROXY_MAPS) {
		loff_t *posp = ppos ? ppos : &file->f_pos;

		ret = kasumi_mount_proxy_filtered_read(proxy, file, buf, NULL,
						       count, posp);
		goto out;
	}

	ret = -EIO;

out:
	srcu_read_unlock(&kasumi_proxy_srcu, srcu_idx);
	return ret;
}

static ssize_t kasumi_mount_proxy_read_iter(struct kiocb *iocb,
					      struct iov_iter *to)
{
	struct kasumi_mount_file_proxy *proxy =
		container_of(iocb->ki_filp->f_op, struct kasumi_mount_file_proxy,
			     proxy_fops);
	ssize_t ret;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&kasumi_proxy_srcu);

	kasumi_log("mount_proxy: read_iter pid=%d comm=%s count=%zu\n",
		 task_pid_nr(current), current->comm, iov_iter_count(to));

	if (!kasumi_mount_proxy_filter_active(proxy)) {
		ret = -EIO;
		goto out;
	}

	if (proxy->kind == KASUMI_PROC_PROXY_MOUNTINFO ||
	    proxy->kind == KASUMI_PROC_PROXY_MOUNTS) {
		ret = kasumi_mount_proxy_serve_whole(proxy, iocb->ki_filp, NULL,
						     to, iov_iter_count(to),
						     &iocb->ki_pos);
		kasumi_log("mount_proxy: fake_read_iter pid=%d comm=%s ret=%zd\n",
			 task_pid_nr(current), current->comm, ret);
		/* An active fake view never falls back to the real table. */
		goto out;
	}

	if (proxy->kind == KASUMI_PROC_PROXY_MAPS) {
		ret = kasumi_mount_proxy_filtered_read(proxy, iocb->ki_filp, NULL,
						       to, iov_iter_count(to),
						       &iocb->ki_pos);
		goto out;
	}

	ret = -EIO;

out:
	srcu_read_unlock(&kasumi_proxy_srcu, srcu_idx);
	return ret;
}

static bool kasumi_mount_proxy_reject_ioctl(
	const struct kasumi_mount_file_proxy *proxy, unsigned int cmd)
{
#ifdef PROCMAP_QUERY
	return proxy->kind == KASUMI_PROC_PROXY_MAPS &&
	       cmd == PROCMAP_QUERY;
#else
	(void)proxy;
	(void)cmd;
	return false;
#endif
}

static KASUMI_NOCFI long kasumi_mount_proxy_ioctl(struct file *file,
						   unsigned int cmd,
						   unsigned long arg)
{
	struct kasumi_mount_file_proxy *proxy =
		container_of(file->f_op, struct kasumi_mount_file_proxy, proxy_fops);
	long ret;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&kasumi_proxy_srcu);
	if (!kasumi_mount_proxy_filter_active(proxy))
		ret = -EIO;
	else if (kasumi_mount_proxy_reject_ioctl(proxy, cmd))
		ret = -EOPNOTSUPP;
	else if (proxy->orig_fops->unlocked_ioctl)
		ret = proxy->orig_fops->unlocked_ioctl(file, cmd, arg);
	else
		ret = -ENOTTY;
	srcu_read_unlock(&kasumi_proxy_srcu, srcu_idx);
	return ret;
}

#ifdef CONFIG_COMPAT
static KASUMI_NOCFI long kasumi_mount_proxy_compat_ioctl(struct file *file,
						  unsigned int cmd,
						  unsigned long arg)
{
	struct kasumi_mount_file_proxy *proxy =
		container_of(file->f_op, struct kasumi_mount_file_proxy, proxy_fops);
	long ret;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&kasumi_proxy_srcu);
	if (!kasumi_mount_proxy_filter_active(proxy))
		ret = -EIO;
	else if (kasumi_mount_proxy_reject_ioctl(proxy, cmd))
		ret = -EOPNOTSUPP;
	else if (proxy->orig_fops->compat_ioctl)
		ret = proxy->orig_fops->compat_ioctl(file, cmd, arg);
	else
		ret = -ENOTTY;
	srcu_read_unlock(&kasumi_proxy_srcu, srcu_idx);
	return ret;
}
#endif

static KASUMI_NOCFI loff_t kasumi_mount_proxy_llseek(struct file *file,
					      loff_t offset, int whence)
{
	struct kasumi_mount_file_proxy *proxy =
		container_of(file->f_op, struct kasumi_mount_file_proxy,
			     proxy_fops);
	loff_t target;
	loff_t ret;

	if (proxy->kind == KASUMI_PROC_PROXY_MAPS)
		return -ESPIPE;
	mutex_lock(&proxy->stream_lock);
	if (whence == SEEK_SET && offset == 0) {
		kasumi_proc_mount_show_fn show =
			proxy->kind == KASUMI_PROC_PROXY_MOUNTINFO ?
			kasumi_show_mountinfo : kasumi_show_vfsmnt;

		ret = kasumi_mount_proxy_restore_seq(proxy, file, show);
		if (ret)
			goto out;
		proxy->stream_raw_len = 0;
		proxy->stream_tail_off = 0;
		proxy->stream_out_len = 0;
		proxy->stream_out_off = 0;
		proxy->stream_orig_pos = 0;
		proxy->stream_user_pos = 0;
		proxy->stream_generation = 0;
		proxy->stream_eof = false;
		proxy->stream_failed = false;
		/* Pairs with the poll-side acquire load. */
		smp_store_release(&proxy->stream_produced, false);
		file->f_pos = 0;
		ret = 0;
		goto out;
	}
	if (!proxy->stream_produced || proxy->stream_failed) {
		ret = -EINVAL;
		goto out;
	}
	switch (whence) {
	case SEEK_SET:
		target = offset;
		break;
	case SEEK_CUR:
		target = proxy->stream_user_pos + offset;
		break;
	case SEEK_END:
		target = (loff_t)proxy->stream_out_len + offset;
		break;
	default:
		ret = -EINVAL;
		goto out;
	}
	if (target < 0 || target > (loff_t)proxy->stream_out_len) {
		ret = -EINVAL;
		goto out;
	}
	proxy->stream_out_off = (size_t)target;
	proxy->stream_user_pos = target;
	file->f_pos = target;
	ret = target;
out:
	mutex_unlock(&proxy->stream_lock);
	return ret;
}

static KASUMI_NOCFI __poll_t kasumi_mount_proxy_poll(struct file *file,
						      struct poll_table_struct *wait)
{
	struct kasumi_mount_file_proxy *proxy =
		container_of(file->f_op, struct kasumi_mount_file_proxy,
			     proxy_fops);
	__poll_t mask = 0;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&kasumi_proxy_srcu);
	if (!kasumi_mount_proxy_filter_active(proxy)) {
		mask = EPOLLERR;
		goto out;
	}
	if (proxy->orig_fops->poll)
		mask = proxy->orig_fops->poll(file, wait);
	else
		mask = EPOLLIN | EPOLLRDNORM;
	kasumi_fake_mi_poll_wait(file, wait);
	/* Acquire the generation/bytes published before stream_produced. */
	if (smp_load_acquire(&proxy->stream_produced) &&
	    READ_ONCE(proxy->stream_generation) !=
		kasumi_fake_mi_generation())
		mask |= EPOLLERR | EPOLLPRI;
out:
	srcu_read_unlock(&kasumi_proxy_srcu, srcu_idx);
	return mask;
}

static KASUMI_NOCFI int kasumi_mount_proxy_release(struct inode *inode, struct file *file)
{
	struct kasumi_mount_file_proxy *proxy =
		container_of(file->f_op, struct kasumi_mount_file_proxy, proxy_fops);
	const struct file_operations *orig_fops = proxy->orig_fops;
	int ret = 0;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&kasumi_proxy_srcu);
	atomic_set(&proxy->state, KASUMI_PROXY_STATE_RELEASED);
	spin_lock(&kasumi_proxy_list_lock);
	list_del_init(&proxy->node);
	spin_unlock(&kasumi_proxy_list_lock);
	atomic_dec(&kasumi_proxy_live);

	WRITE_ONCE(file->f_mode, proxy->orig_f_mode);
	if (orig_fops->release)
		ret = orig_fops->release(inode, file);

	/* Keep the live proxy's THIS_MODULE reference for __fput(), but stop
	 * __fput() from touching proxy storage after this callback returns.
	 */
	WRITE_ONCE(file->f_op, &kasumi_closed_proxy_fops);
	fops_put(orig_fops);
	srcu_read_unlock(&kasumi_proxy_srcu, srcu_idx);
	kasumi_mount_proxy_stream_free(proxy);
	kfree(proxy);
	return ret;
}

static int kasumi_mount_proxy_install_file(
	struct file *file, enum kasumi_proc_proxy_kind kind,
	enum kasumi_policy_scope scope)
{
	struct kasumi_mount_file_proxy *proxy;
	const struct file_operations *orig_fops;
	const struct file_operations *new_fops;
	if (!file || kind == KASUMI_PROC_PROXY_NONE ||
	    atomic_read(&kasumi_proxy_shutdown))
		return -ESHUTDOWN;
	if ((kind == KASUMI_PROC_PROXY_MOUNTINFO ||
	     kind == KASUMI_PROC_PROXY_MOUNTS) &&
	    scope != KASUMI_POLICY_SCOPE_SPOOF)
		return -EINVAL;
	if (kind == KASUMI_PROC_PROXY_MAPS &&
	    scope != KASUMI_POLICY_SCOPE_VIEW &&
	    scope != KASUMI_POLICY_SCOPE_SPOOF)
		return -EINVAL;
	orig_fops = READ_ONCE(file->f_op);
	if (!orig_fops || orig_fops->release == kasumi_mount_proxy_release)
		return -EALREADY;
	proxy = kzalloc(sizeof(*proxy), GFP_ATOMIC);
	if (!proxy)
		return -ENOMEM;

	proxy->orig_fops = orig_fops;
	proxy->kind = kind;
	proxy->scope = scope;
	proxy->orig_f_mode = READ_ONCE(file->f_mode);
	proxy->proxy_fops = *orig_fops;
	/* Pin module text and proxy storage through VFS dispatch and ->release.
	 * An open proc proxy fd intentionally makes delete_module() return
	 * -EWOULDBLOCK until the fd closes.
	 */
	proxy->proxy_fops.owner = THIS_MODULE;
	if (proxy->orig_fops->read)
		proxy->proxy_fops.read = kasumi_mount_proxy_read;
	proxy->proxy_fops.read_iter = kasumi_mount_proxy_read_iter;
	/* generic/copy splice helpers invoke the original seq_file producer and
	 * would bypass both the fake mountinfo and maps projection.
	 */
	proxy->proxy_fops.splice_read = NULL;
	proxy->proxy_fops.llseek = kasumi_mount_proxy_llseek;
	if (kind == KASUMI_PROC_PROXY_MOUNTINFO ||
	    kind == KASUMI_PROC_PROXY_MOUNTS)
		proxy->proxy_fops.poll = kasumi_mount_proxy_poll;
	if (kind == KASUMI_PROC_PROXY_MAPS) {
		proxy->proxy_fops.unlocked_ioctl = kasumi_mount_proxy_ioctl;
#ifdef CONFIG_COMPAT
		proxy->proxy_fops.compat_ioctl = kasumi_mount_proxy_compat_ioctl;
#endif
	}
	proxy->proxy_fops.release = kasumi_mount_proxy_release;
	INIT_LIST_HEAD(&proxy->node);
	atomic_set(&proxy->state, KASUMI_PROXY_STATE_OPEN);
	atomic_set(&proxy->filter_invalidated, 0);
	mutex_init(&proxy->stream_lock);
	proxy->stream_orig_pos = 0;
	proxy->stream_user_pos = 0;
	proxy->stream_generation = 0;
	proxy->stream_failed = false;

	spin_lock(&kasumi_proxy_list_lock);
	/* fd_install has not published file yet, but keep this comparison under
	 * the same lock as list publication so duplicate installers cannot
	 * overwrite and leak one another.
	 */
	if (atomic_read(&kasumi_proxy_shutdown) ||
	    READ_ONCE(file->f_op) != orig_fops) {
		spin_unlock(&kasumi_proxy_list_lock);
		kfree(proxy);
		return -EAGAIN;
	}
	new_fops = fops_get(&proxy->proxy_fops);
	if (!new_fops) {
		spin_unlock(&kasumi_proxy_list_lock);
		kfree(proxy);
		return -ENOENT;
	}
	list_add(&proxy->node, &kasumi_proxy_list);
	atomic_inc(&kasumi_proxy_live);
	if (kind == KASUMI_PROC_PROXY_MAPS)
		WRITE_ONCE(file->f_mode,
			   proxy->orig_f_mode & ~(FMODE_LSEEK | FMODE_PREAD));
	else
		WRITE_ONCE(file->f_mode,
			   proxy->orig_f_mode & ~FMODE_PREAD);
	WRITE_ONCE(file->f_op, new_fops);
	spin_unlock(&kasumi_proxy_list_lock);

	kasumi_log("proc_proxy: installed kind=%d pid=%d comm=%s\n",
		 kind, task_pid_nr(current), current->comm);
	return 0;
}

static KASUMI_NOCFI void kasumi_mount_proxy_drain(void)
{
	struct kasumi_mount_file_proxy *p, *tmp;
	LIST_HEAD(stale_proxies);

	atomic_set(&kasumi_proxy_shutdown, 1);

	/* Every installed proxy holds THIS_MODULE through its fops owner, so
	 * module exit cannot begin until its release path removes it here.
	 */
	synchronize_srcu(&kasumi_proxy_srcu);
	spin_lock(&kasumi_proxy_list_lock);
	list_splice_init(&kasumi_proxy_list, &stale_proxies);
	spin_unlock(&kasumi_proxy_list_lock);
	list_for_each_entry_safe(p, tmp, &stale_proxies, node) {
		WARN_ON_ONCE(atomic_read(&p->state) == KASUMI_PROXY_STATE_OPEN);
		list_del_init(&p->node);
		kasumi_mount_proxy_stream_free(p);
		kfree(p);
	}
}


static int kasumi_parse_maps_line(const char *line, size_t line_len,
				  unsigned long *start, unsigned long *end,
				  char *flags, unsigned long *pgoff,
				  unsigned long *dev, unsigned long *ino,
				  const char **pathname)
{
	unsigned int ma, mi;
	const char *p = line;
	char *endptr;

	if (line_len < 40)
		return -1;
	*start = simple_strtoul(p, &endptr, 16);
	if (endptr == p || *endptr != '-')
		return -1;
	p = endptr + 1;
	*end = simple_strtoul(p, &endptr, 16);
	if (endptr == p || *endptr != ' ')
		return -1;
	p = endptr + 1;
	flags[0] = p[0];
	flags[1] = p[1];
	flags[2] = p[2];
	flags[3] = p[3];
	flags[4] = '\0';
	p += 4;
	if (*p != ' ')
		return -1;
	*pgoff = simple_strtoul(p + 1, &endptr, 16);
	p = endptr;
	if (*p != ' ')
		return -1;
	ma = (unsigned int)simple_strtoul(p + 1, &endptr, 16);
	if (*endptr != ':')
		return -1;
	mi = (unsigned int)simple_strtoul(endptr + 1, &endptr, 16);
	*dev = (unsigned long)MKDEV(ma, mi);
	p = endptr;
	if (*p != ' ')
		return -1;
	*ino = simple_strtoul(p + 1, &endptr, 10);
	p = endptr;
	while (*p == ' ')
		p++;
	*pathname = p;
	return 0;
}

static bool kasumi_maps_line_looks_like_header(const char *line,
					       size_t line_len)
{
	size_t i = 0;

	while (i < line_len && isxdigit(line[i]))
		i++;
	return i > 0 && i < line_len && line[i] == '-';
}

static int kasumi_filter_maps_lines(const char *src, size_t len,
				    char *dst, size_t dst_size, size_t *written,
				    bool *changed, bool *valid,
				    enum kasumi_policy_scope scope)
{
	size_t in = 0, out = 0;
	struct kasumi_maps_rule_entry *r;
	const char *pathname;
	char replacement_path[KSM_MAX_LEN_PATHNAME];
	char header[128];
	char flags[5];
	unsigned long start, end, pgoff, dev, ino;
	unsigned long spoof_ino, spoof_dev;
	size_t path_len, original_path_len, pathname_offset;
	int header_len;
	bool have_replacement_path;
	bool line_changed;
	bool spoof = scope == KASUMI_POLICY_SCOPE_SPOOF;

	if (written)
		*written = 0;
	if (changed)
		*changed = false;
	if (valid)
		*valid = true;
	if (!src || !dst || !written)
		return -EINVAL;

	while (in < len) {
		size_t line_start = in;
		size_t line_len;
		bool complete_line;

		while (in < len && src[in] != '\n')
			in++;
		complete_line = in < len && src[in] == '\n';
		line_len = in - line_start;
		if (complete_line)
			line_len++;
		if (!complete_line) {
			if (valid)
				*valid = false;
			return -EINVAL;
		}

		if (kasumi_parse_maps_line(src + line_start, line_len, &start,
					   &end, flags, &pgoff, &dev, &ino,
					   &pathname) != 0) {
			/* smaps metadata is intentionally passed through. A line that
			 * starts like a VMA header but cannot be parsed is unsafe to expose.
			 */
			if (kasumi_maps_line_looks_like_header(src + line_start,
						       line_len)) {
				if (valid)
					*valid = false;
				return -EINVAL;
			}
			if (out > dst_size || line_len > dst_size - out)
				return -ENOSPC;
			memcpy(dst + out, src + line_start, line_len);
			out += line_len;
			in++;
			continue;
		}

		pathname_offset = (size_t)(pathname - src);
		if (pathname_offset > line_start + line_len - 1)
			return -EINVAL;
		original_path_len = line_start + line_len - 1 - pathname_offset;
		spoof_ino = ino;
		spoof_dev = dev;
		have_replacement_path = false;
		replacement_path[0] = '\0';

		if (spoof) {
			mutex_lock(&kasumi_maps_mutex);
			list_for_each_entry(r, &kasumi_maps_rules, list) {
				if (r->target_ino != ino)
					continue;
				if (r->target_dev != 0 && r->target_dev != dev)
					continue;
				spoof_ino = r->spoofed_ino;
				spoof_dev = r->spoofed_dev;
				/* Do not retain a rule-owned pointer after unlocking. */
				strscpy(replacement_path, r->spoofed_pathname,
					sizeof(replacement_path));
				have_replacement_path = true;
				break;
			}
			mutex_unlock(&kasumi_maps_mutex);
		}

		if (have_replacement_path) {
			path_len = strnlen(replacement_path,
					   sizeof(replacement_path));
			line_changed = spoof_ino != ino || spoof_dev != dev ||
				path_len != original_path_len ||
				memcmp(replacement_path, src + pathname_offset,
				       min(path_len, original_path_len)) != 0;
		} else {
			path_len = original_path_len;
			line_changed = spoof_ino != ino || spoof_dev != dev;
		}

		if (!line_changed) {
			if (out > dst_size || line_len > dst_size - out)
				return -ENOSPC;
			memcpy(dst + out, src + line_start, line_len);
			out += line_len;
			in++;
			continue;
		}

		header_len = scnprintf(header, sizeof(header),
				       "%08lx-%08lx %s %08lx %02x:%02x %lu ",
				       start, end, flags, pgoff,
				       (unsigned int)MAJOR(spoof_dev),
				       (unsigned int)MINOR(spoof_dev), spoof_ino);
		if (header_len <= 0 || header_len >= sizeof(header)) {
			if (valid)
				*valid = false;
			return -EINVAL;
		}
		if (out > dst_size || (size_t)header_len + 1 > dst_size - out ||
		    path_len > dst_size - out - (size_t)header_len - 1)
			return -ENOSPC;
		memcpy(dst + out, header, header_len);
		out += (size_t)header_len;
		if (path_len > 0) {
			if (have_replacement_path)
				memcpy(dst + out, replacement_path, path_len);
			else
				memcpy(dst + out, src + pathname_offset, path_len);
			out += path_len;
		}
		dst[out++] = '\n';
		if (changed)
			*changed = true;
		in++;
	}

	*written = out;
	return 0;
}

/*
 * get_vfs_caps_from_disk kretprobe (cold, exec path only).  When a redirected
 * setcap binary is exec'd, the kernel reads its file capabilities off the
 * *visible* dentry, which is our synthetic vnode with no on-disk
 * security.capability, so the read misses and the binary would lose its caps.
 * The source's caps were parsed and stashed on the vnode at create time; here
 * we simply replay them (atomic-safe: pure copy) and report success.
 *
 * Argument layout follows get_vfs_caps_from_disk():
 *   < 5.12: (dentry, cpu_caps)              -> reg0, reg1
 *  >= 5.12: (idmap/userns, dentry, cpu_caps)-> reg1, reg2
 */
static int kasumi_get_vfs_caps_entry(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	struct kasumi_fscap_ri_data *d = (void *)ri->data;
	const struct dentry *dentry;

	d->have = false;
	d->out = NULL;
	if (!READ_ONCE(kasumi_fscaps_enabled))
		return 0;
#if defined(__aarch64__)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	dentry = (const struct dentry *)regs->regs[1];
	d->out = (struct cpu_vfs_cap_data *)regs->regs[2];
#else
	dentry = (const struct dentry *)regs->regs[0];
	d->out = (struct cpu_vfs_cap_data *)regs->regs[1];
#endif
#elif defined(__x86_64__)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	dentry = (const struct dentry *)regs->si;
	d->out = (struct cpu_vfs_cap_data *)regs->dx;
#else
	dentry = (const struct dentry *)regs->di;
	d->out = (struct cpu_vfs_cap_data *)regs->si;
#endif
#else
	dentry = NULL;
	d->out = NULL;
#endif
	if (!dentry || !d->out)
		return 0;
	if (kasumi_vnode_peek_caps(dentry, &d->caps))
		d->have = true;
	return 0;
}

static int kasumi_get_vfs_caps_ret(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct kasumi_fscap_ri_data *d = (void *)ri->data;

	if (!d->have || !d->out)
		return 0;
	*d->out = d->caps;
	/* Report success (0) so the caller applies the replayed caps regardless of
	 * the miss the real read returned on the synthetic inode. */
#if defined(__aarch64__)
	regs->regs[0] = 0;
#elif defined(__x86_64__)
	regs->ax = 0;
#endif
	return 0;
}

static struct kretprobe kasumi_krp_get_vfs_caps = {
	.entry_handler = kasumi_get_vfs_caps_entry,
	.handler = kasumi_get_vfs_caps_ret,
	.data_size = sizeof(struct kasumi_fscap_ri_data),
	.maxactive = 64,
};

static struct kprobe kasumi_kp_cp_statx;
static bool kasumi_cp_statx_registered;

static int kasumi_cp_statx_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct kstat *stat;
	u32 result_mask;
	u64 real_mnt_id;
	bool hidden = false;
	bool projected_mount_root = false;
	int fake_mnt_id;
	int lookup_ret;

	(void)kp;
	if (!(kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE) ||
	    !kasumi_policy_current_is_spoof_target())
		return 0;
#if defined(__aarch64__)
	stat = (struct kstat *)regs->regs[0];
#elif defined(__x86_64__)
	stat = (struct kstat *)regs->di;
#else
	return 0;
#endif
	if (!stat)
		return 0;
	result_mask = READ_ONCE(stat->result_mask);
	real_mnt_id = READ_ONCE(stat->mnt_id);
#ifdef STATX_MNT_ID_UNIQUE
	/* mnt_id_unique is not the namespace mount ID printed by mountinfo, so
	 * the fake mountinfo map cannot translate it. Suppress the unsupported
	 * field instead of leaking or accidentally mapping a colliding number.
	 */
	if (result_mask & STATX_MNT_ID_UNIQUE) {
		u64 attributes = READ_ONCE(stat->attributes);
		u64 attributes_mask = READ_ONCE(stat->attributes_mask);

		/* The unique ID cannot be checked against the namespace-local hidden
		 * map, so suppress the mount-root side channel unconditionally too. */
		WRITE_ONCE(stat->attributes,
			   attributes & ~(u64)STATX_ATTR_MOUNT_ROOT);
		WRITE_ONCE(stat->attributes_mask,
			   attributes_mask | (u64)STATX_ATTR_MOUNT_ROOT);
		WRITE_ONCE(stat->mnt_id, 0);
		WRITE_ONCE(stat->result_mask,
			   result_mask & ~(STATX_MNT_ID_UNIQUE | STATX_MNT_ID));
		return 0;
	}
#endif
	lookup_ret = kasumi_fake_mi_mount_id_state_cached(
		real_mnt_id, &fake_mnt_id, &hidden,
		&projected_mount_root);
	if (!lookup_ret && hidden) {
		u64 attributes = READ_ONCE(stat->attributes);
		u64 attributes_mask = READ_ONCE(stat->attributes_mask);

		/* Removing an overmount exposes the visible ancestor. A real mount
		 * root remains a projected mount root only when both mounts begin at
		 * the same namespace path (recorded in the snapshot's id map).
		 */
		if (!(attributes & (u64)STATX_ATTR_MOUNT_ROOT) ||
		    !projected_mount_root)
			attributes &= ~(u64)STATX_ATTR_MOUNT_ROOT;
		WRITE_ONCE(stat->attributes,
			   attributes);
		WRITE_ONCE(stat->attributes_mask,
			   attributes_mask | (u64)STATX_ATTR_MOUNT_ROOT);
	} else if (lookup_ret) {
		u64 attributes = READ_ONCE(stat->attributes);
		u64 attributes_mask = READ_ONCE(stat->attributes_mask);

		/* No root-keyed cache means neither the real mount ID nor its
		 * mount-root bit is safe to expose. Publish an authoritative false
		 * value until a matching snapshot is prepared.
		 */
		WRITE_ONCE(stat->attributes,
			   attributes & ~(u64)STATX_ATTR_MOUNT_ROOT);
		WRITE_ONCE(stat->attributes_mask,
			   attributes_mask | (u64)STATX_ATTR_MOUNT_ROOT);
	}
	if (!(result_mask & STATX_MNT_ID))
		return 0;
	if (lookup_ret || fake_mnt_id <= 0) {
		/* cp_statx copies this kstat after the probe returns. Publish a safe
		 * result now; a later call can translate it after the mountinfo cache
		 * refreshes naturally.
		 */
		WRITE_ONCE(stat->mnt_id, 0);
		WRITE_ONCE(stat->result_mask, result_mask & ~STATX_MNT_ID);
		return 0;
	}
	WRITE_ONCE(stat->mnt_id, (u64)fake_mnt_id);
	WRITE_ONCE(stat->result_mask, result_mask);
	return 0;
}

void kasumi_proc_read_hooks_init(void)
{
	unsigned long readlink_addr = kasumi_lookup_name("vfs_readlink");
	unsigned long fd_install_addr = kasumi_lookup_name("fd_install");
	unsigned long cp_statx_addr = kasumi_lookup_name("cp_statx");
	unsigned long caps_addr = kasumi_lookup_name("get_vfs_caps_from_disk");
	unsigned long show_vfsmnt_addr = kasumi_lookup_name("show_vfsmnt");
	unsigned long show_mountinfo_addr = kasumi_lookup_name("show_mountinfo");
	bool use_proxy_filter = false;

	atomic_set(&kasumi_proxy_shutdown, 0);
	atomic_set(&kasumi_proxy_live, 0);
	kasumi_show_vfsmnt = (kasumi_proc_mount_show_fn)show_vfsmnt_addr;
	kasumi_show_mountinfo = (kasumi_proc_mount_show_fn)show_mountinfo_addr;
	if (!kasumi_show_vfsmnt || !kasumi_show_mountinfo)
		pr_warn("Kasumi: proc mount pair snapshot callbacks unavailable\n");
	kasumi_ns_id_seed = (u32)(unsigned long)&kasumi_krp_vfs_readlink ^
			    (u32)((unsigned long)&kasumi_krp_vfs_readlink >> 32);

	if (readlink_addr) {
		kasumi_krp_vfs_readlink.kp.addr =
			(kprobe_opcode_t *)readlink_addr;
		if (!register_kretprobe(&kasumi_krp_vfs_readlink)) {
			kasumi_proc_ns_readlink_registered = 1;
			pr_info("Kasumi: aggressive mount namespace link projection ready\n");
		} else {
			pr_warn("Kasumi: register_kretprobe(vfs_readlink) failed\n");
		}
	} else {
		pr_warn("Kasumi: vfs_readlink not found, aggressive mount hide unavailable\n");
	}

	/* Path-aware statfs projection needs an atomic vfsmount identity map.
	 * Calling vfs_getattr from a kprobe handler can sleep, while an sb-wide
	 * overlay guess corrupts visible-overlay semantics. Keep this hook disabled
	 * until that map is available rather than publish unsafe or false data.
	 */
	pr_warn("Kasumi: statfs spoofing disabled (atomic mount identity unavailable)\n");

	if (cp_statx_addr) {
		kasumi_kp_cp_statx.addr = (kprobe_opcode_t *)cp_statx_addr;
		kasumi_kp_cp_statx.pre_handler = kasumi_cp_statx_pre;
		if (!register_kprobe(&kasumi_kp_cp_statx)) {
			kasumi_cp_statx_registered = true;
			pr_info("Kasumi: statx mount IDs projected via cp_statx\n");
		} else {
			pr_warn("Kasumi: register_kprobe(cp_statx) failed\n");
		}
	} else {
		pr_warn("Kasumi: cp_statx not found, statx mount ID spoof disabled\n");
	}

	if (caps_addr) {
		kasumi_krp_get_vfs_caps.kp.addr = (kprobe_opcode_t *)caps_addr;
		if (register_kretprobe(&kasumi_krp_get_vfs_caps) == 0) {
			kasumi_fscap_kretprobe_registered = 1;
			pr_info("Kasumi: source file-capability replay via get_vfs_caps_from_disk\n");
		} else {
			pr_warn("Kasumi: register_kretprobe(get_vfs_caps_from_disk) failed\n");
		}
	} else {
		pr_warn("Kasumi: get_vfs_caps_from_disk not found, redirected fscaps disabled\n");
	}

	if (fd_install_addr) {
		kasumi_kp_fd_install.addr = (kprobe_opcode_t *)fd_install_addr;
		kasumi_kp_fd_install.pre_handler = kasumi_fd_install_pre;
		if (!register_kprobe(&kasumi_kp_fd_install)) {
			kasumi_fd_install_registered = true;
			use_proxy_filter = true;
		} else {
			pr_warn("Kasumi: register_kprobe(fd_install) failed\n");
		}
	} else {
		pr_warn("Kasumi: fd_install not found\n");
	}

	if (use_proxy_filter) {
		kasumi_proc_proxy_registered = 1;
		pr_info("Kasumi: proc views filtered by fd_install fop proxy\n");
	}

	if (!use_proxy_filter) {
		if (show_vfsmnt_addr) {
			kasumi_kp_show_vfsmnt.addr =
				(kprobe_opcode_t *)show_vfsmnt_addr;
			if (register_kprobe(&kasumi_kp_show_vfsmnt) == 0) {
				kasumi_mount_hide_vfsmnt_registered = 1;
				pr_info("Kasumi: mount hide via kprobe on show_vfsmnt (/proc/mounts)\n");
			}
		} else {
			pr_warn("Kasumi: show_vfsmnt not found\n");
		}
		if (show_mountinfo_addr) {
			kasumi_kp_show_mountinfo.addr =
				(kprobe_opcode_t *)show_mountinfo_addr;
			if (register_kprobe(&kasumi_kp_show_mountinfo) == 0) {
				kasumi_mount_hide_mountinfo_registered = 1;
				pr_info("Kasumi: mount hide via kprobe on show_mountinfo (/proc/pid/mountinfo)\n");
			}
		} else {
			pr_warn("Kasumi: show_mountinfo not found\n");
		}
		pr_warn("Kasumi: maps spoof unavailable without per-open proxy\n");
	}
}

void kasumi_proc_read_hooks_stop_new(void)
{
	atomic_set(&kasumi_proxy_shutdown, 1);
	if (kasumi_fd_install_registered) {
		unregister_kprobe(&kasumi_kp_fd_install);
		kasumi_fd_install_registered = false;
	}
	if (kasumi_proc_ns_readlink_registered) {
		unregister_kretprobe(&kasumi_krp_vfs_readlink);
		kasumi_proc_ns_readlink_registered = 0;
	}
	if (kasumi_cp_statx_registered) {
		unregister_kprobe(&kasumi_kp_cp_statx);
		kasumi_cp_statx_registered = false;
	}
	if (kasumi_fscap_kretprobe_registered) {
		unregister_kretprobe(&kasumi_krp_get_vfs_caps);
		kasumi_fscap_kretprobe_registered = 0;
	}
	if (kasumi_mount_hide_mountinfo_registered) {
		unregister_kprobe(&kasumi_kp_show_mountinfo);
		kasumi_mount_hide_mountinfo_registered = 0;
	}
	if (kasumi_mount_hide_vfsmnt_registered) {
		unregister_kprobe(&kasumi_kp_show_vfsmnt);
		kasumi_mount_hide_vfsmnt_registered = 0;
	}
	kasumi_proc_proxy_registered = 0;
}

unsigned int kasumi_proc_proxy_live(void)
{
	return (unsigned int)atomic_read(&kasumi_proxy_live);
}

void kasumi_proc_read_hooks_exit(void)
{
	kasumi_proc_read_hooks_stop_new();
	/* Proxy fops pin THIS_MODULE, so final destruction starts only after all
	 * installed proc files have naturally reached ->release.
	 */
	kasumi_mount_proxy_drain();
	WARN_ON_ONCE(atomic_read(&kasumi_proxy_live));

	{
		struct kasumi_maps_rule_entry *e, *tmp;

		mutex_lock(&kasumi_maps_mutex);
		list_for_each_entry_safe(e, tmp, &kasumi_maps_rules, list) {
			list_del(&e->list);
			kfree(e);
		}
		mutex_unlock(&kasumi_maps_mutex);
	}

	kasumi_canonical_observers_clear();
	kasumi_show_mountinfo = NULL;
	kasumi_show_vfsmnt = NULL;
}
