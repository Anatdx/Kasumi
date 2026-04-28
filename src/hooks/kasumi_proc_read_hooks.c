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
#include <linux/fcntl.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/srcu.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <uapi/linux/magic.h>
#ifndef EROFS_SUPER_MAGIC
#define EROFS_SUPER_MAGIC 0xe0f5e1e2
#endif
#include <asm/unistd.h>

#include "kasumi_runtime.h"
#include "kasumi_store.h"
#include "kasumi_file_view.h"
#include "kasumi_entrypoints.h"
#include "kasumi_path_policy.h"
#include "kasumi_proc_hooks.h"
#include "kasumi_tracepoint_hooks.h"
#include "kasumi_fake_mountinfo.h"

#ifndef D_REAL_DATA
#define D_REAL_DATA 0
#endif

static struct inode *kasumi_d_real_inode_impl(struct dentry *dentry)
{
	struct dentry *real;

	if (unlikely(dentry->d_flags & DCACHE_OP_REAL) && dentry->d_op && dentry->d_op->d_real) {
		real = dentry->d_op->d_real(dentry, D_REAL_DATA);
		return real && real->d_inode ? real->d_inode : dentry->d_inode;
	}
	return dentry->d_inode;
}

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

/* Preferred path: filter overlay lines from read() when fd is /proc/.../mountinfo or /proc/mounts.
 * Uses syscall kretprobe only (less overhead, can share with other syscall handling). */
#define KASUMI_READ_MOUNT_FILTER_BUF 65536
static char *kasumi_read_filter_buf;
static DEFINE_MUTEX(kasumi_read_filter_mutex);

static size_t kasumi_filter_overlay_lines(char *kbuf, size_t len);
static size_t kasumi_filter_maps_lines(char *kbuf, size_t len);

struct kasumi_read_mount_ri_data {
	int fd;
	void __user *buf;
	size_t count;
	loff_t pos;
	bool use_explicit_pos;
};

bool kasumi_path_is_proc_mount_view(const char *path)
{
	return path && strncmp(path, "/proc/", 6) == 0 &&
	       (strstr(path, "/mountinfo") || strstr(path, "/mounts"));
}

bool kasumi_path_is_proc_mountinfo(const char *path)
{
	return path && strncmp(path, "/proc/", 6) == 0 &&
	       strstr(path, "/mountinfo");
}

static bool kasumi_path_is_proc_maps_view(const char *path)
{
	return path && strncmp(path, "/proc/", 6) == 0 &&
	       (strstr(path, "/maps") || strstr(path, "/smaps"));
}

enum kasumi_proc_proxy_kind {
	KASUMI_PROC_PROXY_NONE = 0,
	KASUMI_PROC_PROXY_MOUNTINFO,
	KASUMI_PROC_PROXY_MOUNTS,
	KASUMI_PROC_PROXY_MAPS,
};

static enum kasumi_proc_proxy_kind kasumi_proc_proxy_kind_for_path(const char *path)
{
	if ((kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE) &&
	    kasumi_path_is_proc_mountinfo(path))
		return KASUMI_PROC_PROXY_MOUNTINFO;
	if ((kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE) &&
	    path && strncmp(path, "/proc/", 6) == 0 && strstr(path, "/mounts"))
		return KASUMI_PROC_PROXY_MOUNTS;
	if ((kasumi_feature_enabled_mask & KSM_FEATURE_MAPS_SPOOF) &&
	    kasumi_path_is_proc_maps_view(path))
		return KASUMI_PROC_PROXY_MAPS;
	return KASUMI_PROC_PROXY_NONE;
}

bool kasumi_path_needs_proc_proxy(const char *path)
{
	return kasumi_proc_proxy_kind_for_path(path) != KASUMI_PROC_PROXY_NONE;
}

/*
 * Revocable proxy lifecycle:
 *   - .owner = NULL so fops_get/fops_put never bump THIS_MODULE refcount; long-lived
 *     readers can't pin the module.
 *   - Every install adds the proxy to kasumi_proxy_list under kasumi_proxy_list_lock.
 *   - On module exit, kasumi_mount_proxy_drain() flips file->f_op back to orig_fops,
 *     then synchronize_srcu()s so any in-flight proxy_read/proxy_release callers exit
 *     before we kfree the proxy. Module text only goes away after exit returns, so the
 *     SRCU barrier is what keeps stale callers from jumping into freed code.
 *   - Natural close (proxy_release) atomically claims state to coordinate with drain;
 *     whichever side claims OPEN->RELEASING vs OPEN->DRAINED owns the kfree.
 */

#define KASUMI_PROXY_STATE_OPEN      0
#define KASUMI_PROXY_STATE_DRAINED   1
#define KASUMI_PROXY_STATE_RELEASING 2

struct kasumi_mount_file_proxy {
	const struct file_operations *orig_fops;
	struct file_operations proxy_fops;
	enum kasumi_proc_proxy_kind kind;
	struct list_head node;
	struct file *file;
	atomic_t state;
	struct rcu_head rcu;
};

static LIST_HEAD(kasumi_proxy_list);
static DEFINE_SPINLOCK(kasumi_proxy_list_lock);
DEFINE_STATIC_SRCU(kasumi_proxy_srcu);
static atomic_t kasumi_proxy_shutdown = ATOMIC_INIT(0);

static void kasumi_mount_proxy_rcu_free(struct rcu_head *rcu)
{
	struct kasumi_mount_file_proxy *p =
		container_of(rcu, struct kasumi_mount_file_proxy, rcu);

	kfree(p);
}

static ssize_t kasumi_mount_proxy_read(struct file *file, char __user *buf,
					 size_t count, loff_t *ppos)
{
	struct kasumi_mount_file_proxy *proxy =
		container_of(file->f_op, struct kasumi_mount_file_proxy, proxy_fops);
	ssize_t ret;
	loff_t pos;
	size_t new_len;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&kasumi_proxy_srcu);

	if (!proxy->orig_fops->read) {
		ret = -EINVAL;
		goto out;
	}

	if (proxy->kind == KASUMI_PROC_PROXY_MOUNTINFO &&
	    (kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE) &&
	    kasumi_should_apply_hide_rules()) {
		pos = ppos ? *ppos : file->f_pos;
		ret = kasumi_fake_mi_serve(file, buf, count, 0, pos);
		if (ret == -1) {
			ret = 0;
			goto out;
		}
		if (ret > 0) {
			if (ppos)
				*ppos += ret;
			else
				file->f_pos += ret;
			goto out;
		}
	}

	ret = proxy->orig_fops->read(file, buf, count, ppos);
	if (ret <= 0 || ret > KASUMI_READ_MOUNT_FILTER_BUF || !kasumi_read_filter_buf)
		goto out;

	if (proxy->kind == KASUMI_PROC_PROXY_MOUNTINFO ||
	    proxy->kind == KASUMI_PROC_PROXY_MOUNTS) {
		if (!(kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE))
			goto out;
		mutex_lock(&kasumi_read_filter_mutex);
		if (copy_from_user(kasumi_read_filter_buf, buf, (size_t)ret)) {
			mutex_unlock(&kasumi_read_filter_mutex);
			goto out;
		}
		new_len = kasumi_filter_overlay_lines(kasumi_read_filter_buf, (size_t)ret);
		if (new_len < (size_t)ret &&
		    copy_to_user(buf, kasumi_read_filter_buf, new_len) == 0)
			ret = (ssize_t)new_len;
		mutex_unlock(&kasumi_read_filter_mutex);
		goto out;
	}

	if (proxy->kind == KASUMI_PROC_PROXY_MAPS) {
		if (!(kasumi_feature_enabled_mask & KSM_FEATURE_MAPS_SPOOF))
			goto out;
		mutex_lock(&kasumi_read_filter_mutex);
		if (copy_from_user(kasumi_read_filter_buf, buf, (size_t)ret)) {
			mutex_unlock(&kasumi_read_filter_mutex);
			goto out;
		}
		new_len = kasumi_filter_maps_lines(kasumi_read_filter_buf, (size_t)ret);
		if (new_len != (size_t)ret &&
		    copy_to_user(buf, kasumi_read_filter_buf, new_len) == 0)
			ret = (ssize_t)new_len;
		mutex_unlock(&kasumi_read_filter_mutex);
	}

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

	if (proxy->kind != KASUMI_PROC_PROXY_MOUNTINFO ||
	    !(kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE) ||
	    !kasumi_should_apply_hide_rules()) {
		if (!proxy->orig_fops->read_iter) {
			ret = -EINVAL;
			goto out;
		}
		ret = proxy->orig_fops->read_iter(iocb, to);
		goto out;
	}

	ret = kasumi_fake_mi_read_iter(iocb, to);
	kasumi_log("mount_proxy: fake_read_iter pid=%d comm=%s ret=%zd\n",
		 task_pid_nr(current), current->comm, ret);
	if (ret >= 0)
		goto out;

	if (!proxy->orig_fops->read_iter)
		goto out;
	kasumi_log("mount_proxy: fallback_orig_read_iter pid=%d comm=%s ret=%zd\n",
		 task_pid_nr(current), current->comm, ret);
	ret = proxy->orig_fops->read_iter(iocb, to);

out:
	srcu_read_unlock(&kasumi_proxy_srcu, srcu_idx);
	return ret;
}

static int kasumi_mount_proxy_release(struct inode *inode, struct file *file)
{
	struct kasumi_mount_file_proxy *proxy =
		container_of(file->f_op, struct kasumi_mount_file_proxy, proxy_fops);
	int ret = 0;
	int prev;
	bool we_own;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&kasumi_proxy_srcu);

	prev = atomic_cmpxchg(&proxy->state, KASUMI_PROXY_STATE_OPEN,
			       KASUMI_PROXY_STATE_RELEASING);
	we_own = (prev == KASUMI_PROXY_STATE_OPEN);
	if (we_own) {
		spin_lock(&kasumi_proxy_list_lock);
		list_del_init(&proxy->node);
		spin_unlock(&kasumi_proxy_list_lock);
	}

	if (proxy->orig_fops->release)
		ret = proxy->orig_fops->release(inode, file);

	srcu_read_unlock(&kasumi_proxy_srcu, srcu_idx);

	if (we_own) {
		/* defer free past current SRCU grace period */
		call_srcu(&kasumi_proxy_srcu, &proxy->rcu,
			  kasumi_mount_proxy_rcu_free);
	}
	/* drained side: kasumi_mount_proxy_drain() owns the kfree */
	return ret;
}

int kasumi_mount_proxy_install_fd(int fd)
{
	struct file *file;
	struct kasumi_mount_file_proxy *proxy;
	char *path_buf;
	char *path;
	const struct file_operations *new_fops;
	enum kasumi_proc_proxy_kind kind;
	int ret = 0;

	if (atomic_read(&kasumi_proxy_shutdown))
		return -ESHUTDOWN;

	file = fget(fd);
	if (!file)
		return -EBADF;
	if (!file->f_op)
		goto out;
	if (file->f_op->release == kasumi_mount_proxy_release)
		goto out;

	path_buf = (char *)__get_free_page(GFP_KERNEL);
	if (!path_buf) {
		ret = -ENOMEM;
		goto out;
	}
	path = d_path(&file->f_path, path_buf, PAGE_SIZE);
	if (IS_ERR(path)) {
		free_page((unsigned long)path_buf);
		goto out;
	}
	kind = kasumi_proc_proxy_kind_for_path(path);
	if (kind == KASUMI_PROC_PROXY_NONE) {
		free_page((unsigned long)path_buf);
		goto out;
	}
	free_page((unsigned long)path_buf);

	proxy = kzalloc(sizeof(*proxy), GFP_KERNEL);
	if (!proxy) {
		ret = -ENOMEM;
		goto out;
	}

	proxy->orig_fops = file->f_op;
	proxy->kind = kind;
	proxy->proxy_fops = *file->f_op;
	/* owner = NULL: fops_get/fops_put will not bump THIS_MODULE refcount,
	 * so long-lived proxied fds cannot block rmmod. Lifetime is governed by
	 * kasumi_proxy_list + SRCU instead.
	 */
	proxy->proxy_fops.owner = NULL;
	if (proxy->orig_fops->read)
		proxy->proxy_fops.read = kasumi_mount_proxy_read;
	if (proxy->orig_fops->read_iter)
		proxy->proxy_fops.read_iter = kasumi_mount_proxy_read_iter;
	proxy->proxy_fops.release = kasumi_mount_proxy_release;
	INIT_LIST_HEAD(&proxy->node);
	proxy->file = file;
	atomic_set(&proxy->state, KASUMI_PROXY_STATE_OPEN);

	spin_lock(&kasumi_proxy_list_lock);
	if (atomic_read(&kasumi_proxy_shutdown)) {
		spin_unlock(&kasumi_proxy_list_lock);
		kfree(proxy);
		ret = -ESHUTDOWN;
		goto out;
	}
	new_fops = fops_get(&proxy->proxy_fops);
	if (!new_fops) {
		spin_unlock(&kasumi_proxy_list_lock);
		kfree(proxy);
		ret = -ENOENT;
		goto out;
	}
	list_add(&proxy->node, &kasumi_proxy_list);
	WRITE_ONCE(file->f_op, new_fops);
	spin_unlock(&kasumi_proxy_list_lock);

	kasumi_log("proc_proxy: installed fd=%d kind=%d pid=%d comm=%s\n",
		 fd, kind, task_pid_nr(current), current->comm);

out:
	fput(file);
	return ret;
}

void kasumi_mount_proxy_drain(void)
{
	struct kasumi_mount_file_proxy *p, *tmp;
	LIST_HEAD(victims);

	atomic_set(&kasumi_proxy_shutdown, 1);

	spin_lock(&kasumi_proxy_list_lock);
	list_for_each_entry_safe(p, tmp, &kasumi_proxy_list, node) {
		if (atomic_cmpxchg(&p->state, KASUMI_PROXY_STATE_OPEN,
				    KASUMI_PROXY_STATE_DRAINED) !=
		    KASUMI_PROXY_STATE_OPEN)
			continue; /* release path owns this proxy */
		list_move(&p->node, &victims);
		/* Restore original f_op so future fops dispatches bypass the
		 * proxy. WRITE_ONCE under the same spinlock release/install
		 * also take ensures no torn write or racing assignment.
		 */
		WRITE_ONCE(p->file->f_op, p->orig_fops);
	}
	spin_unlock(&kasumi_proxy_list_lock);

	/* Wait for all in-flight proxy_read/read_iter/release callers (which
	 * captured a snapshot of f_op before our WRITE_ONCE) to leave the SRCU
	 * read-side critical section before we free their proxy.
	 */
	synchronize_srcu(&kasumi_proxy_srcu);

	list_for_each_entry_safe(p, tmp, &victims, node) {
		list_del(&p->node);
		kfree(p);
	}

	/* Flush any call_srcu callbacks (kasumi_mount_proxy_rcu_free) queued by
	 * the natural release path before we go. Their function pointer lives
	 * in module text, so they must run before module unload completes.
	 */
	srcu_barrier(&kasumi_proxy_srcu);
}

static int kasumi_read_mount_filter_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kasumi_read_mount_ri_data *d = (struct kasumi_read_mount_ri_data *)ri->data;
#if defined(__aarch64__)
	d->fd = (int)regs->regs[0];
	d->buf = (void __user *)regs->regs[1];
	d->count = (size_t)regs->regs[2];
	d->pos = -1;
	d->use_explicit_pos = false;
#elif defined(__x86_64__)
	d->fd = (int)regs->di;
	d->buf = (void __user *)regs->si;
	d->count = (size_t)regs->dx;
	d->pos = -1;
	d->use_explicit_pos = false;
#else
	d->fd = -1;
	d->buf = NULL;
	d->count = 0;
	d->pos = -1;
	d->use_explicit_pos = false;
#endif
	return 0;
}

static int kasumi_pread_mount_filter_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kasumi_read_mount_ri_data *d = (struct kasumi_read_mount_ri_data *)ri->data;
#if defined(__aarch64__)
	d->fd = (int)regs->regs[0];
	d->buf = (void __user *)regs->regs[1];
	d->count = (size_t)regs->regs[2];
	d->pos = (loff_t)regs->regs[3];
	d->use_explicit_pos = true;
#elif defined(__x86_64__)
	d->fd = (int)regs->di;
	d->buf = (void __user *)regs->si;
	d->count = (size_t)regs->dx;
	d->pos = (loff_t)regs->cx;
	d->use_explicit_pos = true;
#else
	d->fd = -1;
	d->buf = NULL;
	d->count = 0;
	d->pos = -1;
	d->use_explicit_pos = false;
#endif
	return 0;
}

struct kasumi_vfs_read_mount_ri_data {
	struct file *file;
	void __user *buf;
	size_t count;
	loff_t pos;
	bool use_explicit_pos;
};

static int kasumi_vfs_read_mount_filter_entry(struct kretprobe_instance *ri,
					      struct pt_regs *regs)
{
	struct kasumi_vfs_read_mount_ri_data *d =
		(struct kasumi_vfs_read_mount_ri_data *)ri->data;
	loff_t *posp;

#if defined(__aarch64__)
	d->file = (struct file *)regs->regs[0];
	d->buf = (void __user *)regs->regs[1];
	d->count = (size_t)regs->regs[2];
	posp = (loff_t *)regs->regs[3];
#elif defined(__x86_64__)
	d->file = (struct file *)regs->di;
	d->buf = (void __user *)regs->si;
	d->count = (size_t)regs->dx;
	posp = (loff_t *)regs->cx;
#else
	d->file = NULL;
	d->buf = NULL;
	d->count = 0;
	d->pos = -1;
	d->use_explicit_pos = false;
	return 0;
#endif

	d->pos = posp ? READ_ONCE(*posp) : -1;
	d->use_explicit_pos = posp && d->file && posp != &d->file->f_pos;
	return 0;
}

/* Remove lines containing " overlay " (mountinfo/mounts format); in-place, return new length */
static size_t kasumi_filter_overlay_lines(char *kbuf, size_t len)
{
	size_t out = 0;
	size_t i = 0;

	while (i < len) {
		size_t line_start = i;
		while (i < len && kbuf[i] != '\n')
			i++;
		if (i > line_start) {
			size_t line_len = i - line_start;
			/* Skip line if it contains " overlay " (space-padded to avoid false hits) */
			bool is_overlay = false;
			size_t j;
			for (j = line_start; j + 8 <= line_start + line_len; j++) {
				if (kbuf[j] == ' ' && kbuf[j+1] == 'o' && kbuf[j+2] == 'v' &&
				    kbuf[j+3] == 'e' && kbuf[j+4] == 'r' && kbuf[j+5] == 'l' &&
				    kbuf[j+6] == 'a' && kbuf[j+7] == 'y' &&
				    (j + 8 == line_start + line_len || kbuf[j+8] == ' ' || kbuf[j+8] == '\n')) {
					is_overlay = true;
					break;
				}
			}
			if (!is_overlay) {
				if (out != line_start)
					memmove(kbuf + out, kbuf + line_start, line_len);
				out += line_len;
				if (i < len) {
					kbuf[out++] = '\n';
					i++;
				}
			} else if (i < len) {
				i++; /* skip newline of the dropped overlay line */
			}
		} else {
			if (i < len)
				i++;
		}
	}
	return out;
}

/* Parse one maps line; return 0 on success. Fills in start,end,flags,pgoff,dev,ino,pathname.
 * Maps line format: start-end flags pgoff major:minor ino pathname */
static int kasumi_parse_maps_line(const char *line, size_t line_len,
		unsigned long *start, unsigned long *end, char *flags,
		unsigned long *pgoff, unsigned long *dev, unsigned long *ino,
		const char **pathname)
{
	unsigned int ma, mi;
	const char *p = line;
	char *endptr;

	if (line_len < 45) /* min "xxxxxxxx-xxxxxxxx xxxx xxxxxxxx xx:xx x \n" */
		return -1;
	*start = simple_strtoul(p, &endptr, 16);
	if (endptr == p || *endptr != '-')
		return -1;
	p = endptr + 1;
	*end = simple_strtoul(p, &endptr, 16);
	if (endptr == p || *endptr != ' ')
		return -1;
	p = endptr + 1;
	flags[0] = p[0]; flags[1] = p[1]; flags[2] = p[2]; flags[3] = p[3];
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

/* Filter /proc/pid/maps buffer: replace lines matching a rule with spoofed ino/dev/pathname.
 * In-place; spoofed line must not exceed original line length (pathname truncated if needed).
 * Returns new length. */
static size_t kasumi_filter_maps_lines(char *kbuf, size_t len)
{
	size_t in = 0, out = 0;
	struct kasumi_maps_rule_entry *r;
	const char *pathname;
	char auto_spoof_path[KSM_MAX_LEN_PATHNAME];
	char flags[5];
	unsigned long start, end, pgoff, dev, ino;
	unsigned long spoof_ino, spoof_dev;
	const char *spoof_name;
	size_t path_len, max_path;
	int n;

	while (in < len) {
		size_t line_start;
		size_t line_len;

		line_start = in;
		while (in < len && kbuf[in] != '\n')
			in++;
		if (in <= line_start) {
			if (in < len)
				in++;
			continue;
		}
		line_len = in - line_start;
		if (kbuf[in] == '\n')
			line_len++;
		if (kasumi_parse_maps_line(kbuf + line_start, line_len,
					 &start, &end, flags, &pgoff, &dev, &ino, &pathname) != 0) {
			if (out != line_start)
				memmove(kbuf + out, kbuf + line_start, line_len);
			out += line_len;
			in += (in < len && kbuf[in] == '\n') ? 1 : 0;
			continue;
		}
		spoof_ino = ino;
		spoof_dev = dev;
		spoof_name = pathname;
		if (kasumi_file_view_lookup_maps(ino, dev, &spoof_ino, &spoof_dev,
						 auto_spoof_path,
						 sizeof(auto_spoof_path)))
			spoof_name = auto_spoof_path;

		mutex_lock(&kasumi_maps_mutex);
		list_for_each_entry(r, &kasumi_maps_rules, list) {
			if (r->target_ino != ino)
				continue;
			if (r->target_dev != 0 && r->target_dev != dev)
				continue;
			spoof_ino = r->spoofed_ino;
			spoof_dev = r->spoofed_dev;
			spoof_name = r->spoofed_pathname;
			break;
		}
		mutex_unlock(&kasumi_maps_mutex);
		if (spoof_ino != ino || spoof_dev != dev || spoof_name != pathname) {
			/* Format new line; must not exceed line_len. */
			max_path = line_len;
			if (max_path > 1)
				max_path -= 1; /* \n */
			/* Reserve "%08lx-%08lx %s %08lx %02x:%02x %lu " = 8+1+8+1+4+1+8+1+5+1+max(ino)=20 ~56 */
			if (max_path > 56)
				max_path -= 56;
			else
				max_path = 0;
			n = scnprintf(kbuf + out, len - out, "%08lx-%08lx %s %08lx %02x:%02x %lu ",
				      start, end, flags, pgoff,
				      (unsigned int)MAJOR(spoof_dev), (unsigned int)MINOR(spoof_dev),
				      spoof_ino);
			path_len = strnlen(spoof_name, max_path);
			if ((size_t)line_len > n + 1 && n + path_len + 1 > line_len)
				path_len = (size_t)line_len - n - 1;
			if (path_len > 0)
				memcpy(kbuf + out + n, spoof_name, path_len);
			n += path_len;
			if (n < len - out)
				kbuf[out + n] = '\n';
			n++;
			out += n;
		} else {
			if (out != line_start)
				memmove(kbuf + out, kbuf + line_start, line_len);
			out += line_len;
		}
		if (in < len && kbuf[in] == '\n')
			in++;
	}
	return out;
}

static int kasumi_read_mount_filter_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long ret;
	struct kasumi_read_mount_ri_data *d = (struct kasumi_read_mount_ri_data *)ri->data;
	struct file *f;
	char *path_buf;
	char *path;
	size_t new_len;
	bool is_mountinfo;
	bool should_hide = false;
	bool fake_served = false;

	/* Fast path: skip when both mount_hide and maps_spoof are disabled */
	if (!(kasumi_feature_enabled_mask & (KSM_FEATURE_MOUNT_HIDE | KSM_FEATURE_MAPS_SPOOF)))
		return 0;

	/* Prevent recursion: our own kernel_read(/proc/self/mountinfo) during
	 * fake_mi cache regeneration arrives here as a sys_read return too. */
	if (kasumi_fake_mi_is_internal_read())
		return 0;

#if defined(__aarch64__)
	ret = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret = (long)regs->ax;
#else
	return 0;
#endif
	if (ret <= 0 || d->fd < 0 || !d->buf || ret > KASUMI_READ_MOUNT_FILTER_BUF)
		return 0;
	if (!kasumi_read_filter_buf)
		return 0;

	f = fget(d->fd);
	if (!f)
		return 0;
	path_buf = (char *)__get_free_page(GFP_KERNEL);
	if (!path_buf) {
		fput(f);
		return 0;
	}
	path_buf[0] = '\0';
	path = d_path(&f->f_path, path_buf, PAGE_SIZE);
	if (IS_ERR(path)) {
		free_page((unsigned long)path_buf);
		fput(f);
		return 0;
	}

	is_mountinfo = (kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE) &&
		       kasumi_path_is_proc_mount_view(path);
	if (is_mountinfo) {
		should_hide = kasumi_should_apply_hide_rules();
		kasumi_log("mount_filter: uid=%u comm=%s explicit=%d hide=%d path=%s\n",
			 __kuid_val(current_uid()), current->comm,
			 d->use_explicit_pos ? 1 : 0, should_hide ? 1 : 0, path);
	}

	/* /proc/.../mountinfo: marked apps get a precomputed fake snapshot that
	 * drops KSU-sourced mounts and renumbers ids contiguously. Unmarked
	 * readers (root, normal apps) are not touched here. */
	if (is_mountinfo && should_hide) {
		ssize_t fake_ret = kasumi_fake_mi_serve(f, d->buf, d->count, (ssize_t)ret,
						      d->use_explicit_pos ? d->pos : -1);
		kasumi_log("mount_filter: fake_ret=%zd kernel_ret=%ld\n", fake_ret, ret);
		if (fake_ret > 0) {
#if defined(__aarch64__)
			regs->regs[0] = (unsigned long)fake_ret;
#elif defined(__x86_64__)
			regs->ax = (unsigned long)fake_ret;
#endif
			fake_served = true;
		} else if (fake_ret == -1) {
			/* EOF signal from fake_mi (cursor past end of fake buffer). */
#if defined(__aarch64__)
			regs->regs[0] = 0;
#elif defined(__x86_64__)
			regs->ax = 0;
#endif
			fake_served = true;
		}
		/* fake_ret == 0 falls through to legacy overlay filter below. */
	}
	fput(f);

	if (fake_served) {
		free_page((unsigned long)path_buf);
		return 0;
	}

	mutex_lock(&kasumi_read_filter_mutex);
	if (copy_from_user(kasumi_read_filter_buf, d->buf, (size_t)ret)) {
		mutex_unlock(&kasumi_read_filter_mutex);
		free_page((unsigned long)path_buf);
		return 0;
	}

	/* /proc/.../mountinfo or /proc/mounts (unmarked, or fake unavailable): overlay-line filter */
	if (is_mountinfo) {
		free_page((unsigned long)path_buf);
		new_len = kasumi_filter_overlay_lines(kasumi_read_filter_buf, (size_t)ret);
		if (new_len < (size_t)ret) {
			if (copy_to_user(d->buf, kasumi_read_filter_buf, new_len) == 0) {
#if defined(__aarch64__)
				regs->regs[0] = (unsigned long)new_len;
#elif defined(__x86_64__)
				regs->ax = (unsigned long)new_len;
#endif
			}
		}
		mutex_unlock(&kasumi_read_filter_mutex);
		return 0;
	}

	/* /proc/.../maps or .../smaps: spoof ino/dev/pathname by rule */
	if ((kasumi_feature_enabled_mask & KSM_FEATURE_MAPS_SPOOF) &&
	    strncmp(path, "/proc/", 6) == 0 &&
	    (strstr(path, "/maps") || strstr(path, "/smaps"))) {
		free_page((unsigned long)path_buf);
		new_len = kasumi_filter_maps_lines(kasumi_read_filter_buf, (size_t)ret);
		if (new_len != (size_t)ret) {
			if (copy_to_user(d->buf, kasumi_read_filter_buf, new_len) == 0) {
#if defined(__aarch64__)
				regs->regs[0] = (unsigned long)new_len;
#elif defined(__x86_64__)
				regs->ax = (unsigned long)new_len;
#endif
			}
		}
		mutex_unlock(&kasumi_read_filter_mutex);
		return 0;
	}

	free_page((unsigned long)path_buf);
	mutex_unlock(&kasumi_read_filter_mutex);
	return 0;
}

static int kasumi_vfs_read_mount_filter_ret(struct kretprobe_instance *ri,
					     struct pt_regs *regs)
{
	long ret;
	struct kasumi_vfs_read_mount_ri_data *d =
		(struct kasumi_vfs_read_mount_ri_data *)ri->data;
	char *path_buf;
	char *path;
	size_t new_len;
	bool is_mountinfo;
	bool should_hide = false;
	bool fake_served = false;

	/* Fast path: skip when both mount_hide and maps_spoof are disabled */
	if (!(kasumi_feature_enabled_mask & (KSM_FEATURE_MOUNT_HIDE | KSM_FEATURE_MAPS_SPOOF)))
		return 0;
	if (kasumi_fake_mi_is_internal_read())
		return 0;

#if defined(__aarch64__)
	ret = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret = (long)regs->ax;
#else
	return 0;
#endif
	if (ret <= 0 || !d->file || !d->buf || ret > KASUMI_READ_MOUNT_FILTER_BUF)
		return 0;
	if (!kasumi_read_filter_buf)
		return 0;

	path_buf = (char *)__get_free_page(GFP_KERNEL);
	if (!path_buf)
		return 0;
	path_buf[0] = '\0';
	path = d_path(&d->file->f_path, path_buf, PAGE_SIZE);
	if (IS_ERR(path)) {
		free_page((unsigned long)path_buf);
		return 0;
	}

	is_mountinfo = (kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE) &&
		       kasumi_path_is_proc_mount_view(path);
	if (is_mountinfo) {
		should_hide = kasumi_should_apply_hide_rules();
		kasumi_log("mount_filter(vfs): uid=%u comm=%s explicit=%d hide=%d path=%s\n",
			 __kuid_val(current_uid()), current->comm,
			 d->use_explicit_pos ? 1 : 0, should_hide ? 1 : 0, path);
	}

	if (is_mountinfo && should_hide) {
		ssize_t fake_ret = kasumi_fake_mi_serve(d->file, d->buf, d->count,
						      (ssize_t)ret,
						      d->use_explicit_pos ? d->pos : -1);
		kasumi_log("mount_filter(vfs): fake_ret=%zd kernel_ret=%ld\n",
			 fake_ret, ret);
		if (fake_ret > 0) {
#if defined(__aarch64__)
			regs->regs[0] = (unsigned long)fake_ret;
#elif defined(__x86_64__)
			regs->ax = (unsigned long)fake_ret;
#endif
			fake_served = true;
		} else if (fake_ret == -1) {
#if defined(__aarch64__)
			regs->regs[0] = 0;
#elif defined(__x86_64__)
			regs->ax = 0;
#endif
			fake_served = true;
		}
	}

	if (fake_served) {
		free_page((unsigned long)path_buf);
		return 0;
	}

	mutex_lock(&kasumi_read_filter_mutex);
	if (copy_from_user(kasumi_read_filter_buf, d->buf, (size_t)ret)) {
		mutex_unlock(&kasumi_read_filter_mutex);
		free_page((unsigned long)path_buf);
		return 0;
	}

	if (is_mountinfo) {
		free_page((unsigned long)path_buf);
		new_len = kasumi_filter_overlay_lines(kasumi_read_filter_buf, (size_t)ret);
		if (new_len < (size_t)ret) {
			if (copy_to_user(d->buf, kasumi_read_filter_buf, new_len) == 0) {
#if defined(__aarch64__)
				regs->regs[0] = (unsigned long)new_len;
#elif defined(__x86_64__)
				regs->ax = (unsigned long)new_len;
#endif
			}
		}
		mutex_unlock(&kasumi_read_filter_mutex);
		return 0;
	}

	if ((kasumi_feature_enabled_mask & KSM_FEATURE_MAPS_SPOOF) &&
	    strncmp(path, "/proc/", 6) == 0 &&
	    (strstr(path, "/maps") || strstr(path, "/smaps"))) {
		free_page((unsigned long)path_buf);
		new_len = kasumi_filter_maps_lines(kasumi_read_filter_buf, (size_t)ret);
		if (new_len != (size_t)ret) {
			if (copy_to_user(d->buf, kasumi_read_filter_buf, new_len) == 0) {
#if defined(__aarch64__)
				regs->regs[0] = (unsigned long)new_len;
#elif defined(__x86_64__)
				regs->ax = (unsigned long)new_len;
#endif
			}
		}
		mutex_unlock(&kasumi_read_filter_mutex);
		return 0;
	}

	free_page((unsigned long)path_buf);
	mutex_unlock(&kasumi_read_filter_mutex);
	return 0;
}

static struct kretprobe kasumi_krp_vfs_read_mount_filter = {
	.entry_handler = kasumi_vfs_read_mount_filter_entry,
	.handler = kasumi_vfs_read_mount_filter_ret,
	.data_size = sizeof(struct kasumi_vfs_read_mount_ri_data),
	.maxactive = 64,
};

static struct kretprobe kasumi_krp_read_mount_filter = {
	.entry_handler = kasumi_read_mount_filter_entry,
	.handler = kasumi_read_mount_filter_ret,
	.data_size = sizeof(struct kasumi_read_mount_ri_data),
	.maxactive = 64,
};

static struct kretprobe kasumi_krp_pread_mount_filter = {
	.entry_handler = kasumi_pread_mount_filter_entry,
	.handler = kasumi_read_mount_filter_ret,
	.data_size = sizeof(struct kasumi_read_mount_ri_data),
	.maxactive = 64,
};

/* Maps spoof fallback when read syscall path unavailable: kretprobe on seq_read.
 * seq_read(file,buf,size,ppos) is used by /proc/pid/maps. Filter only maps/smaps paths. */
static char *kasumi_maps_spoof_buf;
static DEFINE_MUTEX(kasumi_maps_spoof_mutex);

struct kasumi_seq_read_ri_data {
	struct file *file;
	void __user *buf;
	size_t size;
};

static int kasumi_seq_read_maps_filter_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kasumi_seq_read_ri_data *d = (struct kasumi_seq_read_ri_data *)ri->data;
#if defined(__aarch64__)
	d->file = (struct file *)regs->regs[0];
	d->buf = (void __user *)regs->regs[1];
	d->size = (size_t)regs->regs[2];
#elif defined(__x86_64__)
	d->file = (struct file *)regs->di;
	d->buf = (void __user *)regs->si;
	d->size = (size_t)regs->dx;
#else
	d->file = NULL;
	d->buf = NULL;
	d->size = 0;
#endif
	return 0;
}

static int kasumi_seq_read_maps_filter_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long ret;
	struct kasumi_seq_read_ri_data *d = (struct kasumi_seq_read_ri_data *)ri->data;
	char *path_buf;
	char *path;
	size_t new_len;

	if (!(kasumi_feature_enabled_mask & KSM_FEATURE_MAPS_SPOOF))
		return 0;
	if (!d->file || !d->buf || !kasumi_maps_spoof_buf || !kasumi_d_path)
		return 0;

#if defined(__aarch64__)
	ret = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret = (long)regs->ax;
#else
	return 0;
#endif
	if (ret <= 0 || ret > KASUMI_READ_MOUNT_FILTER_BUF)
		return 0;

	path_buf = (char *)__get_free_page(GFP_KERNEL);
	if (!path_buf)
		return 0;
	path_buf[0] = '\0';
	path = kasumi_d_path(&d->file->f_path, path_buf, PAGE_SIZE);
	if (IS_ERR(path) || path[0] != '/' || strncmp(path, "/proc/", 6) != 0 ||
	    (!strstr(path, "/maps") && !strstr(path, "/smaps"))) {
		free_page((unsigned long)path_buf);
		return 0;
	}
	free_page((unsigned long)path_buf);

	mutex_lock(&kasumi_maps_spoof_mutex);
	if (copy_from_user(kasumi_maps_spoof_buf, d->buf, (size_t)ret)) {
		mutex_unlock(&kasumi_maps_spoof_mutex);
		return 0;
	}
	new_len = kasumi_filter_maps_lines(kasumi_maps_spoof_buf, (size_t)ret);
	if (new_len != (size_t)ret) {
		if (copy_to_user(d->buf, kasumi_maps_spoof_buf, new_len) == 0) {
#if defined(__aarch64__)
			regs->regs[0] = (unsigned long)new_len;
#elif defined(__x86_64__)
			regs->ax = (unsigned long)new_len;
#endif
		}
	}
	mutex_unlock(&kasumi_maps_spoof_mutex);
	return 0;
}

static struct kretprobe kasumi_krp_seq_read_maps = {
	.entry_handler = kasumi_seq_read_maps_filter_entry,
	.handler = kasumi_seq_read_maps_filter_ret,
	.data_size = sizeof(struct kasumi_seq_read_ri_data),
	.maxactive = 64,
};

/* statfs f_type spoof: make direct (statfs) match resolved (mountinfo) to avoid INCONSISTENT_MOUNT.
 * We resolve the real (lower) fs type at statfs entry via d_real_inode and pass it through in ret.
 * OVERLAYFS_SUPER_MAGIC from uapi/linux/magic.h so we use the running kernel's definition.
 *
 * Two routes share the same resolver:
 *   - sys_enter/sys_exit tracepoint dispatcher (preferred when registered)
 *   - kretprobe on __arm64_sys_statfs (legacy fallback)
 */

struct kasumi_statfs_ri_data {
	void __user *buf;
	unsigned long spoof_f_type; /* real (lower) s_magic; 0 = do not spoof */
};

unsigned long kasumi_statfs_resolve_spoof_magic(const char *path)
{
	struct path p;
	struct inode *real_ino;
	unsigned long spoof = 0;

	if (!path || !kasumi_kern_path)
		return 0;
	if (kasumi_kern_path(path, 0, &p) != 0)
		return 0;
	if ((unsigned long)p.dentry->d_sb->s_magic == OVERLAYFS_SUPER_MAGIC) {
		real_ino = kasumi_d_real_inode_impl(p.dentry);
		if (real_ino && real_ino->i_sb != p.dentry->d_sb)
			spoof = (unsigned long)real_ino->i_sb->s_magic;
		else
			spoof = (unsigned long)EROFS_SUPER_MAGIC;
	}
	path_put(&p);
	return spoof;
}

void kasumi_statfs_apply_spoof(void __user *buf, unsigned long spoof_f_type)
{
	u64 f_type;

	if (!buf || spoof_f_type == 0)
		return;
	if (copy_from_user(&f_type, buf, sizeof(f_type)))
		return;
	if ((f_type & 0xffffffffUL) == OVERLAYFS_SUPER_MAGIC) {
		f_type = (f_type & 0xffffffff00000000UL) | (spoof_f_type & 0xffffffffUL);
		/* best-effort spoof; ignore write failure */
		if (copy_to_user(buf, &f_type, sizeof(f_type)))
			(void)0;
	}
}

void kasumi_handle_sys_enter_statfs(struct pt_regs *regs, long id)
{
#if defined(__aarch64__) || defined(__x86_64__)
	struct kasumi_percpu *pcpu = kasumi_this_cpu();
	const char __user *pathname_user;
	void __user *buf;
	char path_buf[KSM_MAX_LEN_PATHNAME];

	pcpu->statfs_ctx.active = 0;
#ifdef __NR_statfs
	if (id != __NR_statfs)
		return;
#else
	(void)id;
	return;
#endif
	if (!(kasumi_feature_enabled_mask & KSM_FEATURE_STATFS_SPOOF))
		return;
#if defined(__aarch64__)
	pathname_user = (const char __user *)(uintptr_t)regs->regs[0];
	buf = (void __user *)(uintptr_t)regs->regs[1];
#else
	pathname_user = (const char __user *)(uintptr_t)regs->di;
	buf = (void __user *)(uintptr_t)regs->si;
#endif
	if (!pathname_user || !buf)
		return;
	if (kasumi_strncpy_from_user_nofault) {
		long n = kasumi_strncpy_from_user_nofault(path_buf, pathname_user,
							  sizeof(path_buf) - 1);
		if (n < 0)
			return;
		path_buf[n < (long)(sizeof(path_buf) - 1) ? n :
			 (long)(sizeof(path_buf) - 1)] = '\0';
	} else {
		if (copy_from_user(path_buf, pathname_user, sizeof(path_buf) - 1))
			return;
		path_buf[sizeof(path_buf) - 1] = '\0';
	}

	pcpu->statfs_ctx.spoof_f_type = kasumi_statfs_resolve_spoof_magic(path_buf);
	if (pcpu->statfs_ctx.spoof_f_type == 0)
		return;
	pcpu->statfs_ctx.buf = buf;
	pcpu->statfs_ctx.active = 1;
#else
	(void)regs;
	(void)id;
#endif
}

void kasumi_handle_sys_exit_statfs(struct pt_regs *regs, long ret)
{
#if defined(__aarch64__) || defined(__x86_64__)
	struct kasumi_percpu *pcpu = kasumi_this_cpu();

	(void)regs;
	if (!pcpu->statfs_ctx.active)
		return;
	pcpu->statfs_ctx.active = 0;
	if (ret < 0)
		return;
	kasumi_statfs_apply_spoof(pcpu->statfs_ctx.buf, pcpu->statfs_ctx.spoof_f_type);
#else
	(void)regs;
	(void)ret;
#endif
}

static int kasumi_statfs_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kasumi_statfs_ri_data *d = (struct kasumi_statfs_ri_data *)ri->data;
	const char __user *pathname;
#if defined(__aarch64__)
	d->buf = (void __user *)regs->regs[1];
	pathname = (const char __user *)regs->regs[0];
#elif defined(__x86_64__)
	d->buf = (void __user *)regs->si;
	pathname = (const char __user *)regs->di;
#else
	d->buf = NULL;
	pathname = NULL;
#endif
	d->spoof_f_type = 0;
	if (!(kasumi_feature_enabled_mask & KSM_FEATURE_STATFS_SPOOF) ||
	    !pathname)
		return 0;
	{
		char path_buf[KSM_MAX_LEN_PATHNAME];
		unsigned int n;

		n = copy_from_user(path_buf, pathname, sizeof(path_buf) - 1);
		path_buf[sizeof(path_buf) - 1] = '\0';
		if (n != 0)
			return 0;
		d->spoof_f_type = kasumi_statfs_resolve_spoof_magic(path_buf);
	}
	return 0;
}

static int kasumi_statfs_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long ret;
#if defined(__aarch64__)
	ret = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret = (long)regs->ax;
#else
	return 0;
#endif
	if (ret < 0)
		return 0;
	{
		struct kasumi_statfs_ri_data *d = (struct kasumi_statfs_ri_data *)ri->data;

		kasumi_statfs_apply_spoof(d->buf, d->spoof_f_type);
	}
	return 0;
}

static struct kretprobe kasumi_krp_statfs = {
	.entry_handler = kasumi_statfs_entry,
	.handler = kasumi_statfs_ret,
	.data_size = sizeof(struct kasumi_statfs_ri_data),
	.maxactive = 64,
};

void kasumi_proc_read_hooks_init(void)
{
	static const char *read_syms[] = {
#if defined(__aarch64__)
		"__arm64_sys_read", "sys_read", "SyS_read", NULL
#elif defined(__x86_64__)
		"__x64_sys_read", "sys_read", "SyS_read", NULL
#elif defined(__arm__)
		"__arm_sys_read", "sys_read", "SyS_read", NULL
#else
		"sys_read", "SyS_read", NULL
#endif
	};
	static const char *pread_syms[] = {
#if defined(__aarch64__)
		"__arm64_sys_pread64", "sys_pread64", "ksys_pread64", "SyS_pread64", NULL
#elif defined(__x86_64__)
		"__x64_sys_pread64", "sys_pread64", "ksys_pread64", "SyS_pread64", NULL
#elif defined(__arm__)
		"__arm_sys_pread64", "sys_pread64", "ksys_pread64", "SyS_pread64", NULL
#else
		"sys_pread64", "ksys_pread64", "SyS_pread64", NULL
#endif
	};
	unsigned long vfs_read_addr = 0;
	unsigned long read_addr = 0;
	unsigned long pread_addr = 0;
	const char *read_sym_name = NULL;
	const char *pread_sym_name = NULL;
	bool use_proxy_filter = kasumi_tracepoint_path_registered();
	bool use_syscall_filter = false;
	int i;

	if (use_proxy_filter) {
		kasumi_read_filter_buf = vmalloc(KASUMI_READ_MOUNT_FILTER_BUF);
		if (kasumi_read_filter_buf) {
			kasumi_proc_proxy_registered = 1;
			pr_info("Kasumi: proc read filtering via open fd proxy, kprobes kept as fallback\n");
		} else {
			use_proxy_filter = false;
			pr_warn("Kasumi: proc proxy buffer allocation failed, falling back to read kretprobes\n");
		}
	}

	if (!use_proxy_filter) {
		for (i = 0; read_syms[i]; i++) {
			read_addr = kasumi_lookup_name(read_syms[i]);
			if (read_addr) {
				read_sym_name = read_syms[i];
				break;
			}
		}
		for (i = 0; pread_syms[i]; i++) {
			pread_addr = kasumi_lookup_name(pread_syms[i]);
			if (pread_addr) {
				pread_sym_name = pread_syms[i];
				break;
			}
		}
	}

	if (!use_proxy_filter && (vfs_read_addr || read_addr || pread_addr)) {
		kasumi_read_filter_buf = vmalloc(KASUMI_READ_MOUNT_FILTER_BUF);
		if (kasumi_read_filter_buf) {
			if (!use_syscall_filter && read_addr) {
				kasumi_krp_read_mount_filter.kp.addr = (kprobe_opcode_t *)read_addr;
				if (register_kretprobe(&kasumi_krp_read_mount_filter) == 0) {
					kasumi_mount_hide_read_fallback_registered = 1;
					use_syscall_filter = true;
					pr_info("Kasumi: mount hide via kretprobe on %s (read buffer filter, preferred)\n",
						read_sym_name);
				}
			}
			if (!use_syscall_filter && pread_addr) {
				kasumi_krp_pread_mount_filter.kp.addr = (kprobe_opcode_t *)pread_addr;
				if (register_kretprobe(&kasumi_krp_pread_mount_filter) == 0) {
					kasumi_mount_hide_pread_fallback_registered = 1;
					use_syscall_filter = true;
					pr_info("Kasumi: mount hide via kretprobe on %s (pread64 buffer filter)\n",
						pread_sym_name);
				}
			}
			if (!use_syscall_filter) {
				vfree(kasumi_read_filter_buf);
				kasumi_read_filter_buf = NULL;
			} else {
				pr_info("Kasumi: mount hide prefers syscall buffer filtering when available\n");
			}
		}
	}

	if (!use_proxy_filter && !use_syscall_filter) {
		unsigned long addr_vfsmnt = kasumi_lookup_name("show_vfsmnt");
		unsigned long addr_mountinfo = kasumi_lookup_name("show_mountinfo");

		if (vfs_read_addr || read_addr || pread_addr)
			pr_info("Kasumi: mount hide syscall filter unavailable, falling back to kprobe\n");
		else
			pr_warn("Kasumi: vfs_read/read/pread64 not found, trying kprobe on show_vfsmnt/show_mountinfo\n");
		if (addr_vfsmnt) {
			kasumi_kp_show_vfsmnt.addr = (kprobe_opcode_t *)addr_vfsmnt;
			if (register_kprobe(&kasumi_kp_show_vfsmnt) == 0) {
				kasumi_mount_hide_vfsmnt_registered = 1;
				pr_info("Kasumi: mount hide via kprobe on show_vfsmnt (/proc/mounts)\n");
			}
		} else {
			pr_warn("Kasumi: show_vfsmnt not found\n");
		}
		if (addr_mountinfo) {
			kasumi_kp_show_mountinfo.addr = (kprobe_opcode_t *)addr_mountinfo;
			if (register_kprobe(&kasumi_kp_show_mountinfo) == 0) {
				kasumi_mount_hide_mountinfo_registered = 1;
				pr_info("Kasumi: mount hide via kprobe on show_mountinfo (/proc/pid/mountinfo)\n");
			}
		} else {
			pr_warn("Kasumi: show_mountinfo not found\n");
		}
		{
			unsigned long seq_read_addr = kasumi_lookup_name("seq_read");

			if (seq_read_addr) {
				kasumi_maps_spoof_buf = vmalloc(KASUMI_READ_MOUNT_FILTER_BUF);
				if (kasumi_maps_spoof_buf) {
					kasumi_krp_seq_read_maps.kp.addr = (kprobe_opcode_t *)seq_read_addr;
					if (register_kretprobe(&kasumi_krp_seq_read_maps) == 0) {
						kasumi_maps_seq_read_registered = 1;
						pr_info("Kasumi: maps spoof via kretprobe on seq_read (fallback)\n");
					} else {
						vfree(kasumi_maps_spoof_buf);
						kasumi_maps_spoof_buf = NULL;
					}
				}
			} else {
				pr_warn("Kasumi: seq_read not found, maps spoof disabled when read path unavailable\n");
			}
		}
	}

	if (!kasumi_statfs_kretprobe_registered) {
		/* Always kretprobe, never tracepoint: kern_path() may
		 * sleep but tracepoint runs in atomic context. */
		{
			static const char *statfs_syms[] = {
#if defined(__aarch64__)
				"__arm64_sys_statfs", "sys_statfs", "SyS_statfs", NULL
#elif defined(__x86_64__)
				"__x64_sys_statfs", "sys_statfs", "SyS_statfs", NULL
#elif defined(__arm__)
				"__arm_sys_statfs", "sys_statfs", "SyS_statfs", NULL
#else
				"sys_statfs", "SyS_statfs", NULL
#endif
			};
			unsigned long statfs_addr = 0;
			int j;

			for (j = 0; statfs_syms[j]; j++) {
				statfs_addr = kasumi_lookup_name(statfs_syms[j]);
				if (statfs_addr)
					break;
			}
			if (statfs_addr) {
				kasumi_krp_statfs.kp.addr = (kprobe_opcode_t *)statfs_addr;
				if (register_kretprobe(&kasumi_krp_statfs) == 0) {
					kasumi_statfs_kretprobe_registered = 1;
					pr_info("Kasumi: statfs f_type spoof via kretprobe on %s (INCONSISTENT_MOUNT bypass)\n",
						statfs_syms[j]);
				} else {
					pr_warn("Kasumi: statfs kretprobe register failed\n");
				}
			} else {
				pr_warn("Kasumi: statfs syscall not found, INCONSISTENT_MOUNT bypass disabled\n");
			}
		}
	}
}

void kasumi_proc_read_hooks_exit(void)
{
	bool had_proc_proxy = kasumi_proc_proxy_registered;

	/* Drain installed proc-fd proxies first: restore original f_op on every
	 * tracked file and wait for in-flight callers to leave proxy_read /
	 * proxy_release before we free the proxy structs. With .owner = NULL on
	 * the proxy fops, this is what allows rmmod to succeed even when long-
	 * lived processes still hold proxied /proc fds open.
	 */
	kasumi_mount_proxy_drain();

	if (kasumi_statfs_kretprobe_registered)
		unregister_kretprobe(&kasumi_krp_statfs);
	kasumi_statfs_tracepoint_registered = 0;
	if (kasumi_mount_hide_vfs_read_registered)
		unregister_kretprobe(&kasumi_krp_vfs_read_mount_filter);
	if (kasumi_mount_hide_read_fallback_registered)
		unregister_kretprobe(&kasumi_krp_read_mount_filter);
	if (kasumi_mount_hide_pread_fallback_registered)
		unregister_kretprobe(&kasumi_krp_pread_mount_filter);
	if (kasumi_read_filter_buf) {
		vfree(kasumi_read_filter_buf);
		kasumi_read_filter_buf = NULL;
	}
	if (kasumi_maps_seq_read_registered) {
		unregister_kretprobe(&kasumi_krp_seq_read_maps);
		if (kasumi_maps_spoof_buf) {
			vfree(kasumi_maps_spoof_buf);
			kasumi_maps_spoof_buf = NULL;
		}
	}
	if (had_proc_proxy ||
	    kasumi_mount_hide_vfs_read_registered ||
	    kasumi_mount_hide_read_fallback_registered ||
	    kasumi_mount_hide_pread_fallback_registered ||
	    kasumi_maps_seq_read_registered) {
		struct kasumi_maps_rule_entry *e, *tmp;

		mutex_lock(&kasumi_maps_mutex);
		list_for_each_entry_safe(e, tmp, &kasumi_maps_rules, list) {
			list_del(&e->list);
			kfree(e);
		}
		mutex_unlock(&kasumi_maps_mutex);
	}
	kasumi_proc_proxy_registered = 0;
	if (kasumi_mount_hide_mountinfo_registered)
		unregister_kprobe(&kasumi_kp_show_mountinfo);
	if (kasumi_mount_hide_vfsmnt_registered)
		unregister_kprobe(&kasumi_kp_show_vfsmnt);
}
