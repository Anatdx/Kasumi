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
#include <linux/statfs.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/namei.h>
#include <uapi/linux/magic.h>
#ifndef EROFS_SUPER_MAGIC
#define EROFS_SUPER_MAGIC 0xe0f5e1e2
#endif
#include <asm/unistd.h>

#include "kasumi_runtime.h"
#include "kasumi_root_detection.h"
#include "kasumi_store.h"
#include "kasumi_file_view.h"
#include "kasumi_entrypoints.h"
#include "kasumi_path_policy.h"
#include "kasumi_proc_hooks.h"
#include "kasumi_syscall_redirect.h"
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

#define KASUMI_READ_MOUNT_FILTER_BUF 65536
static char *kasumi_read_filter_buf;
static DEFINE_MUTEX(kasumi_read_filter_mutex);

static size_t kasumi_filter_overlay_lines(char *kbuf, size_t len);
static size_t kasumi_filter_maps_lines(char *kbuf, size_t len, bool *changed);

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
	if (!kasumi_root_allows_spoofing() || !kasumi_should_apply_hide_rules())
		return KASUMI_PROC_PROXY_NONE;
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

bool kasumi_proc_proxy_should_try(void)
{
	if (!READ_ONCE(kasumi_proc_proxy_registered))
		return false;
	if (!kasumi_root_allows_spoofing() || !kasumi_should_apply_hide_rules())
		return false;
	return (kasumi_feature_enabled_mask &
		(KSM_FEATURE_MOUNT_HIDE | KSM_FEATURE_MAPS_SPOOF)) != 0;
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
	bool maps_changed;
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
		if (!kasumi_should_apply_hide_rules())
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
		if (!kasumi_should_apply_hide_rules())
			goto out;
		mutex_lock(&kasumi_read_filter_mutex);
		if (copy_from_user(kasumi_read_filter_buf, buf, (size_t)ret)) {
			mutex_unlock(&kasumi_read_filter_mutex);
			goto out;
		}
		new_len = kasumi_filter_maps_lines(kasumi_read_filter_buf, (size_t)ret,
						   &maps_changed);
		if (maps_changed &&
		    copy_to_user(buf, kasumi_read_filter_buf, new_len) == 0)
			ret = (ssize_t)new_len;
		mutex_unlock(&kasumi_read_filter_mutex);
		goto out;
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

static KASUMI_NOCFI int kasumi_mount_proxy_release(struct inode *inode, struct file *file)
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
		kasumi_call_srcu_ptr(&kasumi_proxy_srcu, &proxy->rcu,
				     kasumi_mount_proxy_rcu_free);
	}
	/* drained side: kasumi_mount_proxy_drain() owns the kfree */
	return ret;
}

KASUMI_NOCFI int kasumi_mount_proxy_install_fd(int fd)
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
	if (!kasumi_d_path) {
		free_page((unsigned long)path_buf);
		ret = -ENOENT;
		goto out;
	}
	path = kasumi_d_path(&file->f_path, path_buf, PAGE_SIZE);
	if (IS_ERR(path)) {
		free_page((unsigned long)path_buf);
		goto out;
	}
	kind = kasumi_proc_proxy_kind_for_path(path);
	if (kind == KASUMI_PROC_PROXY_NONE) {
		free_page((unsigned long)path_buf);
		goto out;
	}
	if (kind == KASUMI_PROC_PROXY_MOUNTINFO)
		(void)kasumi_fake_mi_prepare(false);
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

KASUMI_NOCFI void kasumi_mount_proxy_drain(void)
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
	kasumi_srcu_barrier_ptr(&kasumi_proxy_srcu);
}

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
			bool is_overlay = false;
			size_t j;

			for (j = line_start; j + 8 <= line_start + line_len; j++) {
				if (kbuf[j] == ' ' && kbuf[j + 1] == 'o' &&
				    kbuf[j + 2] == 'v' && kbuf[j + 3] == 'e' &&
				    kbuf[j + 4] == 'r' && kbuf[j + 5] == 'l' &&
				    kbuf[j + 6] == 'a' && kbuf[j + 7] == 'y' &&
				    (j + 8 == line_start + line_len ||
				     kbuf[j + 8] == ' ' || kbuf[j + 8] == '\n')) {
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
				i++;
			}
		} else if (i < len) {
			i++;
		}
	}
	return out;
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

	if (line_len < 45)
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

static size_t kasumi_filter_maps_lines(char *kbuf, size_t len, bool *changed)
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

	if (changed)
		*changed = false;

	while (in < len) {
		size_t line_start = in;
		size_t line_len;
		bool complete_line;

		while (in < len && kbuf[in] != '\n')
			in++;
		complete_line = in < len && kbuf[in] == '\n';
		line_len = in - line_start;
		if (complete_line)
			line_len++;

		if (line_len == 0) {
			if (complete_line) {
				if (out != line_start)
					kbuf[out] = '\n';
				out++;
				in++;
			}
			continue;
		}
		if (!complete_line) {
			if (out != line_start)
				memmove(kbuf + out, kbuf + line_start, line_len);
			out += line_len;
			break;
		}

		if (kasumi_parse_maps_line(kbuf + line_start, line_len, &start,
					   &end, flags, &pgoff, &dev, &ino,
					   &pathname) != 0) {
			if (out != line_start)
				memmove(kbuf + out, kbuf + line_start, line_len);
			out += line_len;
			in++;
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
			size_t body_len = line_len > 0 ? line_len - 1 : 0;

			max_path = body_len > 56 ? body_len - 56 : 0;
			n = scnprintf(kbuf + out, min(line_len, len - out),
				      "%08lx-%08lx %s %08lx %02x:%02x %lu ",
				      start, end, flags, pgoff,
				      (unsigned int)MAJOR(spoof_dev),
				      (unsigned int)MINOR(spoof_dev), spoof_ino);
			path_len = strnlen(spoof_name, max_path);
			if (body_len > n && n + path_len > body_len)
				path_len = body_len - n;
			if (path_len > 0 && body_len > n)
				memcpy(kbuf + out + n, spoof_name, path_len);
			n += path_len;
			if (body_len > n)
				memset(kbuf + out + n, ' ', body_len - n);
			if (complete_line)
				kbuf[out + body_len] = '\n';
			out += line_len;
			if (changed)
				*changed = true;
		} else {
			if (out != line_start)
				memmove(kbuf + out, kbuf + line_start, line_len);
			out += line_len;
		}
		in++;
	}
	return out;
}

struct kasumi_vfs_statfs_ri_data {
	struct kstatfs *buf;
	unsigned long spoof_f_type;
};

static unsigned long kasumi_statfs_spoof_magic(struct dentry *dentry)
{
	struct inode *real_ino;

	if (!dentry || !dentry->d_sb)
		return 0;
	if ((unsigned long)dentry->d_sb->s_magic != OVERLAYFS_SUPER_MAGIC)
		return 0;
	real_ino = kasumi_d_real_inode_impl(dentry);
	if (real_ino && real_ino->i_sb != dentry->d_sb)
		return (unsigned long)real_ino->i_sb->s_magic;
	return (unsigned long)EROFS_SUPER_MAGIC;
}

static int kasumi_vfs_statfs_entry(struct kretprobe_instance *ri,
					   struct pt_regs *regs)
{
	struct kasumi_vfs_statfs_ri_data *d = (void *)ri->data;
	const struct path *path;

#if defined(__aarch64__)
	path = (const struct path *)regs->regs[0];
	d->buf = (struct kstatfs *)regs->regs[1];
#elif defined(__x86_64__)
	path = (const struct path *)regs->di;
	d->buf = (struct kstatfs *)regs->si;
#else
	path = NULL;
	d->buf = NULL;
#endif
	d->spoof_f_type = 0;
	if (!(kasumi_feature_enabled_mask & KSM_FEATURE_STATFS_SPOOF) ||
	    !kasumi_should_apply_hide_rules() ||
	    !path || !path->dentry || !d->buf)
		return 0;
	d->spoof_f_type = kasumi_statfs_spoof_magic(path->dentry);
	return 0;
}

static int kasumi_vfs_statfs_ret(struct kretprobe_instance *ri,
					 struct pt_regs *regs)
{
	struct kasumi_vfs_statfs_ri_data *d = (void *)ri->data;
	long ret;

#if defined(__aarch64__)
	ret = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret = (long)regs->ax;
#else
	return 0;
#endif
	if (ret == 0 && d->buf && d->spoof_f_type &&
	    ((unsigned long)d->buf->f_type & 0xffffffffUL) ==
		OVERLAYFS_SUPER_MAGIC)
		d->buf->f_type = d->spoof_f_type;
	return 0;
}

static struct kretprobe kasumi_krp_vfs_statfs = {
	.entry_handler = kasumi_vfs_statfs_entry,
	.handler = kasumi_vfs_statfs_ret,
	.data_size = sizeof(struct kasumi_vfs_statfs_ri_data),
	.maxactive = 64,
};

void kasumi_proc_read_hooks_init(void)
{
	unsigned long statfs_addr = kasumi_lookup_name("vfs_statfs");
	bool use_proxy_filter = kasumi_syscall_dispatcher_nr >= 0 &&
				kasumi_has_syscall_hook(__NR_openat);

	if (statfs_addr) {
		kasumi_krp_vfs_statfs.kp.addr = (kprobe_opcode_t *)statfs_addr;
		if (register_kretprobe(&kasumi_krp_vfs_statfs) == 0) {
			kasumi_statfs_kretprobe_registered = 1;
			pr_info("Kasumi: statfs spoofing via vfs_statfs\n");
		} else {
			pr_warn("Kasumi: register_kretprobe(vfs_statfs) failed\n");
		}
	} else {
		pr_warn("Kasumi: vfs_statfs not found, statfs spoofing disabled\n");
	}

	if (use_proxy_filter) {
		kasumi_read_filter_buf = vmalloc(KASUMI_READ_MOUNT_FILTER_BUF);
		if (kasumi_read_filter_buf) {
			kasumi_proc_proxy_registered = 1;
			pr_info("Kasumi: proc views filtered by per-open fop proxy\n");
		} else {
			use_proxy_filter = false;
			pr_warn("Kasumi: proc proxy buffer allocation failed\n");
		}
	}

	if (!use_proxy_filter) {
		unsigned long addr_vfsmnt = kasumi_lookup_name("show_vfsmnt");
		unsigned long addr_mountinfo = kasumi_lookup_name("show_mountinfo");

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
		pr_warn("Kasumi: maps spoof unavailable without per-open proxy\n");
	}
}

void kasumi_proc_read_hooks_exit(void)
{
	/* Drain installed proc-fd proxies first: restore original f_op on every
	 * tracked file and wait for in-flight callers to leave proxy_read /
	 * proxy_release before we free the proxy structs. With .owner = NULL on
	 * the proxy fops, this is what allows rmmod to succeed even when long-
	 * lived processes still hold proxied /proc fds open.
	 */
	kasumi_mount_proxy_drain();
	if (kasumi_statfs_kretprobe_registered) {
		unregister_kretprobe(&kasumi_krp_vfs_statfs);
		kasumi_statfs_kretprobe_registered = 0;
	}

	if (kasumi_read_filter_buf) {
		vfree(kasumi_read_filter_buf);
		kasumi_read_filter_buf = NULL;
	}
	{
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
