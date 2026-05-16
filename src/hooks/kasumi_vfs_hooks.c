/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - VFS-facing path, stat, xattr, and iterate_dir hook implementations.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && !defined(arch_ftrace_get_regs)
#define arch_ftrace_get_regs(fregs) (NULL)
#endif
#include <linux/kprobes.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/jhash.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/sched/task.h>
#include <linux/fs_struct.h>
#include <linux/dirent.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/anon_inodes.h>
#include <linux/fcntl.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/utsname.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#include <linux/seq_file.h>
#include <uapi/linux/magic.h>
#ifndef EROFS_SUPER_MAGIC
#define EROFS_SUPER_MAGIC 0xe0f5e1e2
#endif
#include <asm/unistd.h>
#include "kasumi_runtime.h"
#include "kasumi_store.h"
#include "kasumi_entrypoints.h"
#include "kasumi_path_policy.h"
#include "kasumi_overlay.h"
#include "kasumi_vfs_hooks.h"
#include "kasumi_proc_hooks.h"
#include "kasumi_ftrace_hooks.h"
#include "kasumi_fake_mountinfo.h"
#include "kasumi_iop_override.h"
#include "kasumi_fop_override.h"
#include "kasumi_syscall_redirect.h"

#ifndef KASUMI_VFS_KPROBES
#define KASUMI_VFS_KPROBES 1
#endif

#define KASUMI_MAGIC_POS 0x1000000000000000ULL
/* ======================================================================
 * iterate_dir: filldir filter (runs in fs callback context, not kprobe)
 * ====================================================================== */

KASUMI_NOCFI KASUMI_FILLDIR_RET_TYPE
kasumi_filldir_filter(struct dir_context *ctx, const char *name,
		      int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	struct kasumi_filldir_wrapper *w =
		container_of(ctx, struct kasumi_filldir_wrapper, wrap_ctx);
	KASUMI_FILLDIR_RET_TYPE ret;

	if (!kasumi_should_apply_hide_rules())
		goto passthrough;

	/* Inject phase: before first real entry, emit entries from merge targets
	 * and kasumi_paths into the directory listing. */
	if (w->dir_has_inject && !w->inject_done && w->dir_path && w->parent_dentry) {
		struct list_head head;
		struct kasumi_name_list *item, *tmp;
		loff_t inj_pos = KASUMI_MAGIC_POS;

		w->inject_done = true;
		INIT_LIST_HEAD(&head);
		kasumi_populate_injected_list(w->dir_path, w->parent_dentry, &head);

		list_for_each_entry_safe(item, tmp, &head, list) {
			int nlen = strlen(item->name);
			if (unlikely(!w->orig_ctx || !w->orig_ctx->actor))
				break;
			ret = w->orig_ctx->actor(w->orig_ctx, item->name, nlen,
						 inj_pos, 1, item->type);
			atomic64_inc(&kasumi_hook_stats.filldir_injected);
			list_del(&item->list);
			kfree(item->name);
			kfree(item);
			if (ret != KASUMI_FILLDIR_CONTINUE) {
				list_for_each_entry_safe(item, tmp, &head, list) {
					list_del(&item->list);
					kfree(item->name);
					kfree(item);
				}
				return ret;
			}
			inj_pos++;
		}
	}

	if (unlikely(namlen <= 2 && name[0] == '.')) {
		if (namlen == 1 || (namlen == 2 && name[1] == '.'))
			goto passthrough;
	}

	if (kasumi_stealth_enabled && w->dir_path_len == 4) {
		size_t mlen = strlen(kasumi_current_mirror_name);
		if ((unsigned int)namlen == mlen &&
		    memcmp(name, kasumi_current_mirror_name, namlen) == 0)
			return KASUMI_FILLDIR_CONTINUE;
	}

	/* Hide real entries that also exist in merge targets. This prevents
	 * duplicates: the injected version (from populate_injected_list)
	 * replaces the original, just like original kasumi.c does.
	 * Skip when merge target IS the dir we're listing (e.g. target path
	 * resolved to same inode via symlink) - otherwise we'd hide everything.
	 * Must respect allowlist: privileged/allowlist processes see real files. */
	if (kasumi_d_hash_and_lookup && w->merge_target_count > 0 && w->parent_dentry &&
	    !kasumi_is_privileged_process() && kasumi_should_apply_hide_rules()) {
		int i;
		for (i = 0; i < w->merge_target_count; i++) {
			struct dentry *tgt = w->merge_target_dentries[i];
			if (!tgt || tgt == w->parent_dentry)
				continue;
			if (d_inode(tgt) && d_inode(tgt) == d_inode(w->parent_dentry))
				continue;
			{
				struct dentry *child = kasumi_d_hash_and_lookup(tgt,
					&(struct qstr)QSTR_INIT(name, namlen));
				if (child) {
					dput(child);
					atomic64_inc(&kasumi_hook_stats.filldir_hidden);
					return KASUMI_FILLDIR_CONTINUE;
				}
			}
		}
	}

	if (kasumi_d_hash_and_lookup && w->dir_has_hidden && w->parent_dentry &&
	    !kasumi_is_privileged_process() && kasumi_should_apply_hide_rules()) {
		struct dentry *child;

		child = kasumi_d_hash_and_lookup(w->parent_dentry,
				&(struct qstr)QSTR_INIT(name, namlen));
		if (child) {
			struct inode *cinode = d_inode(child);
			if (cinode && cinode->i_mapping &&
			    test_bit(AS_FLAGS_KASUMI_HIDE,
				     &cinode->i_mapping->flags)) {
				dput(child);
				atomic64_inc(&kasumi_hook_stats.filldir_hidden);
				return KASUMI_FILLDIR_CONTINUE;
			}
			dput(child);
		}
	}

passthrough:
	if (unlikely(!w->orig_ctx || !w->orig_ctx->actor))
		return KASUMI_FILLDIR_CONTINUE;
	return w->orig_ctx->actor(w->orig_ctx, name, namlen, offset, ino, d_type);
}

/* ======================================================================
 * Kprobe pre_handlers (modify regs / user path only; return 0 to run original)
 * ====================================================================== */

#if defined(__aarch64__)
#define KASUMI_REG0(regs)		((regs)->regs[0])
#define KASUMI_REG1(regs)		((regs)->regs[1])
#define KASUMI_REG2(regs)		((regs)->regs[2])
#define KASUMI_REG3(regs)		((regs)->regs[3])
#define KASUMI_REG4(regs)		((regs)->regs[4])
#define KASUMI_LR(regs)		((regs)->regs[30])
#define KASUMI_POP_STACK(regs)	do { } while (0)
#elif defined(__x86_64__)
#define KASUMI_REG0(regs)		((regs)->di)
#define KASUMI_REG1(regs)		((regs)->si)
#define KASUMI_REG2(regs)		((regs)->dx)
#define KASUMI_REG3(regs)		((regs)->cx)
#define KASUMI_REG4(regs)		((regs)->r8)
#define KASUMI_LR(regs)		(*(unsigned long *)(regs)->sp)
#define KASUMI_POP_STACK(regs)	do { (regs)->sp += 8; } while (0)
#elif defined(__arm__)
/* ARM32: pt_regs uses uregs[] (r0=0, r1=1, ..., lr=14, pc=15) */
#define KASUMI_REG0(regs)		((regs)->uregs[0])
#define KASUMI_REG1(regs)		((regs)->uregs[1])
#define KASUMI_REG2(regs)		((regs)->uregs[2])
#define KASUMI_REG3(regs)		((regs)->uregs[3])
#define KASUMI_REG4(regs)		((regs)->uregs[4])
#define KASUMI_LR(regs)		((regs)->uregs[14])
#define KASUMI_POP_STACK(regs)	do { } while (0)
#else
#define KASUMI_REG0(regs)		(0)
#define KASUMI_REG1(regs)		(0)
#define KASUMI_REG2(regs)		(0)
#define KASUMI_REG3(regs)		(0)
#define KASUMI_REG4(regs)		(0)
#define KASUMI_LR(regs)		(0)
#define KASUMI_POP_STACK(regs)	do { } while (0)
#endif

/* Path register pointer for syscall-entry style pt_regs (avoids u64* vs unsigned long* across archs). */
#if defined(__aarch64__) || defined(__x86_64__)
#define KASUMI_PATH_REG_PTR(regs, id)  ((u64 *)((id) == __NR_execve ? &KASUMI_REG0(regs) : &KASUMI_REG1(regs)))
#define KASUMI_PATH_REG_VAL(p)         ((u64)(uintptr_t)(p))
#else
#define KASUMI_PATH_REG_PTR(regs, id)  ((unsigned long *)((id) == __NR_execve ? &KASUMI_REG0(regs) : &KASUMI_REG1(regs)))
#define KASUMI_PATH_REG_VAL(p)         ((unsigned long)(uintptr_t)(p))
#endif

/*
 * vfs_getattr / vfs_getxattr argument positions.
 *
 * Upstream Linux added an idmap arg to vfs_getattr in 5.12, but Android GKI
 * kernels (verified across 5.10/5.15/6.1/6.6/6.12) keep the original 4-arg
 * signature `vfs_getattr(path, stat, mask, flags)`. So the upstream version
 * gate was wrong for every Android target — always shifted args by one and
 * silently early-exited on `!p->dentry`. Hardcode the 4-arg layout instead.
 */
#define KASUMI_GETATTR_PATH_REG(regs) KASUMI_REG0(regs)
#define KASUMI_GETATTR_STAT_REG(regs) KASUMI_REG1(regs)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
#define KASUMI_GETXATTR_DENTRY_REG(regs) KASUMI_REG1(regs)
#define KASUMI_GETXATTR_NAME_REG(regs)   KASUMI_REG2(regs)
#define KASUMI_GETXATTR_VALUE_REG(regs)  KASUMI_REG3(regs)
#define KASUMI_GETXATTR_SIZE_REG(regs)   KASUMI_REG4(regs)
#else
#define KASUMI_GETXATTR_DENTRY_REG(regs) KASUMI_REG0(regs)
#define KASUMI_GETXATTR_NAME_REG(regs)   KASUMI_REG1(regs)
#define KASUMI_GETXATTR_VALUE_REG(regs)  KASUMI_REG2(regs)
#define KASUMI_GETXATTR_SIZE_REG(regs)   KASUMI_REG3(regs)
#endif

/*
 * Atomic-safe user access for kprobe pre-handler (cannot sleep).
 * copy_from_user/copy_to_user may sleep on page fault -> use nofault variants.
 * Resolved dynamically via kallsyms (not exported on GKI).
 */
#include <linux/sched/task_stack.h>

#define KASUMI_HIDE_PATH "/.kasumi_hidden_placeholder"

char __user *kasumi_userspace_stack_buffer(const char *data, size_t len)
{
	char __user *p;

	if (!current->mm)
		return NULL;
	p = (void __user *)current_user_stack_pointer() - len;
	return copy_to_user(p, data, len) ? NULL : p;
}

static inline bool kasumi_tp_check_path_syscall(long id)
{
	switch (id) {
	case __NR_openat:
	case __NR_faccessat:
#ifdef __NR_newfstatat
	case __NR_newfstatat:
#endif
	case __NR_execve:
#ifdef __NR_execveat
	case __NR_execveat:
#endif
#ifdef __NR_openat2
	case __NR_openat2:
#endif
		return true;
	default:
		return false;
	}
}

void kasumi_handle_sys_enter_getfd(struct pt_regs *regs, long id)
{
#if defined(__aarch64__)
	unsigned long a0 = regs->regs[0];
	unsigned long a1 = regs->regs[1];
	unsigned long a2 = regs->regs[2];
	unsigned long a3 = regs->regs[3];
#elif defined(__x86_64__)
	unsigned long a0 = regs->di;
	unsigned long a1 = regs->si;
	unsigned long a2 = regs->dx;
	unsigned long a3 = regs->r10;
#elif defined(__arm__)
	unsigned long a0 = regs->uregs[0];
	unsigned long a1 = regs->uregs[1];
	unsigned long a2 = regs->uregs[2];
	unsigned long a3 = regs->uregs[3];
#else
	return;
#endif
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return;

	/* reboot: magic + put_user via 4th arg */
	if (id == __NR_reboot && a0 == KSM_MAGIC1 && a1 == KSM_MAGIC2 && a2 == (unsigned long)KSM_CMD_GET_FD) {
		int fd = kasumi_get_anon_fd();
		if (fd >= 0) {
			int __user *fd_ptr = (int __user *)(unsigned long)a3;
			if (fd_ptr)
				put_user(fd, fd_ptr);
		}
		return;
	}
	/* prctl: option=KSM_PRCTL_GET_FD, arg2=fd_ptr */
	if (id == __NR_prctl && a0 == (unsigned long)KSM_PRCTL_GET_FD) {
		int fd = kasumi_get_anon_fd();
		if (fd >= 0) {
			int __user *fd_ptr = (int __user *)(unsigned long)a1;
			if (fd_ptr)
				put_user(fd, fd_ptr);
		}
		return;
	}
	/* ni_syscall: set per-cpu for sys_exit to replace return value */
	if (id == (long)kasumi_syscall_nr_param && a0 == KSM_MAGIC1 && a1 == KSM_MAGIC2 && a2 == (unsigned long)KSM_CMD_GET_FD) {
		int fd = kasumi_get_anon_fd();
		if (fd >= 0) {
			kasumi_this_cpu()->override_fd = fd;
			kasumi_this_cpu()->override_active = 1;
		}
	}
}

void kasumi_handle_sys_exit_getfd(struct pt_regs *regs, long ret)
{
	(void)ret;
	if (!kasumi_this_cpu()->override_active)
		return;
#if defined(__aarch64__)
	regs->regs[0] = kasumi_this_cpu()->override_fd;
#elif defined(__x86_64__)
	regs->ax = kasumi_this_cpu()->override_fd;
#elif defined(__arm__)
	regs->uregs[0] = kasumi_this_cpu()->override_fd;
#endif
	kasumi_this_cpu()->override_active = 0;
}

#if defined(__aarch64__) || defined(__x86_64__)
/* Cmdline spoof: check if fd refers to /proc/cmdline. Used by the direct
 * h_read handler and kretprobe fallback. */
bool kasumi_fd_is_proc_cmdline(int fd)
{
	struct file *file;
	struct dentry *dentry, *parent;
	bool is_cmdline = false;

	file = fget(fd);
	if (!file)
		return false;
	dentry = file->f_path.dentry;
	parent = dentry ? dentry->d_parent : NULL;
	if (dentry && dentry->d_name.len == 7 &&
	    memcmp(dentry->d_name.name, "cmdline", 7) == 0 && parent) {
		/* Parent is "proc" dir or proc root (empty name) */
		if ((parent->d_name.len == 5 && memcmp(parent->d_name.name, "proc", 5) == 0) ||
		    parent->d_name.len == 0)
			is_cmdline = true;
	}
	fput(file);
	return is_cmdline;
}
#endif

void kasumi_handle_sys_enter_cmdline(struct pt_regs *regs, long id)
{
#if defined(__aarch64__) || defined(__x86_64__)
	unsigned long fd, buf, count;

	if (!kasumi_cmdline_spoof_active)
		return;
	if (id != __NR_read)
		return;
	/*
	 * If the TSR has installed h_read, it owns the spoof in one
	 * shot — leave the percpu cmdline_ctx untouched so the sys_exit handler
	 * doesn't double-spoof an already-rewritten buffer.
	 */
	if (kasumi_has_syscall_hook(__NR_read))
		return;
	if (READ_ONCE(kasumi_daemon_pid) > 0 && task_tgid_vnr(current) == READ_ONCE(kasumi_daemon_pid))
		return;

#if defined(__aarch64__)
	fd = regs->regs[0];
	buf = regs->regs[1];
	count = regs->regs[2];
#else
	fd = regs->di;
	buf = regs->si;
	count = regs->dx;
#endif

	if (!kasumi_fd_is_proc_cmdline((int)fd))
		return;

	kasumi_this_cpu()->cmdline_ctx.buf = (char __user *)buf;
	kasumi_this_cpu()->cmdline_ctx.count = (size_t)count;
	kasumi_this_cpu()->cmdline_ctx.active = 1;
#endif
}

void kasumi_handle_sys_exit_cmdline(struct pt_regs *regs, long ret)
{
#if defined(__aarch64__) || defined(__x86_64__)
	struct kasumi_percpu *pcpu = kasumi_this_cpu();
	size_t spoof_len, write_len;

	if (!pcpu->cmdline_ctx.active || ret <= 0)
		goto out;
	pcpu->cmdline_ctx.active = 0;

	if (!READ_ONCE(kasumi_cmdline_spoof_active))
		goto out;

	rcu_read_lock();
	{
		struct kasumi_cmdline_rcu *c = rcu_dereference(kasumi_spoof_cmdline_ptr);
		if (!c || !c->cmdline[0]) {
			rcu_read_unlock();
			goto out;
		}
		spoof_len = strnlen(c->cmdline, sizeof(c->cmdline) - 1);
		/* Original cmdline ends with \n; match that */
		write_len = spoof_len + 1; /* +1 for \n */
		if (write_len > pcpu->cmdline_ctx.count)
			write_len = pcpu->cmdline_ctx.count;
		if (write_len > 0) {
			size_t n = (spoof_len < write_len) ? spoof_len : write_len - 1;
			if (copy_to_user(pcpu->cmdline_ctx.buf, c->cmdline, n) == 0) {
				if (n < write_len && copy_to_user(pcpu->cmdline_ctx.buf + n, "\n", 1) == 0)
					write_len = n + 1;
				else
					write_len = n;
#if defined(__aarch64__)
				regs->regs[0] = (unsigned long)write_len;
#else
				regs->ax = (unsigned long)write_len;
#endif
			}
		}
	}
	rcu_read_unlock();
out:
	(void)0;
#endif
}

void kasumi_handle_sys_enter_statx(struct pt_regs *regs, long id)
{
#if defined(__aarch64__) || defined(__x86_64__)
	struct kasumi_percpu *pcpu = kasumi_this_cpu();
	const char __user *filename_user;
	unsigned long buf_ptr;
	char *path;

	pcpu->statx_ctx.active = 0;
	if (id != __NR_statx)
		return;
	if (!(kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE) ||
	    !kasumi_should_apply_hide_rules())
		return;

#if defined(__aarch64__)
	filename_user = (const char __user *)(uintptr_t)regs->regs[1];
	buf_ptr = regs->regs[4];
#else
	filename_user = (const char __user *)(uintptr_t)regs->si;
	buf_ptr = regs->r8;
#endif
	if (!filename_user || !buf_ptr)
		return;

	path = pcpu->statx_ctx.path;
	if (kasumi_strncpy_from_user_nofault) {
		long n = kasumi_strncpy_from_user_nofault(path, filename_user,
							KSM_MAX_LEN_PATHNAME - 1);
		if (n < 0)
			return;
		path[n < (long)(KSM_MAX_LEN_PATHNAME - 1) ? n :
		     (long)(KSM_MAX_LEN_PATHNAME - 1)] = '\0';
	} else {
		if (copy_from_user(path, filename_user, KSM_MAX_LEN_PATHNAME - 1))
			return;
		path[KSM_MAX_LEN_PATHNAME - 1] = '\0';
	}

	if (path[0] != '/')
		return;

	pcpu->statx_ctx.buf = (struct statx __user *)(uintptr_t)buf_ptr;
	pcpu->statx_ctx.active = 1;
#else
	(void)regs;
	(void)id;
#endif
}

void kasumi_handle_sys_exit_statx(struct pt_regs *regs, long ret)
{
#if defined(__aarch64__) || defined(__x86_64__)
	struct kasumi_percpu *pcpu = kasumi_this_cpu();
	struct statx stx;
	int fake_mnt_id;

	(void)regs;
	if (!pcpu->statx_ctx.active)
		return;
	pcpu->statx_ctx.active = 0;
	if (ret != 0 || !pcpu->statx_ctx.buf)
		return;

	fake_mnt_id = kasumi_fake_mi_lookup_mount_id_cached(pcpu->statx_ctx.path);
	if (fake_mnt_id <= 0)
		return;
	if (!kasumi_copy_from_user_nofault || !kasumi_copy_to_user_nofault)
		return;
	if (kasumi_copy_from_user_nofault(&stx, pcpu->statx_ctx.buf,
					  sizeof(stx)) != 0)
		return;

	stx.stx_mnt_id = (u64)fake_mnt_id;
	if (kasumi_copy_to_user_nofault(pcpu->statx_ctx.buf, &stx,
					sizeof(stx)) != 0)
		return;

	kasumi_log("statx spoof: path=%s fake_mnt_id=%d pid=%d comm=%s\n",
		 pcpu->statx_ctx.path, fake_mnt_id,
		 task_pid_nr(current), current->comm);
#else
	(void)regs;
	(void)ret;
#endif
}

void kasumi_handle_sys_exit_path(struct pt_regs *regs, long ret)
{
	struct kasumi_percpu *pcpu = kasumi_this_cpu();

	(void)regs;
	if (!pcpu->mount_proxy_pending)
		return;

	pcpu->mount_proxy_pending = 0;
	if (ret < 0)
		return;

	(void)kasumi_mount_proxy_install_fd((int)ret);
}

void kasumi_handle_sys_enter_path(struct pt_regs *regs, long id)
{
	const char __user *filename_user;
	char *buf;
	char *target;
	char __user *new_path;
	bool check_mount_proxy = false;
	bool have_path_filters;

	if (!kasumi_tp_check_path_syscall(id))
		return;
	if (atomic_long_read(&kasumi_ioctl_tgid) == (long)task_tgid_vnr(current))
		return;
	if (atomic_long_read(&kasumi_xattr_source_tgid) == (long)task_tgid_vnr(current))
		return;
	kasumi_this_cpu()->mount_proxy_pending = 0;
	check_mount_proxy = id == __NR_openat
#ifdef __NR_openat2
			    || id == __NR_openat2
#endif
			    ;
	have_path_filters = atomic_read(&kasumi_rule_count) != 0 ||
			    atomic_read(&kasumi_hide_count) != 0;
	/* Fast path: no path filters and no mount view fd wrapping need. */
	if (likely(!have_path_filters && !check_mount_proxy))
		return;
	if (check_mount_proxy && kasumi_proc_proxy_should_try())
		kasumi_this_cpu()->mount_proxy_pending = 1;

	filename_user = (const char __user *)(uintptr_t)*KASUMI_PATH_REG_PTR(regs, id);
	if (!filename_user)
		return;

	buf = kasumi_getname_buf_base + (smp_processor_id() * KASUMI_PATH_BUF);
	if (kasumi_strncpy_from_user_nofault) {
		long ret = kasumi_strncpy_from_user_nofault(buf, filename_user, KASUMI_PATH_BUF - 1);
		if (ret < 0)
			return;
		buf[ret < (long)(KASUMI_PATH_BUF - 1) ? ret : (long)(KASUMI_PATH_BUF - 1)] = '\0';
	} else {
		if (copy_from_user(buf, filename_user, KASUMI_PATH_BUF - 1))
			return;
		buf[KASUMI_PATH_BUF - 1] = '\0';
	}

	if (check_mount_proxy && buf[0] == '/' && kasumi_path_needs_proc_proxy(buf)) {
		int prep_rc;

		kasumi_log("proc_proxy: arm pid=%d comm=%s path=%s\n",
			 task_pid_nr(current), current->comm, buf);
		if (kasumi_path_is_proc_mountinfo(buf) &&
		    kasumi_should_apply_hide_rules()) {
			prep_rc = kasumi_fake_mi_prepare(false);
			kasumi_log("proc_proxy: prepare pid=%d comm=%s rc=%d\n",
				 task_pid_nr(current), current->comm, prep_rc);
		}
	}

	if (!have_path_filters)
		return;

	if (unlikely(kasumi_should_hide(buf))) {
		new_path = kasumi_userspace_stack_buffer(KASUMI_HIDE_PATH, sizeof(KASUMI_HIDE_PATH));
		if (new_path)
			*KASUMI_PATH_REG_PTR(regs, id) = KASUMI_PATH_REG_VAL(new_path);
		return;
	}

	if (buf[0] != '/')
		return;
	target = kasumi_resolve_target(buf);
	if (!target)
		return;
	{
		size_t tlen = strlen(target) + 1;
		if (tlen > KASUMI_PATH_BUF) {
			kfree(target);
			return;
		}
		new_path = kasumi_userspace_stack_buffer(target, tlen);
		kfree(target);
		if (new_path)
			*KASUMI_PATH_REG_PTR(regs, id) = KASUMI_PATH_REG_VAL(new_path);
	}
}

/* getname_flags pre-handler: only modify user path and regs; return 0 to run original. */
static KASUMI_NOCFI int kasumi_kp_getname_flags_pre(struct kprobe *p, struct pt_regs *regs)
{
	const char __user *filename_user;
	char *buf;
	char *target;
	bool check_mountinfo_prime;
	bool have_path_filters;

	(void)p;

	if (kasumi_this_cpu()->kprobe_reent)
		return 0;
	/* Skip when current is in ioctl path resolution (avoids reent / deadlock with metamount+kasumid). */
	if (atomic_long_read(&kasumi_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	/* Skip when resolving source path for xattr spoofing (need unredirected path). */
	if (atomic_long_read(&kasumi_xattr_source_tgid) == (long)task_tgid_vnr(current))
		return 0;
	check_mountinfo_prime = (kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE) != 0;
	have_path_filters = atomic_read(&kasumi_rule_count) != 0 ||
			    atomic_read(&kasumi_hide_count) != 0;
	/* Fast path: no path filters and no mountinfo prewarm need. */
	if (likely(!have_path_filters && !check_mountinfo_prime))
		return 0;

	filename_user = (const char __user *)KASUMI_REG0(regs);
	if (!filename_user)
		return 0;

	buf = kasumi_getname_buf_base + (smp_processor_id() * KASUMI_PATH_BUF);
	if (kasumi_strncpy_from_user_nofault) {
		long ret = kasumi_strncpy_from_user_nofault(buf, filename_user, KASUMI_PATH_BUF - 1);
		if (ret < 0)
			return 0;
		buf[ret < (long)(KASUMI_PATH_BUF - 1) ? ret : (KASUMI_PATH_BUF - 1)] = '\0';
	} else {
		if (copy_from_user(buf, filename_user, KASUMI_PATH_BUF - 1))
			return 0;
		buf[KASUMI_PATH_BUF - 1] = '\0';
	}

	if (check_mountinfo_prime && buf[0] == '/' &&
	    kasumi_path_is_proc_mountinfo(buf) &&
	    kasumi_should_apply_hide_rules())
		(void)kasumi_fake_mi_prepare(false);

	if (!have_path_filters)
		return 0;

	/* Hide: skip original and return error (no putname needed) */
	if (unlikely(kasumi_should_hide(buf))) {
		kasumi_this_cpu()->kprobe_reent = 1;
		KASUMI_REG0(regs) = (unsigned long)ERR_PTR(-ENOENT);
		instruction_pointer_set(regs, KASUMI_LR(regs));
		KASUMI_POP_STACK(regs);
#if defined(__x86_64__)
		regs->ax = (unsigned long)ERR_PTR(-ENOENT);
#endif
		kasumi_this_cpu()->kprobe_reent = 0;
		return 1;
	}

	/* Redirect: use getname_kernel to build a struct filename from the target
	 * path, then skip the original getname_flags entirely.  This avoids
	 * writing back to user memory (which may be read-only, too small, or
	 * cause PAN/MTE faults in atomic context). */
	if (buf[0] != '/')
		return 0;
	target = kasumi_resolve_target(buf);
	if (!target)
		return 0;
	if (kasumi_getname_kernel) {
		struct filename *fname;

		kasumi_this_cpu()->kprobe_reent = 1;
		fname = kasumi_getname_kernel(target);
		kasumi_this_cpu()->kprobe_reent = 0;
		kfree(target);
		if (IS_ERR(fname))
			return 0;
		KASUMI_REG0(regs) = (unsigned long)fname;
		instruction_pointer_set(regs, KASUMI_LR(regs));
		KASUMI_POP_STACK(regs);
		return 1;
	}
	kfree(target);
	return 0;
}

/* vfs_getattr kprobe pre: nop (stat spoofing is done in kretprobe entry/ret). */
static int kasumi_kp_vfs_getattr_pre(struct kprobe *p, struct pt_regs *regs)
{
	(void)p; (void)regs;
	return 0;
}

/*
 * vfs_getattr kretprobe entry: resolve path, check kasumi_targets.
 * Uses ri->data (migration-safe) instead of per-CPU storage.
 */
KASUMI_NOCFI int kasumi_krp_vfs_getattr_entry(struct kretprobe_instance *ri,
						  struct pt_regs *regs)
{
	struct kasumi_getattr_ri_data *d = (void *)ri->data;
	const struct path *p;
	char buf[256];
	char *dp;

	atomic64_inc(&kasumi_hook_stats.vfs_getattr_entries);
	d->is_target = false;
	d->stat = NULL;
	d->mapping = NULL;

	if (!READ_ONCE(kasumi_enabled))
		return 0;
	if (!kasumi_should_apply_hide_rules())
		return 0;
	if (atomic_long_read(&kasumi_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	if (kasumi_this_cpu()->in_populate_inject)
		return 0;
	if (atomic_read(&kasumi_rule_count) == 0 &&
	    atomic_read(&kasumi_spoof_kstat_count) == 0)
		return 0;

	p = (const struct path *)KASUMI_GETATTR_PATH_REG(regs);
	d->stat = (struct kstat *)KASUMI_GETATTR_STAT_REG(regs);

	if (!p || !p->dentry || !d->stat)
		return 0;

	if (d_inode(p->dentry) && d_inode(p->dentry)->i_mapping)
		d->mapping = d_inode(p->dentry)->i_mapping;

	/* Fast path: inode already marked from a previous redirect match */
	if (d->mapping && test_bit(AS_FLAGS_KASUMI_SPOOF_KSTAT, &d->mapping->flags)) {
		/* If shadow i_op is installed, it will spoof inline — skip the
		 * ret handler entirely to avoid redundant work. */
		if (test_bit(AS_FLAGS_KASUMI_IOP_INSTALLED, &d->mapping->flags))
			return -1;
		d->is_target = true;
		return 0;
	}

	dp = ERR_PTR(-ENOENT);
	if (kasumi_d_absolute_path)
		dp = kasumi_d_absolute_path(p, buf, sizeof(buf));
	if (IS_ERR(dp) && kasumi_dentry_path_raw)
		dp = kasumi_dentry_path_raw(p->dentry, buf, sizeof(buf));
	if (IS_ERR_OR_NULL(dp) || dp[0] != '/')
		return 0;

	rcu_read_lock();
	if (kasumi_reverse_lookup_target(dp) ||
	    kasumi_spoof_kstat_lookup_by_path(dp))
		d->is_target = true;
	if (!d->is_target && d_inode(p->dentry)) {
		struct inode *ino = d_inode(p->dentry);
		if (kasumi_spoof_kstat_lookup_by_ino(
			(unsigned long)ino->i_ino,
			ino->i_sb ? (unsigned long)ino->i_sb->s_dev : 0))
			d->is_target = true;
	}
	rcu_read_unlock();

	return 0;
}

/*
 * vfs_getattr kretprobe ret: spoof kstat for redirect targets.
 * Makes the file appear to belong to /system with root ownership.
 */
/*
 * Apply kstat spoofing in place. Shared by:
 *   - vfs_getattr kretprobe ret handler (legacy slow path)
 *   - kasumi_shadow_getattr in kasumi_iop_override.c (fast path after install)
 *
 * Note: `inode` may be NULL for the legacy path (we still have stat / mapping
 * via the kretprobe ri data); the shadow path always provides it.
 */
void kasumi_apply_kstat_spoof(struct inode *inode, struct kstat *stat)
{
	struct kasumi_spoof_kstat_entry *e = NULL;

	if (!stat)
		return;
	if (!kasumi_should_apply_hide_rules())
		return;

	/* Explicit per-inode spoof rule (api15) takes precedence. */
	if (inode && atomic_read(&kasumi_spoof_kstat_count) > 0) {
		rcu_read_lock();
		e = kasumi_spoof_kstat_lookup_by_ino((unsigned long)inode->i_ino,
						     (unsigned long)stat->dev);
		if (e) {
			if (e->spoofed_dev)        stat->dev = e->spoofed_dev;
			if (e->spoofed_ino)        stat->ino = e->spoofed_ino;
			if (e->spoofed_nlink)      stat->nlink = e->spoofed_nlink;
			if (e->spoofed_size)       stat->size = e->spoofed_size;
			if (e->spoofed_blksize)    stat->blksize = e->spoofed_blksize;
			if (e->spoofed_blocks)     stat->blocks = e->spoofed_blocks;
			if (e->spoofed_atime_sec || e->spoofed_atime_nsec) {
				stat->atime.tv_sec  = e->spoofed_atime_sec;
				stat->atime.tv_nsec = e->spoofed_atime_nsec;
			}
			if (e->spoofed_mtime_sec || e->spoofed_mtime_nsec) {
				stat->mtime.tv_sec  = e->spoofed_mtime_sec;
				stat->mtime.tv_nsec = e->spoofed_mtime_nsec;
			}
			if (e->spoofed_ctime_sec || e->spoofed_ctime_nsec) {
				stat->ctime.tv_sec  = e->spoofed_ctime_sec;
				stat->ctime.tv_nsec = e->spoofed_ctime_nsec;
			}
		}
		rcu_read_unlock();
	}

	if (!e) {
		/* Generic fallback: piggyback on add_rule redirect targets. */
		if (kasumi_system_dev)
			stat->dev = kasumi_system_dev;
		stat->ino = (u64)jhash(stat, sizeof(stat->ino), 0x48594D4F) | 0x100000ULL;
		if (S_ISREG(stat->mode))
			stat->nlink = 1;
	}

	stat->uid = GLOBAL_ROOT_UID;
	stat->gid = GLOBAL_ROOT_GID;

	kasumi_log("kstat: spoofed ino %lu (explicit=%d)\n",
		 (unsigned long)stat->ino, e ? 1 : 0);

	if (inode && inode->i_mapping)
		set_bit(AS_FLAGS_KASUMI_SPOOF_KSTAT, &inode->i_mapping->flags);
}

int kasumi_krp_vfs_getattr_ret(struct kretprobe_instance *ri,
				    struct pt_regs *regs)
{
	struct kasumi_getattr_ri_data *d = (void *)ri->data;
	int ret_val;

	if (!d->is_target || !d->stat)
		return 0;

#if defined(__aarch64__)
	ret_val = (int)regs->regs[0];
#elif defined(__x86_64__)
	ret_val = (int)regs->ax;
#else
	ret_val = 0;
#endif
	if (ret_val != 0)
		return 0;

	{
		struct inode *inode = d->mapping ? d->mapping->host : NULL;
		kasumi_apply_kstat_spoof(inode, d->stat);
		atomic64_inc(&kasumi_hook_stats.vfs_getattr_spoofs);
		/*
		 * Lookup-time i_op install: after first successful spoof,
		 * install a shadow inode_operations so future stat()s go
		 * through an indirect call instead of trapping into this
		 * kprobe. Safe to call repeatedly (idempotent).
		 */
		if (inode)
			kasumi_iop_install(inode);
	}

	return 0;
}

/*
 * Get SELinux context from a path (used for source path when spoofing).
 * Bypass must be set (kasumi_xattr_source_tgid) so path resolution is not redirected.
 * Returns length of context string (excl. NUL) or negative on error.
 */
static KASUMI_NOCFI ssize_t kasumi_get_selinux_ctx_from_path(struct path *path, char *buf, size_t buflen)
{
	if (!kasumi_vfs_getxattr_addr || buflen < 2)
		return -ENOENT;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	return ((ssize_t (*)(void *, struct dentry *, const char *, void *, size_t))kasumi_vfs_getxattr_addr)(
		mnt_idmap(path->mnt), path->dentry, "security.selinux", buf, buflen);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	return ((ssize_t (*)(void *, struct dentry *, const char *, void *, size_t))kasumi_vfs_getxattr_addr)(
		mnt_user_ns(path->mnt), path->dentry, "security.selinux", buf, buflen);
#else
	return ((ssize_t (*)(struct dentry *, const char *, void *, size_t))kasumi_vfs_getxattr_addr)(
		path->dentry, "security.selinux", buf, buflen);
#endif
}

/*
 * vfs_getxattr kretprobe entry: check if querying security.selinux on a
 * redirect target.  Resolves source path and reads its actual SELinux context
 * from the mounted directory (no hardcoding).
 */
KASUMI_NOCFI int kasumi_krp_vfs_getxattr_entry(struct kretprobe_instance *ri,
						   struct pt_regs *regs)
{
	struct kasumi_getxattr_ri_data *d = (void *)ri->data;
	struct dentry *dentry;
	const char *xattr_name;
	struct inode *inode;
	char *tmp;  /* heap to avoid arm32 frame-larger-than=1024 */
	char *dp;
	struct kasumi_entry *entry;
	struct path src_path;
	ssize_t ret;

	d->spoof_selinux = false;
	d->value_buf = NULL;
	d->value_size = 0;
	d->src_ctx[0] = '\0';
	d->src_ctx_len = 0;
	atomic64_inc(&kasumi_hook_stats.getxattr_entries);

	/* Skip when we're in the inner call (resolving source path's context) */
	if (atomic_long_read(&kasumi_xattr_source_tgid) == (long)task_tgid_vnr(current))
		return 0;

	if (!READ_ONCE(kasumi_enabled))
		return 0;
	if (!kasumi_should_apply_hide_rules())
		return 0;
	if (atomic_long_read(&kasumi_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	if (atomic_read(&kasumi_rule_count) == 0)
		return 0;

	xattr_name = (const char *)KASUMI_GETXATTR_NAME_REG(regs);
	if (!xattr_name)
		return 0;
	if (strcmp(xattr_name, "security.selinux") != 0)
		return 0;

	dentry = (struct dentry *)KASUMI_GETXATTR_DENTRY_REG(regs);
	if (!dentry)
		return 0;

	inode = d_inode(dentry);
	if (!inode || !inode->i_mapping)
		return 0;
	if (!test_bit(AS_FLAGS_KASUMI_SPOOF_KSTAT, &inode->i_mapping->flags))
		return 0;

	tmp = kmalloc(256 + 256 + KSM_MAX_LEN_PATHNAME + 256 + 256 + 512, GFP_KERNEL);
	if (!tmp)
		return 0;

	/* Resolve target path for reverse lookup. dentry_path_raw gives path
	 * relative to fs root; try full path and /data + rel for common Android layout. */
	dp = ERR_PTR(-ENOENT);
	if (kasumi_dentry_path_raw)
		dp = kasumi_dentry_path_raw(dentry, tmp, 256);
	if (IS_ERR_OR_NULL(dp) || dp[0] != '/')
		goto out_free;

	rcu_read_lock();
	entry = kasumi_reverse_lookup_target(dp);
	if (!entry && dp[0] == '/' && dp[1] != '\0') {
		if (snprintf(tmp + 256, 256, "/data%s", dp) < 256)
			entry = kasumi_reverse_lookup_target(tmp + 256);
	}
	if (entry && entry->src && strlen(entry->src) < KSM_MAX_LEN_PATHNAME)
		strscpy(tmp + 512, entry->src, KSM_MAX_LEN_PATHNAME);
	else
		*(tmp + 512) = '\0';
	rcu_read_unlock();
	if (*(tmp + 512) == '\0')
		goto out_free;

	/* Resolve source path (bypass redirect) and get its actual SELinux context.
	 * When source file doesn't exist (e.g. overlay dir is empty), try parent
	 * directories. Use d_absolute_path on resolved parent to get symlink-resolved
	 * path (e.g. /system/product -> /product), then try resolved+remainder. */
	atomic_long_set(&kasumi_xattr_source_tgid, (long)task_tgid_vnr(current));
	if (kasumi_kern_path) {
		char *src_copy = tmp + 512;
		char *parent = src_copy + KSM_MAX_LEN_PATHNAME;
		char *resolved = parent + 256;
		char *alt = resolved + 256;
		const char *try_path = src_copy;
		size_t len = strlen(src_copy);
		size_t parent_len;

		while (try_path && len > 1) {
			/* Try logical path (LOOKUP_FOLLOW resolves symlinks) */
			if (kasumi_kern_path(try_path, LOOKUP_FOLLOW, &src_path) == 0) {
				ret = kasumi_get_selinux_ctx_from_path(&src_path, d->src_ctx, KASUMI_SELINUX_CTX_MAX);
				kasumi_path_put(&src_path);
				if (ret > 0 && (size_t)ret < KASUMI_SELINUX_CTX_MAX) {
					d->src_ctx_len = (size_t)ret;
					d->src_ctx[d->src_ctx_len] = '\0';
					d->spoof_selinux = true;
					break;
				}
			}
			/* Logical path failed: try parent, get resolved path via d_absolute_path,
			 * then try resolved+remainder (handles any symlink, not just /system/product). */
			if (len >= 256)
				break;
			memcpy(parent, try_path, len + 1);
			{
				char *slash = strrchr(parent, '/');
				if (!slash || slash == parent)
					break;
				*slash = '\0';
				parent_len = slash - parent;
			}
			if (kasumi_kern_path(parent, LOOKUP_FOLLOW, &src_path) == 0) {
				char *res = NULL;
				bool got_ctx = false;
				if (kasumi_d_absolute_path)
					res = kasumi_d_absolute_path(&src_path, resolved, 256);
				if (IS_ERR_OR_NULL(res) && kasumi_dentry_path_raw)
					res = kasumi_dentry_path_raw(src_path.dentry, resolved, 256);
				if (res && !IS_ERR(res) && res[0] == '/' &&
				    parent_len < len && try_path[parent_len] == '/') {
					const char *remainder = try_path + parent_len;
					if (snprintf(alt, 512, "%s%s", res, remainder) < 512 &&
					    strcmp(alt, try_path) != 0) {
						struct path alt_path;
						if (kasumi_kern_path(alt, LOOKUP_FOLLOW, &alt_path) == 0) {
							ret = kasumi_get_selinux_ctx_from_path(&alt_path, d->src_ctx, KASUMI_SELINUX_CTX_MAX);
							kasumi_path_put(&alt_path);
							if (ret > 0 && (size_t)ret < KASUMI_SELINUX_CTX_MAX)
								got_ctx = true;
						}
					}
				}
				if (!got_ctx) {
					ret = kasumi_get_selinux_ctx_from_path(&src_path, d->src_ctx, KASUMI_SELINUX_CTX_MAX);
					if (ret > 0 && (size_t)ret < KASUMI_SELINUX_CTX_MAX)
						got_ctx = true;
				}
				kasumi_path_put(&src_path);
				if (got_ctx) {
					d->src_ctx_len = (size_t)ret;
					d->src_ctx[d->src_ctx_len] = '\0';
					d->spoof_selinux = true;
					break;
				}
			}
			try_path = parent;
			len = parent_len;
		}
	}
	atomic_long_set(&kasumi_xattr_source_tgid, 0);

	d->value_buf = (void *)KASUMI_GETXATTR_VALUE_REG(regs);
	d->value_size = (size_t)KASUMI_GETXATTR_SIZE_REG(regs);

out_free:
	kfree(tmp);
	return 0;
}

/*
 * vfs_getxattr kretprobe ret: overwrite value buffer with source path's
 * actual SELinux context (from entry handler) and fix return value.
 */
int kasumi_krp_vfs_getxattr_ret(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	struct kasumi_getxattr_ri_data *d = (void *)ri->data;
	long ret_val;
	size_t ctx_len;

	if (!d->spoof_selinux || !d->value_buf || !d->src_ctx_len)
		return 0;

#if defined(__aarch64__)
	ret_val = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret_val = (long)regs->ax;
#else
	ret_val = 0;
#endif
	if (ret_val <= 0)
		return 0;

	ctx_len = d->src_ctx_len + 1; /* include NUL */
	if (d->value_size < ctx_len)
		return 0;
	memcpy(d->value_buf, d->src_ctx, ctx_len);
	atomic64_inc(&kasumi_hook_stats.getxattr_spoofs);

#if defined(__aarch64__)
	regs->regs[0] = (unsigned long)d->src_ctx_len;
#elif defined(__x86_64__)
	regs->ax = (unsigned long)d->src_ctx_len;
#endif

	return 0;
}

/* d_path: kprobe pre now a nop; entry handler below does the real work. */
static int kasumi_kp_d_path_pre(struct kprobe *p, struct pt_regs *regs)
{
	(void)p; (void)regs;
	return 0;
}

/*
 * d_path kretprobe entry: save buf/buflen from regs, resolve the struct path
 * to see if it's a redirect target.  d_path signature:
 *   char *d_path(const struct path *path, char *buf, int buflen)
 */
KASUMI_NOCFI int kasumi_krp_d_path_entry(struct kretprobe_instance *ri,
					     struct pt_regs *regs)
{
	struct kasumi_d_path_ri_data *d = (void *)ri->data;
	const struct path *p;
	char tmp[256];
	char *dp;
	struct kasumi_entry *entry;

	atomic64_inc(&kasumi_hook_stats.d_path_entries);
	d->is_target = false;
	d->buf = (char *)KASUMI_REG1(regs);
	d->buflen = (int)KASUMI_REG2(regs);
	d->src_path[0] = '\0';

	if (!READ_ONCE(kasumi_enabled))
		return 0;
	if (atomic_long_read(&kasumi_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	if (atomic_read(&kasumi_rule_count) == 0)
		return 0;

	p = (const struct path *)KASUMI_REG0(regs);
	if (!p || !p->dentry)
		return 0;

	dp = ERR_PTR(-ENOENT);
	if (kasumi_d_absolute_path)
		dp = kasumi_d_absolute_path(p, tmp, sizeof(tmp));
	if (IS_ERR(dp) && kasumi_dentry_path_raw)
		dp = kasumi_dentry_path_raw(p->dentry, tmp, sizeof(tmp));
	if (IS_ERR_OR_NULL(dp) || dp[0] != '/')
		return 0;

	rcu_read_lock();
	entry = kasumi_reverse_lookup_target(dp);
	if (entry && strlen(entry->src) < KASUMI_D_PATH_SRC_MAX) {
		d->is_target = true;
		strscpy(d->src_path, entry->src, KASUMI_D_PATH_SRC_MAX);
	}
	rcu_read_unlock();

	return 0;
}

/*
 * d_path kretprobe ret: if the resolved path was a redirect target,
 * overwrite the result so /proc/pid/fd/N shows /system/... instead of
 * /data/adb/modules/xxx/...
 *
 * d_path() returns a pointer INSIDE the caller's buffer (buf + offset).
 * We write the source path into the buffer from the end and update the
 * return value register to point to the new start.
 */
int kasumi_krp_d_path_ret(struct kretprobe_instance *ri,
			       struct pt_regs *regs)
{
	struct kasumi_d_path_ri_data *d = (void *)ri->data;
	char *ret_ptr;
	size_t src_len;
	char *new_start;

	if (!d->is_target || !d->src_path[0] || !d->buf || d->buflen <= 0)
		return 0;

#if defined(__aarch64__)
	ret_ptr = (char *)regs->regs[0];
#elif defined(__x86_64__)
	ret_ptr = (char *)regs->ax;
#else
	ret_ptr = NULL;
#endif
	if (IS_ERR_OR_NULL(ret_ptr))
		return 0;

	src_len = strlen(d->src_path);
	if ((int)src_len + 1 > d->buflen)
		return 0;

	new_start = d->buf + d->buflen - src_len - 1;
	memcpy(new_start, d->src_path, src_len + 1);

#if defined(__aarch64__)
	regs->regs[0] = (unsigned long)new_start;
#elif defined(__x86_64__)
	regs->ax = (unsigned long)new_start;
#endif
	atomic64_inc(&kasumi_hook_stats.d_path_rewrites);

	return 0;
}

/*
 * iterate_dir: pre swaps ctx to our wrapper so kernel runs filldir filter.
 * KASUMI_NOCFI: indirect calls to kasumi_d_absolute_path / kasumi_dentry_path_raw.
 */
KASUMI_NOCFI int kasumi_kp_iterate_dir_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file;
	struct kasumi_filldir_wrapper *w;
	struct dir_context *orig_ctx;

	(void)p;
	kasumi_this_cpu()->iterate_did_swap = 0;
	atomic64_inc(&kasumi_hook_stats.iterate_entries);

	file = (struct file *)KASUMI_REG0(regs);
	orig_ctx = (struct dir_context *)KASUMI_REG1(regs);
	if (kasumi_fop_file_is_shadowed(file))
		return 0;

	w = kasumi_iterate_prepare_wrapper(file, orig_ctx);
	if (!w)
		return 0;

	atomic64_inc(&kasumi_hook_stats.iterate_wrapped);
	kasumi_this_cpu()->iterate_did_swap = 1;
	KASUMI_REG1(regs) = (unsigned long)&w->wrap_ctx;
	return 0;
}

struct kasumi_filldir_wrapper *kasumi_iterate_prepare_wrapper(struct file *file,
							      struct dir_context *orig_ctx)
{
	struct kasumi_filldir_wrapper *w;
	struct inode *dir_inode;
	const char *dname;

	if (atomic_long_read(&kasumi_ioctl_tgid) == (long)task_tgid_vnr(current))
		return NULL;
	if (kasumi_this_cpu()->in_populate_inject)
		return NULL;
	if (!READ_ONCE(kasumi_enabled))
		return NULL;
	if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return NULL;
	if (READ_ONCE(kasumi_daemon_pid) > 0 && task_tgid_vnr(current) == READ_ONCE(kasumi_daemon_pid))
		return NULL;
	if (!orig_ctx || !orig_ctx->actor)
		return NULL;
	if (orig_ctx->actor == kasumi_filldir_filter)
		return NULL;

	w = kmem_cache_zalloc(kasumi_filldir_cache, GFP_ATOMIC);
	if (!w)
		return NULL;

	w->orig_ctx = orig_ctx;
	w->wrap_ctx.actor = kasumi_filldir_filter;
	w->wrap_ctx.pos = orig_ctx->pos;
	w->parent_dentry = file && file->f_path.dentry ? file->f_path.dentry : NULL;

	if (w->parent_dentry) {
		dir_inode = d_inode(w->parent_dentry);
		if (dir_inode && dir_inode->i_mapping) {
			w->dir_has_hidden = test_bit(AS_FLAGS_KASUMI_DIR_HAS_HIDDEN,
						     &dir_inode->i_mapping->flags);
			/* Fast path: if dir has no inject flag, skip rcu_read_lock + hash traversal */
			w->dir_has_inject = test_bit(AS_FLAGS_KASUMI_DIR_HAS_INJECT,
						    &dir_inode->i_mapping->flags);
		}
		dname = w->parent_dentry->d_name.name;
		if (dname[0] == 'd' && dname[1] == 'e' && dname[2] == 'v' && dname[3] == '\0')
			w->dir_path_len = 4;

		/*
		 * Only when dir_has_inject (from flag) is true: build full path and
		 * traverse hash to get merge_target_dentries. Most dirs skip this.
		 */
		if (atomic_read(&kasumi_rule_count) > 0 && w->dir_has_inject) {
			char *buf = kasumi_iterate_buf_base + (smp_processor_id() * KASUMI_ITERATE_PATH_BUF);
			char *dp = ERR_PTR(-ENOENT);

			if (kasumi_d_absolute_path)
				dp = kasumi_d_absolute_path(&file->f_path, buf,
							  KASUMI_ITERATE_PATH_BUF);
			if (IS_ERR(dp) && kasumi_dentry_path_raw)
				dp = kasumi_dentry_path_raw(w->parent_dentry, buf,
							  KASUMI_ITERATE_PATH_BUF);

			if (!IS_ERR_OR_NULL(dp) && *dp == '/') {
				struct kasumi_inject_entry *ie;
				struct kasumi_merge_entry *me;
				u32 h;
				int mbkt;
				size_t plen = strlen(dp);

				if (plen < KASUMI_ITERATE_PATH_BUF) {
					memcpy(w->dir_path_buf, dp, plen + 1);
					w->dir_path = w->dir_path_buf;
				}
				h = full_name_hash(NULL, dp, strlen(dp));

				rcu_read_lock();
				hlist_for_each_entry_rcu(ie,
					&kasumi_inject_dirs[hash_min(h, KASUMI_HASH_BITS)],
					node) {
					if (strcmp(ie->dir, dp) == 0) {
						w->dir_has_inject = true;
						break;
					}
				}
				/* Scan all merge entries (few) to match both
				 * src and resolved_src; cache target dentries. */
				hash_for_each_rcu(kasumi_merge_dirs, mbkt, me, node) {
					if (strcmp(me->src, dp) == 0 ||
					    (me->resolved_src &&
					     strcmp(me->resolved_src, dp) == 0)) {
						w->dir_has_inject = true;
						if (me->target_dentry &&
						    w->merge_target_count < KASUMI_MAX_MERGE_TARGETS)
							w->merge_target_dentries[w->merge_target_count++] =
								me->target_dentry;
					}
				}
				rcu_read_unlock();
			}
		}
	}

	if (!w->dir_has_hidden && !w->dir_has_inject &&
	    (!kasumi_stealth_enabled || w->dir_path_len != 4)) {
		kmem_cache_free(kasumi_filldir_cache, w);
		return NULL;
	}

	return w;
}

void kasumi_iterate_finish_wrapper(struct kasumi_filldir_wrapper *wrapper)
{
	if (!wrapper)
		return;
	if (wrapper->orig_ctx)
		wrapper->orig_ctx->pos = wrapper->wrap_ctx.pos;
	kmem_cache_free(kasumi_filldir_cache, wrapper);
}

static int __maybe_unused kasumi_krp_iterate_dir_entry(struct kretprobe_instance *ri,
						     struct pt_regs *regs)
{
	struct kasumi_iterate_ri_data *d = (void *)ri->data;
	struct dir_context *ctx = (struct dir_context *)KASUMI_REG1(regs);

	d->did_swap = 0;
	d->wrapper = NULL;
	if (ctx && ctx->actor == kasumi_filldir_filter) {
		d->did_swap = 1;
		d->wrapper = container_of(ctx, struct kasumi_filldir_wrapper,
					  wrap_ctx);
	}
	return 0;
}

int kasumi_krp_iterate_dir_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kasumi_iterate_ri_data *d = (void *)ri->data;

	(void)regs;
	if (d->did_swap && d->wrapper) {
		kasumi_iterate_finish_wrapper(d->wrapper);
		d->wrapper = NULL;
	}
	return 0;
}

#define KASUMI_VFS_HOOK_COUNT 4
#define KASUMI_VFS_IDX_GETNAME   0
#define KASUMI_VFS_IDX_GETATTR  1
#define KASUMI_VFS_IDX_DPATH    2
#define KASUMI_VFS_IDX_ITERDIR  3

static const struct {
	const char *name;
	int (*pre)(struct kprobe *, struct pt_regs *);
} kasumi_vfs_hooks[] = {
	{ "getname_flags", kasumi_kp_getname_flags_pre },
	{ "vfs_getattr",   kasumi_kp_vfs_getattr_pre },
	{ "d_path",        kasumi_kp_d_path_pre },
	{ "iterate_dir",   kasumi_kp_iterate_dir_pre },
};
static struct kprobe kasumi_kprobes[KASUMI_VFS_HOOK_COUNT];

static struct kretprobe __maybe_unused kasumi_krp_vfs_getattr;
static struct kretprobe __maybe_unused kasumi_krp_d_path;
static struct kretprobe __maybe_unused kasumi_krp_iterate_dir;
static struct kretprobe kasumi_krp_vfs_getxattr;

int kasumi_vfs_hooks_init(bool skip_vfs)
{
#if KASUMI_VFS_KPROBES
	if (!skip_vfs) {
		int ret;

		pr_alert("Kasumi: STAGE 7: hot VFS kprobes disabled\n");
		kasumi_vfs_use_ftrace = false;
		kasumi_getxattr_kprobe_registered = 0;

		if (kasumi_syscall_dispatcher_nr < 0 ||
		    !kasumi_has_syscall_hook(__NR_openat)) {
			unsigned long addr = kasumi_lookup_name(kasumi_vfs_hooks[0].name);

			if (!addr) {
				pr_err("Kasumi: symbol not found: %s\n", kasumi_vfs_hooks[0].name);
				return -ENOENT;
			}
			kasumi_kprobes[0].addr = (kprobe_opcode_t *)addr;
			kasumi_kprobes[0].pre_handler = kasumi_vfs_hooks[0].pre;
			ret = register_kprobe(&kasumi_kprobes[0]);
			if (ret) {
				pr_err("Kasumi: register_kprobe(getname_flags) failed: %d\n", ret);
				return ret;
			}
			pr_info("Kasumi: kprobe getname_flags @0x%lx\n", addr);
			kasumi_getname_kprobe_registered = true;
		}

		pr_info("Kasumi: initialized (getattr=iop, readdir=fop, d_path=disabled, getxattr kprobe=disabled, GET_FD via %s)\n",
			kasumi_syscall_dispatcher_nr >= 0 ? "TSR" : "kprobes");
	} else {
		pr_alert("Kasumi: skipping VFS hooks (kasumi_skip_vfs=1)\n");
		pr_info("Kasumi: initialized (VFS hooks skipped, GET_FD via %s)\n",
			kasumi_syscall_dispatcher_nr >= 0 ? "TSR" : "kprobes");
	}
#else
	pr_info("Kasumi: initialized (GET_FD only, VFS kprobes disabled)\n");
#endif
	return 0;
}

void kasumi_vfs_hooks_exit(bool skip_vfs)
{
#if KASUMI_VFS_KPROBES
	if (!skip_vfs) {
		if (kasumi_getxattr_kprobe_registered) {
			unregister_kretprobe(&kasumi_krp_vfs_getxattr);
			kasumi_getxattr_kprobe_registered = 0;
		}
		if (kasumi_getname_kprobe_registered) {
			unregister_kprobe(&kasumi_kprobes[0]);
			kasumi_getname_kprobe_registered = false;
		}
	}
#else
	(void)skip_vfs;
#endif
}
