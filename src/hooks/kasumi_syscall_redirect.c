/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - Tracepoint Syscall Redirect dispatcher.
 *
 * One unused ni_syscall table slot is replaced with a shared dispatcher.
 * The sys_enter tracepoint only rewrites the syscall number to that slot;
 * handlers run here later in normal syscall context.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/srcu.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <asm/syscall.h>
#include <asm/unistd.h>
#include <asm/cacheflush.h>

#include "kasumi_base.h"
#include "kasumi_runtime.h"
#include "kasumi_file_view.h"
#include "kasumi_entrypoints.h"
#include "kasumi_path_policy.h"
#include "kasumi_proc_hooks.h"
#include "kasumi_vfs_hooks.h"
#include "kasumi_fake_mountinfo.h"
#include "kasumi_root_detection.h"
#include "kasumi_syscall_redirect.h"
#include "kasumi_fake_selinuxfs_access.h"
#include "kasumi_uname.h"
#include "kasumi_patch_memory.h"

/* ---- Runtime-resolved kernel patching functions ------------------------ */

/*
 * emergency_sync() lives in fs/sync.c but is not EXPORT_SYMBOL — resolved by
 * kallsyms.  It is the same primitive that sysrq-s uses: schedules an async
 * worker that calls ksys_sync().  We rely on the worker completing within
 * the post-timeout msleep before kernel_restart() is invoked.
 */
static void (*ksm_emergency_sync)(void);

static int ksm_resolve_patch_api(void)
{
	/* Best effort — if missing we'll skip the sync before reboot. */
	ksm_emergency_sync = (void *)kasumi_lookup_name("emergency_sync");
	if (ksm_emergency_sync &&
	    kasumi_valid_kernel_addr((unsigned long)ksm_emergency_sync))
		pr_info("Kasumi: emergency_sync @ %lx\n",
			(unsigned long)ksm_emergency_sync);
	else
		pr_warn("Kasumi: emergency_sync not resolved (reboot fallback will skip fs sync)\n");

	return 0;
}

/* ---- Syscall table & redirect ------------------------------------------ */

void *kasumi_syscall_table;
int  kasumi_syscall_dispatcher_nr = -1;
static int kasumi_tsr_basic_param;
module_param_named(kasumi_tsr_basic, kasumi_tsr_basic_param, int, 0600);
MODULE_PARM_DESC(kasumi_tsr_basic, "DBG: TSR hooks only openat/reboot/prctl (skip stat/statfs/read/write/getdents/xattr) to isolate crashing handler.");

static kasumi_syscall_hook_fn hooks[__NR_syscalls];
static kasumi_syscall_hook_fn saved_ni_syscall;
DEFINE_STATIC_SRCU(kasumi_redirect_srcu);

static int patch_entry(int nr, kasumi_syscall_hook_fn fn)
{
	unsigned long addr = (unsigned long)kasumi_syscall_table +
			    nr * sizeof(void *);
	int ret;

	kasumi_log("patch TSR dispatcher slot %d @ %lx -> %px\n", nr, addr, fn);
	ret = kasumi_patch_text((void *)addr, &fn, sizeof(fn),
				KASUMI_PATCH_TEXT_FLUSH_DCACHE);
	if (ret)
		pr_err("Kasumi: patch TSR dispatcher slot %d failed: %d\n",
		       nr, ret);
	return ret;
}

static int find_ni_syscall_slot(void)
{
	kasumi_syscall_hook_fn *table = kasumi_syscall_table;
	unsigned long ni_callable;
	unsigned long ni_raw;
	int i;

	if (!table)
		return -ENOENT;

	ni_callable = kasumi_lookup_callable_quiet("__arm64_sys_ni_syscall");
	ni_raw = kasumi_lookup_name_quiet("__arm64_sys_ni_syscall");
	if (!ni_callable && !ni_raw)
		return -ENOENT;

	for (i = 0; i < __NR_syscalls; i++) {
		unsigned long entry = (unsigned long)READ_ONCE(table[i]);

		if (entry == ni_callable || entry == ni_raw)
			return i;
	}

	return -ENOSPC;
}

static KASUMI_NOCFI long kasumi_call_original(int nr,
					       const struct pt_regs *regs)
{
	kasumi_syscall_hook_fn fn;

	if (!kasumi_syscall_table || nr < 0 || nr >= __NR_syscalls)
		return -ENOSYS;

	fn = READ_ONCE(((kasumi_syscall_hook_fn *)kasumi_syscall_table)[nr]);
	if (!fn)
		return -ENOSYS;
	/* Preserve direct hooks temporarily installed by KernelSU or a peer. */
	return fn(regs);
}

static KASUMI_NOCFI long kasumi_syscall_dispatcher(const struct pt_regs *regs)
{
	kasumi_syscall_hook_fn fn;
	int orig_nr;
	int idx;
	long ret;

	if (!regs || regs->syscallno != READ_ONCE(kasumi_syscall_dispatcher_nr))
		return -ENOSYS;

	orig_nr = (int)PT_REGS_ORIG_SYSCALL(regs);
	if (orig_nr < 0 || orig_nr >= __NR_syscalls ||
	    orig_nr == READ_ONCE(kasumi_syscall_dispatcher_nr))
		return -ENOSYS;

	((struct pt_regs *)regs)->syscallno = orig_nr;
	PT_REGS_ORIG_SYSCALL((struct pt_regs *)regs) = orig_nr;

	if (kasumi_uname_scoped_active() && kasumi_should_apply_hide_rules())
		kasumi_uname_apply_scoped_current();

	idx = srcu_read_lock(&kasumi_redirect_srcu);
	fn = READ_ONCE(hooks[orig_nr]);
	ret = fn ? fn(regs) : kasumi_call_original(orig_nr, regs);
	srcu_read_unlock(&kasumi_redirect_srcu, idx);
	return ret;
}

int kasumi_register_syscall_hook(int nr, kasumi_syscall_hook_fn fn)
{
	if (nr < 0 || nr >= __NR_syscalls)
		return -EINVAL;
	if (READ_ONCE(hooks[nr]))
		return -EEXIST;
	WRITE_ONCE(hooks[nr], fn);
	return 0;
}

void kasumi_unregister_syscall_hook(int nr)
{
	if (nr >= 0 && nr < __NR_syscalls)
		WRITE_ONCE(hooks[nr], NULL);
}

bool kasumi_has_syscall_hook(int nr)
{
	return nr >= 0 && nr < __NR_syscalls && READ_ONCE(hooks[nr]);
}

static void kasumi_add_syscall_hook_counted(int nr, kasumi_syscall_hook_fn fn,
					    int *count)
{
	if (kasumi_register_syscall_hook(nr, fn) == 0)
		(*count)++;
}

/* ---- Hook handlers ----------------------------------------------------- */

#ifndef KASUMI_HIDE_PATH
#define KASUMI_HIDE_PATH "/.kasumi_hidden_placeholder"
#endif

/* ---- GET_FD via reboot / prctl ---------------------------------------- */

static long h_getfd(const struct pt_regs *regs, int nr)
{
#if defined(__aarch64__)
	unsigned long a0 = regs->regs[0];
	unsigned long a1 = regs->regs[1];
	unsigned long a2 = regs->regs[2];
#else
	unsigned long a0 = regs->di;
	unsigned long a1 = regs->si;
	unsigned long a2 = regs->dx;
#endif
	int fd;

	(void)nr;
	if (a0 != KSM_MAGIC1 || a1 != KSM_MAGIC2 ||
	    a2 != (unsigned long)KSM_CMD_GET_FD)
		return -ENOSYS;

	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return -ENOSYS;

	fd = kasumi_get_anon_fd();
	if (fd < 0)
		return -ENOSYS;

#if defined(__aarch64__)
	{
		int __user *fd_ptr = (int __user *)(unsigned long)regs->regs[3];
		if (fd_ptr)
			put_user(fd, fd_ptr);
	}
#endif
	return fd;
}

static long h_reboot(const struct pt_regs *regs)
{
	long ret = h_getfd(regs, __NR_reboot);
	return ret >= 0 ? ret : kasumi_call_original(__NR_reboot, regs);
}

static long h_prctl(const struct pt_regs *regs)
{
#if defined(__aarch64__)
	unsigned long option = regs->regs[0];
	unsigned long arg2 = regs->regs[1];
#else
	unsigned long option = regs->di;
	unsigned long arg2 = regs->si;
#endif

	if (option != (unsigned long)KSM_PRCTL_GET_FD)
		return kasumi_call_original(__NR_prctl, regs);

	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return kasumi_call_original(__NR_prctl, regs);

	{
		int fd = kasumi_get_anon_fd();
		if (fd < 0)
			return kasumi_call_original(__NR_prctl, regs);
#if defined(__aarch64__)
		{
			int __user *fd_ptr = (int __user *)(unsigned long)arg2;
			if (fd_ptr)
				put_user(fd, fd_ptr);
		}
#endif
		return fd;
	}
}

/* ---- /proc/cmdline spoof via TSR -------------------------------------- *
 *
 * read() is a blockable high-frequency syscall.  Hooking it means
 * the dispatcher's SRCU read-side can be held indefinitely while any
 * process is parked in a blocking read (sockets, pipes, ttys — there are
 * always dozens of these in an Android system).  Plain synchronize_srcu()
 * at module exit would never drain.
 *
 * Safety on unload is guaranteed by the bounded drain implemented in
 * kasumi_syscall_redirect_exit(): call_srcu() + wait_for_completion_timeout().
 * If the drain does not complete within 5 seconds we orderly-reboot rather
 * than free module .text out from under in-flight callers.  This is the
 * only correct way to hook a blockable syscall from an LKM — KSU avoids
 * the question entirely by hooking only short, non-blocking syscalls
 * (setresuid/execve/newfstatat/faccessat).
 */
#if defined(__aarch64__) || defined(__x86_64__)
static long h_read(const struct pt_regs *regs)
{
	long ret;
	int fd;
	char __user *buf;
	size_t count;
	struct kasumi_cmdline_rcu *c;
	bool is_cmdline;

	/*
	 * Daemon's own reads of /proc/cmdline must observe the truth (otherwise
	 * the userspace controller can't tell the spoofed cmdline apart from
	 * its own bookkeeping).  Match the policy of the legacy
	 * kasumi_handle_sys_enter_cmdline() path.
	 */
	if (READ_ONCE(kasumi_daemon_pid) > 0 &&
	    task_tgid_vnr(current) == READ_ONCE(kasumi_daemon_pid))
		return kasumi_call_original(__NR_read, regs);

	if (!READ_ONCE(kasumi_cmdline_spoof_active) ||
	    !kasumi_should_apply_hide_rules())
		return kasumi_call_original(__NR_read, regs);

#if defined(__aarch64__)
	fd = (int)regs->regs[0];
	buf = (char __user *)(uintptr_t)regs->regs[1];
	count = (size_t)regs->regs[2];
#else
	fd = (int)regs->di;
	buf = (char __user *)(uintptr_t)regs->si;
	count = (size_t)regs->dx;
#endif

	/*
	 * Resolve the fd's identity BEFORE the read so we don't race a
	 * concurrent close().  fget()/fput() in process context is safe — we
	 * are the syscall body, not a tracepoint or atomic notifier.
	 */
	is_cmdline = kasumi_fd_is_proc_cmdline(fd);

	ret = kasumi_call_original(__NR_read, regs);

	if (!is_cmdline || ret <= 0)
		return ret;

	/*
	 * Overwrite the kernel-supplied buffer in-place with the configured
	 * spoof, mirroring the post-conditions the legacy
	 * kasumi_handle_sys_exit_cmdline() leaves behind: \n-terminated, length
	 * clamped to userspace count, ret reset to bytes actually written.
	 */
	rcu_read_lock();
	c = rcu_dereference(kasumi_spoof_cmdline_ptr);
	if (c && c->cmdline[0]) {
		size_t spoof_len = strnlen(c->cmdline, sizeof(c->cmdline) - 1);
		size_t write_len = spoof_len + 1; /* +1 for trailing \n */
		size_t n;

		if (write_len > count)
			write_len = count;
		n = (spoof_len < write_len) ? spoof_len : write_len - 1;
		if (write_len > 0 && copy_to_user(buf, c->cmdline, n) == 0) {
			if (n < write_len &&
			    copy_to_user(buf + n, "\n", 1) == 0)
				ret = (long)(n + 1);
			else
				ret = (long)n;
		}
	}
	rcu_read_unlock();

	return ret;
}
#endif /* __aarch64__ || __x86_64__ */

/* ---- /proc/self/attr/current dyntransition probe filtering ------------ */
#if defined(__aarch64__) || defined(__x86_64__)
static bool kasumi_fd_is_proc_attr_current(int fd)
{
	struct file *file;
	struct dentry *dentry, *parent;
	bool is_attr_current = false;

	file = fget(fd);
	if (!file)
		return false;

	dentry = file->f_path.dentry;
	parent = dentry ? dentry->d_parent : NULL;
	if (dentry && parent &&
	    dentry->d_name.len == 7 &&
	    memcmp(dentry->d_name.name, "current", 7) == 0 &&
	    parent->d_name.len == 4 &&
	    memcmp(parent->d_name.name, "attr", 4) == 0)
		is_attr_current = true;

	fput(file);
	return is_attr_current;
}

static long h_write(const struct pt_regs *regs)
{
	int fd;
	const char __user *buf;
	size_t count;
	char context[KASUMI_SELINUX_CTX_MAX];
	size_t len;

	if (!(kasumi_feature_enabled_mask & KSM_FEATURE_SELINUX_FIX) ||
	    !kasumi_current_is_selinux_guard_target())
		return kasumi_call_original(__NR_write, regs);

#if defined(__aarch64__)
	fd = (int)regs->regs[0];
	buf = (const char __user *)(uintptr_t)regs->regs[1];
	count = (size_t)regs->regs[2];
#else
	fd = (int)regs->di;
	buf = (const char __user *)(uintptr_t)regs->si;
	count = (size_t)regs->dx;
#endif
	if (!buf || count == 0 || count >= sizeof(context))
		return kasumi_call_original(__NR_write, regs);
	if (!kasumi_fd_is_proc_attr_current(fd))
		return kasumi_call_original(__NR_write, regs);

	len = count;
	if (copy_from_user(context, buf, len))
		return kasumi_call_original(__NR_write, regs);
	context[len] = '\0';

	if (kasumi_fake_selinuxfs_context_is_sensitive(context)) {
		kasumi_log("fake_selinuxfs: rejected attr/current write pid=%d uid=%u comm=%s\n",
			   task_tgid_vnr(current), __kuid_val(current_uid()), current->comm);
		return -EINVAL;
	}

	return kasumi_call_original(__NR_write, regs);
}
#endif /* __aarch64__ || __x86_64__ */

/* ---- path redirect + mount proxy via TSR ------------------------------- */

static void kasumi_set_path_arg1(const struct pt_regs *regs, unsigned long value)
{
#if defined(__aarch64__)
	((struct pt_regs *)regs)->regs[1] = value;
#elif defined(__x86_64__)
	((struct pt_regs *)regs)->si = value;
#endif
}

static void kasumi_set_path_arg0(const struct pt_regs *regs, unsigned long value)
{
#if defined(__aarch64__)
	((struct pt_regs *)regs)->regs[0] = value;
#elif defined(__x86_64__)
	((struct pt_regs *)regs)->di = value;
#endif
}

static KASUMI_NOCFI long kasumi_copy_user_path_at(int dirfd, const char __user *u,
				     char *path, size_t size)
{
	char *page;
	char *dir;
	struct file *file;
	struct path pwd;
	long len;
	int written;

	if (!u || !path || size == 0)
		return -EINVAL;
	len = strncpy_from_user(path, u, size);
	if (len <= 0 || len >= size)
		return len;
	path[size - 1] = '\0';
	if (path[0] == '/' || !kasumi_d_path)
		return len;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page)
		return len;
	if (dirfd == AT_FDCWD) {
		if (!current->fs || !kasumi_path_get_ptr)
			goto out_free;
		spin_lock(&current->fs->lock);
		pwd = current->fs->pwd;
		kasumi_path_get(&pwd);
		spin_unlock(&current->fs->lock);
		dir = kasumi_d_path(&pwd, page, PAGE_SIZE);
		if (!IS_ERR_OR_NULL(dir) && dir[0] == '/') {
			char rel[KSM_MAX_LEN_PATHNAME];

			strscpy(rel, path, sizeof(rel));
			if (strcmp(dir, "/") == 0)
				written = scnprintf(path, size, "/%s", rel);
			else
				written = scnprintf(path, size, "%s/%s", dir, rel);
			if (written > 0 && written < size)
				len = written;
		}
		kasumi_path_put(&pwd);
		goto out_free;
	}
	file = fget(dirfd);
	if (!file)
		goto out_free;
	dir = kasumi_d_path(&file->f_path, page, PAGE_SIZE);
	if (!IS_ERR_OR_NULL(dir) && dir[0] == '/') {
		char rel[KSM_MAX_LEN_PATHNAME];

		strscpy(rel, path, sizeof(rel));
		if (strcmp(dir, "/") == 0)
			written = scnprintf(path, size, "/%s", rel);
		else
			written = scnprintf(path, size, "%s/%s", dir, rel);
		if (written > 0 && written < size)
			len = written;
	}
	fput(file);
out_free:
	free_page((unsigned long)page);
	return len;
}

static long do_openat(const struct pt_regs *regs, int nr)
{
	char path[KSM_MAX_LEN_PATHNAME];
	const char __user *u = (void __user *)(uintptr_t)regs->regs[1];
	char *t;
	char *target_path = NULL;
	long ret;
	int dirfd = (int)regs->regs[0];
	bool raw_proc_proxy = false;
	long tgid = (long)task_tgid_vnr(current);

	if (atomic_long_read(&kasumi_ioctl_tgid) == tgid ||
	    atomic_long_read(&kasumi_xattr_source_tgid) == tgid)
		return kasumi_call_original(nr, regs);
	if (kasumi_copy_user_path_at(dirfd, u, path, sizeof(path)) <= 0)
		return kasumi_call_original(nr, regs);

	if (path[0] == '/' && kasumi_path_needs_proc_proxy(path)) {
		raw_proc_proxy = true;
		if (kasumi_path_is_proc_mountinfo(path) &&
		    kasumi_should_apply_hide_rules())
			kasumi_fake_mi_prepare(false);
	}

	if (path[0] == '/' && atomic_read(&kasumi_rule_count) > 0) {
		t = kasumi_resolve_target_slow(path);
		if (t) {
			size_t l = strlen(t) + 1;
			char __user *n;
			if (l <= KASUMI_PATH_BUF) {
				n = kasumi_userspace_stack_buffer(t, l);
				if (n)
					kasumi_set_path_arg1(regs, (unsigned long)n);
			}
			target_path = t;
		}
	}

	if (unlikely(kasumi_should_hide(path))) {
		char __user *n = kasumi_userspace_stack_buffer(
			KASUMI_HIDE_PATH, sizeof(KASUMI_HIDE_PATH));
		if (n)
			kasumi_set_path_arg1(regs, (unsigned long)n);
	}

	ret = kasumi_call_original(nr, regs);
	if (!raw_proc_proxy && ret >= 0 && target_path)
		(void)kasumi_file_view_bind_fd((int)ret, path, target_path);
	if (raw_proc_proxy && ret >= 0 && kasumi_proc_proxy_should_try())
		kasumi_mount_proxy_install_fd((int)ret);
	kfree(target_path);
	return ret;
}

static long h_openat(const struct pt_regs *r)
{
	return do_openat(r, __NR_openat);
}

static long h_openat2(const struct pt_regs *r)
{
	return do_openat(r, __NR_openat2);
}

static long do_statfs(const struct pt_regs *regs, int nr)
{
	char path[KSM_MAX_LEN_PATHNAME];
	const char __user *u;
	void __user *buf;
	char *target = NULL;
	unsigned long s = 0;
	long ret;

#if defined(__aarch64__)
	u = (const char __user *)(uintptr_t)regs->regs[0];
	buf = (void __user *)(uintptr_t)regs->regs[1];
#else
	u = (const char __user *)(uintptr_t)regs->di;
	buf = (void __user *)(uintptr_t)regs->si;
#endif
	if (kasumi_copy_user_path_at(AT_FDCWD, u, path, sizeof(path)) <= 0)
		return kasumi_call_original(nr, regs);
	if (path[0] == '/' && kasumi_should_hide(path))
		return -ENOENT;

	if ((kasumi_feature_enabled_mask & KSM_FEATURE_STATFS_SPOOF) &&
	    kasumi_should_apply_hide_rules())
		s = kasumi_statfs_resolve_spoof_magic(path);

	if (path[0] == '/') {
		target = kasumi_resolve_target_slow(path);
		if (target) {
			size_t len = strlen(target) + 1;
			char __user *n = NULL;

			if (len <= KASUMI_PATH_BUF)
				n = kasumi_userspace_stack_buffer(target, len);
			if (n)
				kasumi_set_path_arg0(regs, (unsigned long)n);
		}
	}

	ret = kasumi_call_original(nr, regs);
	if (ret >= 0 && s)
		kasumi_statfs_apply_spoof(buf, s);
	kfree(target);
	return ret;
}

static long h_statfs(const struct pt_regs *regs)
{
	return do_statfs(regs, __NR_statfs);
}

/*
 * fstatfs(fd, buf): same INCONSISTENT_MOUNT bypass as statfs, but we resolve
 * the dentry through the open file rather than re-walking the pathname.  This
 * matters because (a) bionic's fstatfs/fstatfs64 wrappers route here, not
 * __NR_statfs, and (b) we avoid kern_path() altogether on a path the caller
 * already opened, which is both faster and not subject to symlink/automount
 * tricks the path-based hook had to compensate for via LOOKUP_FOLLOW.
 */
static long do_fstatfs(const struct pt_regs *regs, int nr)
{
	void __user *buf;
	int fd;
	unsigned long s = 0;
	struct file *file;
	long ret;

#if defined(__aarch64__)
	fd = (int)regs->regs[0];
	buf = (void __user *)(uintptr_t)regs->regs[1];
#else
	fd = (int)regs->di;
	buf = (void __user *)(uintptr_t)regs->si;
#endif

	if (!(kasumi_feature_enabled_mask & KSM_FEATURE_STATFS_SPOOF) ||
	    !kasumi_should_apply_hide_rules())
		return kasumi_call_original(nr, regs);

	file = fget(fd);
	if (file) {
		s = kasumi_statfs_resolve_spoof_magic_dentry(file->f_path.dentry);
		fput(file);
	}
	ret = kasumi_call_original(nr, regs);
	if (ret >= 0 && s)
		kasumi_statfs_apply_spoof(buf, s);
	return ret;
}

static long h_fstatfs(const struct pt_regs *regs)
{
	return do_fstatfs(regs, __NR_fstatfs);
}

#ifdef __NR_statx
static long h_statx(const struct pt_regs *regs)
{
	char path[KSM_MAX_LEN_PATHNAME];
	const char __user *filename_user;
	struct statx __user *buf;
	struct statx stx;
	int fake_mnt_id;
	long path_len;
	long ret;
	int dirfd;

#if defined(__aarch64__)
	dirfd = (int)regs->regs[0];
	filename_user = (const char __user *)(uintptr_t)regs->regs[1];
	buf = (struct statx __user *)(uintptr_t)regs->regs[4];
#else
	dirfd = (int)regs->di;
	filename_user = (const char __user *)(uintptr_t)regs->si;
	buf = (struct statx __user *)(uintptr_t)regs->r8;
#endif
	if (!filename_user || !buf)
		return kasumi_call_original(__NR_statx, regs);

	path_len = kasumi_copy_user_path_at(dirfd, filename_user, path, sizeof(path));
	if (path_len <= 0 || path_len >= sizeof(path))
		return kasumi_call_original(__NR_statx, regs);
	if (path[0] != '/')
		return kasumi_call_original(__NR_statx, regs);
	if (kasumi_should_hide(path))
		return -ENOENT;
	{
		char *target = kasumi_resolve_target_slow(path);

		if (target) {
			size_t len = strlen(target) + 1;
			char __user *n = NULL;

			if (len <= KASUMI_PATH_BUF)
				n = kasumi_userspace_stack_buffer(target, len);
			kfree(target);
			if (n) {
				kasumi_set_path_arg1(regs, (unsigned long)n);
			}
		}
	}

	if (!(kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE) ||
	    !kasumi_should_apply_hide_rules())
		return kasumi_call_original(__NR_statx, regs);

	ret = kasumi_call_original(__NR_statx, regs);
	if (ret != 0)
		return ret;

	fake_mnt_id = kasumi_fake_mi_lookup_mount_id(path);
	if (fake_mnt_id <= 0)
		return ret;
	if (copy_from_user(&stx, buf, sizeof(stx)) != 0)
		return ret;

	stx.stx_mnt_id = (u64)fake_mnt_id;
	if (copy_to_user(buf, &stx, sizeof(stx)) != 0)
		return ret;

	kasumi_log("statx spoof: path=%s fake_mnt_id=%d pid=%d comm=%s\n",
		   path, fake_mnt_id, task_pid_nr(current), current->comm);
	return ret;
}
#endif

struct kasumi_linux_dirent64 {
	u64 d_ino;
	s64 d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

static KASUMI_NOCFI long h_getdents64(const struct pt_regs *regs)
{
	char *kbuf = NULL;
	char *pathbuf = NULL;
	char *dir_path;
	unsigned int pos = 0, out = 0;
	unsigned int max_name_off = offsetof(struct kasumi_linux_dirent64, d_name);
	long ret;
	int fd;
	void __user *udirent;
	struct file *file;

#if defined(__aarch64__)
	fd = (int)regs->regs[0];
	udirent = (void __user *)(uintptr_t)regs->regs[1];
#else
	fd = (int)regs->di;
	udirent = (void __user *)(uintptr_t)regs->si;
#endif
	ret = kasumi_call_original(__NR_getdents64, regs);
	if (ret <= 0 || atomic_read(&kasumi_hide_count) == 0 || !udirent)
		return ret;
	if (ret > 256 * 1024)
		return ret;

	file = fget(fd);
	if (!file)
		return ret;
	pathbuf = (char *)__get_free_page(GFP_KERNEL);
	if (!pathbuf) {
		fput(file);
		return ret;
	}
	dir_path = kasumi_d_path ? kasumi_d_path(&file->f_path, pathbuf, PAGE_SIZE) : ERR_PTR(-ENOENT);
	fput(file);
	if (IS_ERR_OR_NULL(dir_path) || *dir_path != '/') {
		free_page((unsigned long)pathbuf);
		return ret;
	}

	kbuf = kmalloc(ret, GFP_KERNEL);
	if (!kbuf) {
		free_page((unsigned long)pathbuf);
		return ret;
	}
	if (copy_from_user(kbuf, udirent, ret))
		goto out;

	while (pos < ret) {
		struct kasumi_linux_dirent64 *d = (void *)(kbuf + pos);
		unsigned short reclen = d->d_reclen;
		bool hide = false;

		if (reclen < max_name_off + 1 || pos + reclen > ret)
			goto out;
		if (!(d->d_name[0] == '.' &&
		      (d->d_name[1] == '\0' ||
		       (d->d_name[1] == '.' && d->d_name[2] == '\0')))) {
			char *full;

			if (strcmp(dir_path, "/") == 0)
				full = kasprintf(GFP_KERNEL, "/%s", d->d_name);
			else
				full = kasprintf(GFP_KERNEL, "%s/%s", dir_path, d->d_name);
			if (full) {
				hide = kasumi_should_hide(full);
				kfree(full);
			}
		}
		if (hide) {
			atomic64_inc(&kasumi_hook_stats.filldir_hidden);
		} else {
			if (out != pos)
				memmove(kbuf + out, d, reclen);
			out += reclen;
		}
		pos += reclen;
	}
	if (out != ret && !copy_to_user(udirent, kbuf, out))
		ret = out;

out:
	kfree(kbuf);
	free_page((unsigned long)pathbuf);
	return ret;
}

static long do_path1_hide(const struct pt_regs *regs, int nr)
{
	char path[KSM_MAX_LEN_PATHNAME];
	const char __user *u;
	char *target;
	int dirfd;

#if defined(__aarch64__)
	dirfd = (int)regs->regs[0];
	u = (const char __user *)(uintptr_t)regs->regs[1];
#else
	dirfd = (int)regs->di;
	u = (const char __user *)(uintptr_t)regs->si;
#endif
	if (kasumi_copy_user_path_at(dirfd, u, path, sizeof(path)) <= 0)
		return kasumi_call_original(nr, regs);
	if (path[0] == '/' && kasumi_should_hide(path))
		return -ENOENT;
	if (path[0] == '/') {
		target = kasumi_resolve_target_slow(path);
		if (target) {
			size_t len = strlen(target) + 1;
			char __user *n = NULL;

			if (len <= KASUMI_PATH_BUF)
				n = kasumi_userspace_stack_buffer(target, len);
			kfree(target);
			if (n)
				kasumi_set_path_arg1(regs, (unsigned long)n);
		}
	}
	return kasumi_call_original(nr, regs);
}

static long do_path0_hide(const struct pt_regs *regs, int nr)
{
	char path[KSM_MAX_LEN_PATHNAME];
	const char __user *u;
	char *target;

#if defined(__aarch64__)
	u = (const char __user *)(uintptr_t)regs->regs[0];
#else
	u = (const char __user *)(uintptr_t)regs->di;
#endif
	if (kasumi_copy_user_path_at(AT_FDCWD, u, path, sizeof(path)) <= 0)
		return kasumi_call_original(nr, regs);
	if (path[0] == '/' && kasumi_should_hide(path))
		return -ENOENT;
	if (path[0] == '/') {
		target = kasumi_resolve_target_slow(path);
		if (target) {
			size_t len = strlen(target) + 1;
			char __user *n = NULL;

			if (len <= KASUMI_PATH_BUF)
				n = kasumi_userspace_stack_buffer(target, len);
			kfree(target);
			if (n)
				kasumi_set_path_arg0(regs, (unsigned long)n);
		}
	}
	return kasumi_call_original(nr, regs);
}

#ifdef __NR_statfs64
static long h_statfs64(const struct pt_regs *regs)
{
	return do_statfs(regs, __NR_statfs64);
}
#endif

#ifdef __NR_fstatfs64
static long h_fstatfs64(const struct pt_regs *regs)
{
	return do_fstatfs(regs, __NR_fstatfs64);
}
#endif

#ifdef __NR_newfstatat
static long h_newfstatat(const struct pt_regs *regs)
{
	return do_path1_hide(regs, __NR_newfstatat);
}
#endif

#ifdef __NR_faccessat
static long h_faccessat(const struct pt_regs *regs)
{
	return do_path1_hide(regs, __NR_faccessat);
}
#endif

#ifdef __NR_getxattr
static long h_getxattr(const struct pt_regs *regs)
{
	return do_path0_hide(regs, __NR_getxattr);
}
#endif

#ifdef __NR_lgetxattr
static long h_lgetxattr(const struct pt_regs *regs)
{
	return do_path0_hide(regs, __NR_lgetxattr);
}
#endif

#ifdef __NR_listxattr
static long h_listxattr(const struct pt_regs *regs)
{
	return do_path0_hide(regs, __NR_listxattr);
}
#endif

#ifdef __NR_llistxattr
static long h_llistxattr(const struct pt_regs *regs)
{
	return do_path0_hide(regs, __NR_llistxattr);
}
#endif

/* ---- Init / exit ------------------------------------------------------- */

int kasumi_syscall_redirect_init(void)
{
	int n = 0;
	int ret;
	int slot;

	ret = ksm_resolve_patch_api();
	if (ret)
		return ret;

	kasumi_syscall_table = (void *)kasumi_lookup_name("sys_call_table");
	if (!kasumi_syscall_table)
		return -ENOENT;

	slot = find_ni_syscall_slot();
	if (slot < 0) {
		pr_err("Kasumi: no free ni_syscall slot: %d\n", slot);
		kasumi_syscall_table = NULL;
		return slot;
	}
	if ((kasumi_root_mask & KASUMI_ROOT_KSU_RDR) &&
	    kasumi_ksu_dispatcher_nr >= 0 && slot == kasumi_ksu_dispatcher_nr) {
		pr_err("Kasumi: refusing KernelSU dispatcher slot %d\n", slot);
		kasumi_syscall_table = NULL;
		return -EBUSY;
	}

	saved_ni_syscall = READ_ONCE(
		((kasumi_syscall_hook_fn *)kasumi_syscall_table)[slot]);
	WRITE_ONCE(kasumi_syscall_dispatcher_nr, slot);
	ret = patch_entry(slot, kasumi_syscall_dispatcher);
	if (ret) {
		WRITE_ONCE(kasumi_syscall_dispatcher_nr, -1);
		saved_ni_syscall = NULL;
		kasumi_syscall_table = NULL;
		return ret;
	}

	kasumi_add_syscall_hook_counted(__NR_openat, h_openat, &n);
	kasumi_add_syscall_hook_counted(__NR_openat2, h_openat2, &n);
	kasumi_add_syscall_hook_counted(__NR_reboot, h_reboot, &n);
	kasumi_add_syscall_hook_counted(__NR_prctl, h_prctl, &n);
	if (!kasumi_tsr_basic_param) {
		kasumi_add_syscall_hook_counted(__NR_statfs, h_statfs, &n);
		kasumi_add_syscall_hook_counted(__NR_fstatfs, h_fstatfs, &n);
#ifdef __NR_statx
		kasumi_add_syscall_hook_counted(__NR_statx, h_statx, &n);
#endif
#ifdef __NR_statfs64
		kasumi_add_syscall_hook_counted(__NR_statfs64, h_statfs64, &n);
#endif
#ifdef __NR_fstatfs64
		kasumi_add_syscall_hook_counted(__NR_fstatfs64, h_fstatfs64, &n);
#endif
#if defined(__aarch64__) || defined(__x86_64__)
		kasumi_add_syscall_hook_counted(__NR_read, h_read, &n);
		kasumi_add_syscall_hook_counted(__NR_write, h_write, &n);
#endif
		kasumi_add_syscall_hook_counted(__NR_getdents64, h_getdents64, &n);
#ifdef __NR_newfstatat
		kasumi_add_syscall_hook_counted(__NR_newfstatat, h_newfstatat, &n);
#endif
#ifdef __NR_faccessat
		kasumi_add_syscall_hook_counted(__NR_faccessat, h_faccessat, &n);
#endif
#ifdef __NR_getxattr
		kasumi_add_syscall_hook_counted(__NR_getxattr, h_getxattr, &n);
#endif
#ifdef __NR_lgetxattr
		kasumi_add_syscall_hook_counted(__NR_lgetxattr, h_lgetxattr, &n);
#endif
#ifdef __NR_listxattr
		kasumi_add_syscall_hook_counted(__NR_listxattr, h_listxattr, &n);
#endif
#ifdef __NR_llistxattr
		kasumi_add_syscall_hook_counted(__NR_llistxattr, h_llistxattr, &n);
#endif
	}

	pr_info("Kasumi: TSR dispatcher ready at ni_syscall slot %d, %d routes\n",
		slot, n);
	return 0;
}

/*
 * Per-call drain bookkeeping for kasumi_syscall_redirect_exit().  The
 * struct lives as a function-static so it survives if we hit the reboot
 * fallback path — we never want call_srcu's callback writing into a freed
 * stack frame.
 */
struct kasumi_drain_state {
	struct rcu_head head;
	struct completion *done;
};

static void kasumi_redirect_drain_done(struct rcu_head *head)
{
	struct kasumi_drain_state *s =
		container_of(head, struct kasumi_drain_state, head);
	complete(s->done);
}

KASUMI_NOCFI void kasumi_syscall_redirect_exit(void)
{
	DECLARE_COMPLETION_ONSTACK(drain_done);
	static struct kasumi_drain_state drain;
	kasumi_syscall_hook_fn installed;
	int slot;
	int i;
	bool drained;
	bool active;

	slot = READ_ONCE(kasumi_syscall_dispatcher_nr);
	active = slot >= 0 && kasumi_syscall_table && saved_ni_syscall;
	if (!active)
		goto clear_state;

	/*
	 * Teardown ordering, mirroring KSU's ksu_syscall_hook_exit():
	 *
	 *   1. The sys_enter tracepoint has already been unregistered by the
	 *      bootstrap, so no new syscall can be redirected here.
	 *
	 *   2. Restore the single ni_syscall dispatcher slot while the hook table
	 *      is still intact. Any task already inside the dispatcher can finish
	 *      with a valid handler lookup.
	 *
	 *   3. Drain in-flight handlers via SRCU with a bounded timeout. For
	 *      the short syscalls we currently hook (openat / openat2 / statfs
	 *      / reboot / prctl) this completes in well under a millisecond.
	 *      If a future blockable hook (e.g. h_read) is registered, an
	 *      in-flight call can hang in vfs_read indefinitely; in that case
	 *      we cannot safely free module .text — fall through to an orderly
	 *      reboot instead.
	 *
	 *   4. Now we can clear the hook table; no reader can observe it.
	 *
	 * Clearing hooks before the drain would let an in-flight dispatcher see
	 * incomplete state or return -ENOSYS unexpectedly.
	 */
	installed = READ_ONCE(
		((kasumi_syscall_hook_fn *)kasumi_syscall_table)[slot]);
	if (installed == kasumi_syscall_dispatcher)
		(void)patch_entry(slot, saved_ni_syscall);
	else
		pr_warn("Kasumi: TSR slot %d changed by another owner; not restoring it\n",
			slot);

	/*
	 * Async SRCU drain so we can bound the wait.  `drain` is a static so
	 * it survives if we hit the timeout path and reboot — we don't want
	 * the callback writing to a freed stack frame.
	 */
	drain.done = &drain_done;
	kasumi_call_srcu_ptr(&kasumi_redirect_srcu, &drain.head, kasumi_redirect_drain_done);
	drained = wait_for_completion_timeout(&drain_done, 5 * HZ) != 0;

	if (!drained) {
		/*
		 * In-flight syscall handler stuck in our .text — most likely
		 * a future read/write/poll-class hook waiting on I/O.  Freeing
		 * module memory now would leave that handler with a dangling
		 * return address.  Sync filesystems and reboot.
		 */
		pr_emerg("Kasumi: syscall handlers did not drain in 5s; rebooting in 3s to keep module .text alive for in-flight callers\n");

		if (ksm_emergency_sync) {
			pr_emerg("Kasumi: emergency_sync() before reboot\n");
			ksm_emergency_sync();
		}

		/*
		 * Give emergency_sync's workqueue time to finish (its worker
		 * is async) and userspace a moment to read the dmesg banner.
		 */
		msleep(3000);

		kernel_restart("kasumi: unload SRCU drain timeout");
		/* unreachable */
		return;
	}

	for (i = 0; i < __NR_syscalls; i++)
		WRITE_ONCE(hooks[i], NULL);

clear_state:
	WRITE_ONCE(kasumi_syscall_dispatcher_nr, -1);
	saved_ni_syscall = NULL;
	kasumi_syscall_table = NULL;
	pr_info("Kasumi: TSR dispatcher exited\n");
}
