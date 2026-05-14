/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - syscall table redirect via aarch64_insn_write_literal_u64.
 *
 * Uses the kernel's own instruction-patching machinery (which internally
 * handles patch_lock, fixmap, TLB flush, and cache maintenance) to swap
 * an unused ni_syscall slot with a dispatcher.  The tracepoint handler
 * only rewrites syscallno into the dispatcher slot — a single-register
 * store.  The hook handlers run in normal process context.
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
#include <linux/sched.h>
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

/* ---- Runtime-resolved kernel patching functions ------------------------ */

static int (*ksm_insn_write_u64)(void *addr, u64 val);

/*
 * emergency_sync() lives in fs/sync.c but is not EXPORT_SYMBOL — resolved by
 * kallsyms.  It is the same primitive that sysrq-s uses: schedules an async
 * worker that calls ksys_sync().  We rely on the worker completing within
 * the post-timeout msleep before kernel_restart() is invoked.
 */
static void (*ksm_emergency_sync)(void);

static int ksm_resolve_patch_api(void)
{
	ksm_insn_write_u64 = (void *)kasumi_lookup_name(
		"aarch64_insn_write_literal_u64");
	if (ksm_insn_write_u64 &&
	    kasumi_valid_kernel_addr((unsigned long)ksm_insn_write_u64)) {
		pr_info("Kasumi: aarch64_insn_write_literal_u64 @ %lx\n",
			(unsigned long)ksm_insn_write_u64);
	} else {
		pr_err("Kasumi: aarch64_insn_write_literal_u64 not found\n");
		return -ENOENT;
	}

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
static kasumi_syscall_hook_fn hooks[__NR_syscalls];
static kasumi_syscall_hook_fn saved_ni;
DEFINE_STATIC_SRCU(kasumi_redirect_srcu);
kasumi_syscall_hook_fn orig_kernel_openat, orig_kernel_openat2, orig_kernel_statfs, orig_kernel_fstatfs;
#ifdef __NR_statfs64
kasumi_syscall_hook_fn orig_kernel_statfs64;
#endif
#ifdef __NR_fstatfs64
kasumi_syscall_hook_fn orig_kernel_fstatfs64;
#endif

static int patch_entry(int nr, kasumi_syscall_hook_fn fn)
{
	unsigned long addr = (unsigned long)kasumi_syscall_table +
			    nr * sizeof(void *);
	u64 val = (u64)fn;
	int ret;

	kasumi_log("patch syscall %d @ %lx -> %llx\n", nr, addr, val);
	ret = ksm_insn_write_u64((void *)addr, val);
	if (ret)
		pr_err("Kasumi: aarch64_insn_write_literal_u64(%lx) failed: %d\n",
		       addr, ret);
	return ret;
}

static int find_ni_slot(void)
{
	unsigned long ni = kasumi_lookup_name("__arm64_sys_ni_syscall.cfi_jt");
	int i;
	if (!ni || !kasumi_valid_kernel_addr(ni))
		ni = kasumi_lookup_name("__arm64_sys_ni_syscall");
	if (!ni || !kasumi_valid_kernel_addr(ni))
		return -ENOENT;
	for (i = 0; i < __NR_syscalls; i++)
		if ((unsigned long)((kasumi_syscall_hook_fn *)
				    kasumi_syscall_table)[i] == ni)
			return i;
	return -ENOENT;
}

static long __nocfi dispatcher(const struct pt_regs *regs)
{
	int orig = (int)((struct pt_regs *)regs)->regs[8];
	kasumi_syscall_hook_fn fn;
	long ret;
	int idx;

	if (orig < 0 || orig >= __NR_syscalls)
		return -ENOSYS;
	((struct pt_regs *)regs)->syscallno = orig;
	((struct pt_regs *)regs)->regs[8] = orig;

	idx = srcu_read_lock(&kasumi_redirect_srcu);
	fn = READ_ONCE(hooks[orig]);
	ret = likely(fn) ? fn(regs) : -ENOSYS;
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

/* ---- Hook handlers ----------------------------------------------------- */

#ifndef KASUMI_HIDE_PATH
#define KASUMI_HIDE_PATH "/.kasumi_hidden_placeholder"
#endif

/* saved original handlers for GET_FD / cmdline */
static kasumi_syscall_hook_fn orig_kernel_reboot;
static kasumi_syscall_hook_fn orig_kernel_prctl;
static kasumi_syscall_hook_fn orig_kernel_read;
static kasumi_syscall_hook_fn orig_kernel_write;

/* ---- GET_FD via reboot / prctl / custom nr (TSR) ---------------------- */

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
	return ret >= 0 ? ret : orig_kernel_reboot(regs);
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
		return orig_kernel_prctl(regs);

	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return orig_kernel_prctl(regs);

	{
		int fd = kasumi_get_anon_fd();
		if (fd < 0)
			return orig_kernel_prctl(regs);
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

/* ---- /proc/cmdline spoof via TSR (replaces sys_enter+sys_exit pair) ---- *
 *
 * read() is a blockable high-frequency syscall.  Hooking it means
 * dispatcher()'s SRCU read-side can be held indefinitely while any
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
		return orig_kernel_read(regs);

	if (!READ_ONCE(kasumi_cmdline_spoof_active) ||
	    !kasumi_should_apply_hide_rules())
		return orig_kernel_read(regs);

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

	ret = orig_kernel_read(regs);

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
		return orig_kernel_write(regs);

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
		return orig_kernel_write(regs);
	if (!kasumi_fd_is_proc_attr_current(fd))
		return orig_kernel_write(regs);

	len = count;
	if (copy_from_user(context, buf, len))
		return orig_kernel_write(regs);
	context[len] = '\0';

	if (kasumi_fake_selinuxfs_context_is_sensitive(context)) {
		kasumi_log("fake_selinuxfs: rejected attr/current write pid=%d uid=%u comm=%s\n",
			   task_tgid_vnr(current), __kuid_val(current_uid()), current->comm);
		return -EINVAL;
	}

	return orig_kernel_write(regs);
}
#endif /* __aarch64__ || __x86_64__ */

/* ---- path redirect + mount proxy (TSR) --------------------------------- */

static long do_openat(const struct pt_regs *regs, kasumi_syscall_hook_fn orig)
{
	char path[KSM_MAX_LEN_PATHNAME];
	const char __user *u = (void __user *)(uintptr_t)regs->regs[1];
	char *t;
	char *target_path = NULL;
	long ret;
	bool raw_proc_proxy = false;
	long tgid = (long)task_tgid_vnr(current);

	if (atomic_long_read(&kasumi_ioctl_tgid) == tgid ||
	    atomic_long_read(&kasumi_xattr_source_tgid) == tgid)
		return orig(regs);
	if (!u || copy_from_user(path, u, sizeof(path) - 1))
		return orig(regs);
	path[sizeof(path) - 1] = '\0';

	if (path[0] == '/' && kasumi_path_needs_proc_proxy(path)) {
		raw_proc_proxy = true;
		if (kasumi_path_is_proc_mountinfo(path) &&
		    kasumi_should_apply_hide_rules())
			kasumi_fake_mi_prepare(false);
	}

	if (path[0] == '/' && atomic_read(&kasumi_rule_count) > 0) {
		t = kasumi_resolve_target(path);
		if (t) {
			size_t l = strlen(t) + 1;
			char __user *n;
			if (l <= KASUMI_PATH_BUF) {
				n = kasumi_userspace_stack_buffer(t, l);
				if (n)
					((unsigned long *)regs)[1] =
						(unsigned long)n;
			}
			target_path = t;
		}
	}

	if (unlikely(kasumi_should_hide(path))) {
		char __user *n = kasumi_userspace_stack_buffer(
			KASUMI_HIDE_PATH, sizeof(KASUMI_HIDE_PATH));
		if (n)
			((unsigned long *)regs)[1] = (unsigned long)n;
	}

	ret = orig(regs);
	if (!raw_proc_proxy && ret >= 0 && target_path)
		(void)kasumi_file_view_bind_fd((int)ret, path, target_path);
	if (ret >= 0 && kasumi_proc_proxy_should_try())
		kasumi_mount_proxy_install_fd((int)ret);
	kfree(target_path);
	return ret;
}

static long h_openat(const struct pt_regs *r)  { return do_openat(r, orig_kernel_openat); }
static long h_openat2(const struct pt_regs *r) { return do_openat(r, orig_kernel_openat2); }

static long h_statfs(const struct pt_regs *regs)
{
	char path[KSM_MAX_LEN_PATHNAME];
	void __user *buf = (void __user *)(uintptr_t)regs->regs[1];
	unsigned long s;
	long ret;

	if (!(kasumi_feature_enabled_mask & KSM_FEATURE_STATFS_SPOOF) ||
	    !kasumi_should_apply_hide_rules())
		return orig_kernel_statfs(regs);
	if (copy_from_user(path, (void __user *)(uintptr_t)regs->regs[0],
			  sizeof(path) - 1))
		return orig_kernel_statfs(regs);
	path[sizeof(path) - 1] = 0;

	s = kasumi_statfs_resolve_spoof_magic(path);
	ret = orig_kernel_statfs(regs);
	if (ret >= 0 && s)
		kasumi_statfs_apply_spoof(buf, s);
	return ret;
}

/*
 * fstatfs(fd, buf): same INCONSISTENT_MOUNT bypass as statfs, but we resolve
 * the dentry through the open file rather than re-walking the pathname.  This
 * matters because (a) bionic's fstatfs/fstatfs64 wrappers route here, not
 * __NR_statfs, and (b) we avoid kern_path() altogether on a path the caller
 * already opened, which is both faster and not subject to symlink/automount
 * tricks the path-based hook had to compensate for via LOOKUP_FOLLOW.
 */
static long h_fstatfs(const struct pt_regs *regs)
{
	void __user *buf = (void __user *)(uintptr_t)regs->regs[1];
	int fd = (int)regs->regs[0];
	unsigned long s = 0;
	struct file *file;
	long ret;

	if (!(kasumi_feature_enabled_mask & KSM_FEATURE_STATFS_SPOOF) ||
	    !kasumi_should_apply_hide_rules())
		return orig_kernel_fstatfs(regs);

	file = fget(fd);
	if (file) {
		s = kasumi_statfs_resolve_spoof_magic_dentry(file->f_path.dentry);
		fput(file);
	}
	ret = orig_kernel_fstatfs(regs);
	if (ret >= 0 && s)
		kasumi_statfs_apply_spoof(buf, s);
	return ret;
}

/* ---- Init / exit ------------------------------------------------------- */

int kasumi_syscall_redirect_init(void)
{
	int slot, ret;

	ret = ksm_resolve_patch_api();
	if (ret)
		return ret;

	kasumi_syscall_table = (void *)kasumi_lookup_name("sys_call_table");
	if (!kasumi_syscall_table)
		return -ENOENT;

	orig_kernel_openat = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[__NR_openat];
	orig_kernel_openat2 = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[__NR_openat2];
	orig_kernel_statfs = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[__NR_statfs];
	orig_kernel_fstatfs = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[__NR_fstatfs];
#ifdef __NR_statfs64
	orig_kernel_statfs64 = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[__NR_statfs64];
#endif
#ifdef __NR_fstatfs64
	orig_kernel_fstatfs64 = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[__NR_fstatfs64];
#endif
	orig_kernel_reboot = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[__NR_reboot];
	orig_kernel_prctl = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[__NR_prctl];
#if defined(__aarch64__) || defined(__x86_64__)
	orig_kernel_read = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[__NR_read];
	orig_kernel_write = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[__NR_write];
#endif

	slot = find_ni_slot();
	if (slot < 0) {
		pr_err("Kasumi: no ni_syscall slot\n");
		return slot;
	}
	if ((kasumi_root_mask & KASUMI_ROOT_KSU_RDR) &&
	    kasumi_ksu_dispatcher_nr >= 0 &&
	    slot == kasumi_ksu_dispatcher_nr) {
		pr_warn("Kasumi: TSR slot %d conflicts with KernelSU redirect, falling back to non-TSR hooks\n",
			slot);
		return -EBUSY;
	}
	kasumi_syscall_dispatcher_nr = slot;
	saved_ni = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[slot];

	ret = patch_entry(slot, (kasumi_syscall_hook_fn)dispatcher);
	if (ret) {
		pr_err("Kasumi: patch dispatcher failed: %d\n", ret);
		kasumi_syscall_dispatcher_nr = -1;
		return ret;
	}

{
	int n = 0;
	kasumi_register_syscall_hook(__NR_openat,  h_openat);  n++;
	kasumi_register_syscall_hook(__NR_openat2, h_openat2); n++;
	kasumi_register_syscall_hook(__NR_statfs,  h_statfs);  n++;
	kasumi_register_syscall_hook(__NR_fstatfs, h_fstatfs); n++;
#ifdef __NR_statfs64
	kasumi_register_syscall_hook(__NR_statfs64, h_statfs); n++;
#endif
#ifdef __NR_fstatfs64
	kasumi_register_syscall_hook(__NR_fstatfs64, h_fstatfs); n++;
#endif
	kasumi_register_syscall_hook(__NR_reboot,  h_reboot);  n++;
	kasumi_register_syscall_hook(__NR_prctl,   h_prctl);   n++;
#if defined(__aarch64__) || defined(__x86_64__)
	kasumi_register_syscall_hook(__NR_read,    h_read);    n++;
	kasumi_register_syscall_hook(__NR_write,   h_write);   n++;
#endif
	pr_info("Kasumi: redirect active @ slot %d, %d hooks\n",
		kasumi_syscall_dispatcher_nr, n);
}
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

void kasumi_syscall_redirect_exit(void)
{
	DECLARE_COMPLETION_ONSTACK(drain_done);
	static struct kasumi_drain_state drain;
	int i;
	bool drained;

	/*
	 * Caller (kasumi_bootstrap_exit) has already unregistered the
	 * sys_enter/sys_exit tracepoint and called
	 * tracepoint_synchronize_unregister(), so no fresh syscall will have
	 * its syscallno rewritten to our dispatcher slot from this point on.
	 *
	 * Teardown ordering, mirroring KSU's ksu_syscall_hook_exit():
	 *
	 *   1. Restore the sys_call_table[slot] -> ni_syscall while the hook
	 *      table is still intact, so any in-flight syscall already in the
	 *      dispatcher (with syscallno already set to our slot) finishes
	 *      with a valid handler lookup.  After this patch, the dispatcher
	 *      stops being entered.
	 *
	 *   2. Drain in-flight handlers via SRCU with a bounded timeout.  For
	 *      the short syscalls we currently hook (openat / openat2 / statfs
	 *      / reboot / prctl) this completes in well under a millisecond.
	 *      If a future blockable hook (e.g. h_read) is registered, an
	 *      in-flight call can hang in vfs_read indefinitely; in that case
	 *      we cannot safely free module .text — fall through to an orderly
	 *      reboot instead.
	 *
	 *   3. Now we can clear the hook table — no reader can observe it.
	 *
	 * Doing it in the opposite order (clear hooks before patch) would let
	 * a tracepoint-rewritten syscall enter dispatcher(), find hooks[nr] ==
	 * NULL, and erroneously return -ENOSYS to userspace.
	 */
	if (kasumi_syscall_dispatcher_nr >= 0)
		patch_entry(kasumi_syscall_dispatcher_nr, saved_ni);

	/*
	 * Async SRCU drain so we can bound the wait.  `drain` is a static so
	 * it survives if we hit the timeout path and reboot — we don't want
	 * the callback writing to a freed stack frame.
	 */
	drain.done = &drain_done;
	call_srcu(&kasumi_redirect_srcu, &drain.head, kasumi_redirect_drain_done);
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

	kasumi_syscall_dispatcher_nr = -1;
	orig_kernel_openat  = NULL;
	orig_kernel_openat2 = NULL;
	orig_kernel_statfs  = NULL;
	orig_kernel_fstatfs = NULL;
#ifdef __NR_statfs64
	orig_kernel_statfs64 = NULL;
#endif
#ifdef __NR_fstatfs64
	orig_kernel_fstatfs64 = NULL;
#endif
	orig_kernel_reboot  = NULL;
	orig_kernel_prctl   = NULL;
	orig_kernel_read    = NULL;
	orig_kernel_write   = NULL;
	pr_info("Kasumi: redirect exited\n");
}
