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
#include "kasumi_vfs_hooks.h"
#include "kasumi_root_detection.h"
#include "kasumi_syscall_redirect.h"
#include "kasumi_patch_memory.h"

/* ---- Syscall table & redirect ------------------------------------------ */

void *kasumi_syscall_table;
int  kasumi_syscall_dispatcher_nr = -1;
static int kasumi_tsr_basic_param;
module_param_named(kasumi_tsr_basic, kasumi_tsr_basic_param, int, 0600);
MODULE_PARM_DESC(kasumi_tsr_basic, "DBG: TSR hooks only openat/openat2 (skip path/stat routes) to isolate crashing handler.");

static kasumi_syscall_hook_fn hooks[__NR_syscalls];
static kasumi_syscall_hook_fn saved_ni_syscall;
static int kasumi_installed_dispatcher_slot = -1;
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
	int next_nr = nr;

	if (!kasumi_syscall_table || nr < 0 || nr >= __NR_syscalls)
		return -ENOSYS;

	/* KernelSU owns the same two routes upstream. Kasumi runs after its
	 * sys_enter callback, projects the VIEW pathname, then invokes the whole
	 * KernelSU dispatcher so sucompat and the real syscall still execute once.
	 * This uses the upstream dispatcher ABI instead of private helper symbols.
	 */
	if ((READ_ONCE(kasumi_root_mask) & KASUMI_ROOT_KSU_RDR) &&
	    READ_ONCE(kasumi_ksu_dispatcher_nr) >= 0) {
#ifdef __NR_newfstatat
		if (nr == __NR_newfstatat)
			next_nr = READ_ONCE(kasumi_ksu_dispatcher_nr);
#endif
#ifdef __NR_faccessat
		if (nr == __NR_faccessat)
			next_nr = READ_ONCE(kasumi_ksu_dispatcher_nr);
#endif
	}
	if (next_nr < 0 || next_nr >= __NR_syscalls ||
	    next_nr == READ_ONCE(kasumi_syscall_dispatcher_nr))
		return -ENOSYS;

	fn = READ_ONCE(((kasumi_syscall_hook_fn *)kasumi_syscall_table)[next_nr]);
	if (!fn)
		return -ENOSYS;
	if (next_nr != nr) {
		((struct pt_regs *)regs)->syscallno = next_nr;
		PT_REGS_ORIG_SYSCALL((struct pt_regs *)regs) = nr;
	}
	/* Preserve direct hooks and the upstream KernelSU dispatcher. */
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

bool kasumi_syscall_redirect_claimable(int nr, int current_nr)
{
	if (current_nr == nr)
		return true;
	if (!(READ_ONCE(kasumi_root_mask) & KASUMI_ROOT_KSU_RDR) ||
	    current_nr != READ_ONCE(kasumi_ksu_dispatcher_nr))
		return false;
#ifdef __NR_newfstatat
	if (nr == __NR_newfstatat)
		return true;
#endif
#ifdef __NR_faccessat
	if (nr == __NR_faccessat)
		return true;
#endif
	return false;
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
	long tgid = (long)task_tgid_vnr(current);

	if (atomic_long_read(&kasumi_ioctl_tgid) == tgid ||
	    atomic_long_read(&kasumi_xattr_source_tgid) == tgid)
		return kasumi_call_original(nr, regs);
	if (kasumi_copy_user_path_at(dirfd, u, path, sizeof(path)) <= 0)
		return kasumi_call_original(nr, regs);

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
	if (ret >= 0 && target_path)
		(void)kasumi_file_view_bind_fd((int)ret, path, target_path);
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
	char *target = NULL;
	long ret;

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
			if (n)
				kasumi_set_path_arg0(regs, (unsigned long)n);
		}
	}

	ret = kasumi_call_original(nr, regs);
	kfree(target);
	return ret;
}

static long h_statfs(const struct pt_regs *regs)
{
	return do_statfs(regs, __NR_statfs);
}

#ifdef __NR_statx
static long h_statx(const struct pt_regs *regs)
{
	char path[KSM_MAX_LEN_PATHNAME];
	const char __user *filename_user;
	long path_len;
	int dirfd;

#if defined(__aarch64__)
	dirfd = (int)regs->regs[0];
	filename_user = (const char __user *)(uintptr_t)regs->regs[1];
#else
	dirfd = (int)regs->di;
	filename_user = (const char __user *)(uintptr_t)regs->si;
#endif
	if (!filename_user)
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

	return kasumi_call_original(__NR_statx, regs);
}
#endif

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
	/* KernelSU reserves this exact path for sucompat on faccessat and
	 * newfstatat. Preserve the sentinel until its dispatcher has handled it;
	 * otherwise a Kasumi redirect/hide rule would silently disable `su`.
	 */
	if ((READ_ONCE(kasumi_root_mask) & KASUMI_ROOT_KSU_RDR) &&
	    !strcmp(path, "/system/bin/su"))
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
	kasumi_installed_dispatcher_slot = slot;
	ret = patch_entry(slot, kasumi_syscall_dispatcher);
	if (ret) {
		WRITE_ONCE(kasumi_syscall_dispatcher_nr, -1);
		kasumi_installed_dispatcher_slot = -1;
		saved_ni_syscall = NULL;
		kasumi_syscall_table = NULL;
		return ret;
	}

	kasumi_add_syscall_hook_counted(__NR_openat, h_openat, &n);
	kasumi_add_syscall_hook_counted(__NR_openat2, h_openat2, &n);
	if (!kasumi_tsr_basic_param) {
		kasumi_add_syscall_hook_counted(__NR_statfs, h_statfs, &n);
#ifdef __NR_statx
		kasumi_add_syscall_hook_counted(__NR_statx, h_statx, &n);
#endif
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

/* Per-call drain bookkeeping for kasumi_syscall_redirect_exit(). */
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

KASUMI_NOCFI int kasumi_syscall_redirect_stop_new(void)
{
	kasumi_syscall_hook_fn installed;
	int slot = READ_ONCE(kasumi_installed_dispatcher_slot);
	int ret;

	if (slot < 0 || !kasumi_syscall_table || !saved_ni_syscall)
		return 0;
	if (READ_ONCE(kasumi_syscall_dispatcher_nr) < 0)
		return 0;

	installed = READ_ONCE(
		((kasumi_syscall_hook_fn *)kasumi_syscall_table)[slot]);
	if (installed == kasumi_syscall_dispatcher) {
		ret = patch_entry(slot, saved_ni_syscall);
		if (ret)
			return ret;
	} else if (installed != saved_ni_syscall) {
		pr_err("Kasumi: TSR slot %d ownership changed; refusing unsafe detach\n",
		       slot);
		return -EBUSY;
	} else {
		pr_info("Kasumi: TSR slot %d was already restored\n", slot);
	}
	/* A caller can invoke the occupied ni_syscall slot directly without a
	 * sys_enter redirect guard.  Tasks-RCU closes the table-load-to-dispatcher
	 * entry window for that guardless path before unload may proceed.
	 */
	kasumi_synchronize_rcu_tasks();

	/* Keep the table, handlers and SRCU domain alive for dispatchers that
	 * entered before the slot was restored. Final teardown drains them.
	 */
	WRITE_ONCE(kasumi_syscall_dispatcher_nr, -1);
	return 0;
}

bool kasumi_syscall_redirect_detached(void)
{
	return READ_ONCE(kasumi_syscall_dispatcher_nr) < 0;
}

KASUMI_NOCFI void kasumi_syscall_redirect_exit(void)
{
	DECLARE_COMPLETION_ONSTACK(drain_done);
	struct kasumi_drain_state drain;
	int i;
	int ret;

	if (READ_ONCE(kasumi_installed_dispatcher_slot) < 0)
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
	 *   3. sys_enter queues a task-work guard and pins THIS_MODULE before it
	 *      redirects a syscall.  The guard releases that reference through
	 *      RCU only after the task returns from the syscall or exits.  Module
	 *      exit therefore cannot begin while a dispatcher is in flight,
	 *      including an openat blocked on a FIFO or slow filesystem.
	 *
	 *   4. Now we can clear the hook table; no reader can observe it.
	 *
	 * Clearing hooks before the drain would let an in-flight dispatcher see
	 * incomplete state or return -ENOSYS unexpectedly.
	 */
	ret = kasumi_syscall_redirect_stop_new();
	if (WARN_ON_ONCE(ret))
		return;

	/* Defensive drain; task-work guards make this grace period normally empty. */
	drain.done = &drain_done;
	kasumi_call_srcu_ptr(&kasumi_redirect_srcu, &drain.head,
			     kasumi_redirect_drain_done);
	wait_for_completion(&drain_done);

	for (i = 0; i < __NR_syscalls; i++)
		WRITE_ONCE(hooks[i], NULL);

clear_state:
	WRITE_ONCE(kasumi_syscall_dispatcher_nr, -1);
	WRITE_ONCE(kasumi_installed_dispatcher_slot, -1);
	saved_ni_syscall = NULL;
	kasumi_syscall_table = NULL;
	pr_info("Kasumi: TSR dispatcher exited\n");
}
