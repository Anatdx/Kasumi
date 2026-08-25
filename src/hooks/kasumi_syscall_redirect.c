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
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs_struct.h>
#include <linux/kdev_t.h>
#include <linux/namei.h>
#include <linux/openat2.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/vmalloc.h>
#include <linux/xattr.h>
#include <asm/syscall.h>
#include <asm/stat.h>
#include <asm/unistd.h>
#include <asm/cacheflush.h>

#include "kasumi_base.h"
#include "kasumi_runtime.h"
#include "kasumi_virtual_file.h"
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
static atomic64_t kasumi_legacy_path_fallback_count = ATOMIC64_INIT(0);
static atomic64_t kasumi_virtual_access_handled_count = ATOMIC64_INIT(0);
static atomic64_t kasumi_virtual_xattr_handled_count = ATOMIC64_INIT(0);
static atomic64_t kasumi_virtual_mutation_handled_count = ATOMIC64_INIT(0);
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

static bool kasumi_ksu_shared_syscall(int nr)
{
#ifdef __NR_newfstatat
	if (nr == __NR_newfstatat)
		return true;
#endif
#ifdef __NR_faccessat
	if (nr == __NR_faccessat)
		return true;
#endif
#ifdef __NR_execve
	if (nr == __NR_execve)
		return true;
#endif
#ifdef __NR_execveat
	if (nr == __NR_execveat)
		return true;
#endif
	return false;
}

static KASUMI_NOCFI long kasumi_call_original(int nr,
					       const struct pt_regs *regs)
{
	kasumi_syscall_hook_fn fn;
	int next_nr = nr;

	if (!kasumi_syscall_table || nr < 0 || nr >= __NR_syscalls)
		return -ENOSYS;

	/* KernelSU owns these routes upstream. Kasumi runs after its
	 * sys_enter callback, projects the VIEW pathname, then invokes the whole
	 * KernelSU dispatcher so sucompat and the real syscall still execute once.
	 * This uses the upstream dispatcher ABI instead of private helper symbols.
	 */
	if ((READ_ONCE(kasumi_root_mask) & KASUMI_ROOT_KSU_RDR) &&
	    READ_ONCE(kasumi_ksu_dispatcher_nr) >= 0 &&
	    kasumi_ksu_shared_syscall(nr))
		next_nr = READ_ONCE(kasumi_ksu_dispatcher_nr);
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
	return kasumi_ksu_shared_syscall(nr);
}

u64 kasumi_syscall_redirect_fallback_count(void)
{
	return (u64)atomic64_read(&kasumi_legacy_path_fallback_count);
}

u64 kasumi_syscall_virtual_access_count(void)
{
	return (u64)atomic64_read(&kasumi_virtual_access_handled_count);
}

u64 kasumi_syscall_virtual_xattr_count(void)
{
	return (u64)atomic64_read(&kasumi_virtual_xattr_handled_count);
}

u64 kasumi_syscall_virtual_mutation_count(void)
{
	return (u64)atomic64_read(&kasumi_virtual_mutation_handled_count);
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

static void kasumi_set_syscall_arg(const struct pt_regs *regs,
				   unsigned int index, unsigned long value)
{
#if defined(__aarch64__)
	if (index < 6)
		((struct pt_regs *)regs)->regs[index] = value;
#elif defined(__x86_64__)
	switch (index) {
	case 0:
		((struct pt_regs *)regs)->di = value;
		break;
	case 1:
		((struct pt_regs *)regs)->si = value;
		break;
	case 2:
		((struct pt_regs *)regs)->dx = value;
		break;
	case 3:
		((struct pt_regs *)regs)->r10 = value;
		break;
	case 4:
		((struct pt_regs *)regs)->r8 = value;
		break;
	case 5:
		((struct pt_regs *)regs)->r9 = value;
		break;
	}
#endif
}

static char __user *kasumi_userspace_exec_buffer(const char *data, size_t len)
{
	char __user *buffer;
	unsigned long stack_pointer;

	if (!current->mm || !data || !len || len > KASUMI_PATH_BUF)
		return NULL;
	stack_pointer = current_user_stack_pointer();
	if (stack_pointer < 2 * PAGE_SIZE)
		return NULL;
	buffer = (char __user *)(stack_pointer - 2 * PAGE_SIZE);
	return copy_to_user(buffer, data, len) ? NULL : buffer;
}

static unsigned long kasumi_syscall_arg(const struct pt_regs *regs,
					unsigned int index)
{
#if defined(__aarch64__)
	return index < 6 ? regs->regs[index] : 0;
#elif defined(__x86_64__)
	switch (index) {
	case 0:
		return regs->di;
	case 1:
		return regs->si;
	case 2:
		return regs->dx;
	case 3:
		return regs->r10;
	case 4:
		return regs->r8;
	case 5:
		return regs->r9;
	}
#endif
	return 0;
}

static void kasumi_close_private_fd(unsigned int fd)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
	(void)__close_fd(current->files, fd);
#else
	(void)close_fd(fd);
#endif
}

static int kasumi_rule_get_visible_stat(const char *path,
					unsigned int lookup_flags,
					struct kstat *stat)
{
	struct kasumi_rule_source source = {};
	bool found;

	if (!path || !stat ||
	    !kasumi_rule_get_source_flags(path, lookup_flags, &source))
		return source.error;
	found = source.stat_valid &&
		(S_ISREG(source.source_mode) || S_ISDIR(source.source_mode) ||
		 S_ISCHR(source.source_mode) || S_ISBLK(source.source_mode) ||
		 S_ISFIFO(source.source_mode) || S_ISSOCK(source.source_mode) ||
		 S_ISLNK(source.source_mode));
	if (found) {
		*stat = source.stat;
		stat->ino = source.visible_ino;
		stat->dev = source.visible_dev;
	}
	kasumi_path_put(&source.path);
	return found ? 1 : -EOPNOTSUPP;
}

static int kasumi_copy_kstat_to_user_stat(const struct kstat *stat,
					  struct stat __user *statbuf)
{
	struct stat tmp;

	if (!statbuf)
		return -EFAULT;
	memset(&tmp, 0, sizeof(tmp));
	tmp.st_dev = new_encode_dev(stat->dev);
	tmp.st_ino = stat->ino;
	tmp.st_mode = stat->mode;
	tmp.st_nlink = stat->nlink;
	tmp.st_uid = from_kuid_munged(current_user_ns(), stat->uid);
	tmp.st_gid = from_kgid_munged(current_user_ns(), stat->gid);
	tmp.st_rdev = new_encode_dev(stat->rdev);
	tmp.st_size = stat->size;
	tmp.st_blksize = stat->blksize;
	tmp.st_blocks = stat->blocks;
	tmp.st_atime = stat->atime.tv_sec;
	tmp.st_atime_nsec = stat->atime.tv_nsec;
	tmp.st_mtime = stat->mtime.tv_sec;
	tmp.st_mtime_nsec = stat->mtime.tv_nsec;
	tmp.st_ctime = stat->ctime.tv_sec;
	tmp.st_ctime_nsec = stat->ctime.tv_nsec;
	return copy_to_user(statbuf, &tmp, sizeof(tmp)) ? -EFAULT : 0;
}

static int kasumi_copy_kstat_to_user_statx(const struct kstat *stat,
					   struct statx __user *statbuf)
{
	struct statx tmp;

	if (!statbuf)
		return -EFAULT;
	memset(&tmp, 0, sizeof(tmp));
	tmp.stx_mask = stat->result_mask & (STATX_BASIC_STATS | STATX_BTIME);
	tmp.stx_blksize = stat->blksize;
	tmp.stx_attributes = stat->attributes;
	tmp.stx_nlink = stat->nlink;
	tmp.stx_uid = from_kuid_munged(current_user_ns(), stat->uid);
	tmp.stx_gid = from_kgid_munged(current_user_ns(), stat->gid);
	tmp.stx_mode = stat->mode;
	tmp.stx_ino = stat->ino;
	tmp.stx_size = stat->size;
	tmp.stx_blocks = stat->blocks;
	tmp.stx_attributes_mask = stat->attributes_mask;
	tmp.stx_atime.tv_sec = stat->atime.tv_sec;
	tmp.stx_atime.tv_nsec = stat->atime.tv_nsec;
	tmp.stx_btime.tv_sec = stat->btime.tv_sec;
	tmp.stx_btime.tv_nsec = stat->btime.tv_nsec;
	tmp.stx_ctime.tv_sec = stat->ctime.tv_sec;
	tmp.stx_ctime.tv_nsec = stat->ctime.tv_nsec;
	tmp.stx_mtime.tv_sec = stat->mtime.tv_sec;
	tmp.stx_mtime.tv_nsec = stat->mtime.tv_nsec;
	tmp.stx_rdev_major = MAJOR(stat->rdev);
	tmp.stx_rdev_minor = MINOR(stat->rdev);
	tmp.stx_dev_major = MAJOR(stat->dev);
	tmp.stx_dev_minor = MINOR(stat->dev);
	return copy_to_user(statbuf, &tmp, sizeof(tmp)) ? -EFAULT : 0;
}

static int kasumi_user_tail_zero(const void __user *data, size_t size)
{
	const u8 __user *cursor = data;
	u8 buffer[32];
	size_t i;

	while (size) {
		size_t chunk = min(size, sizeof(buffer));

		if (copy_from_user(buffer, cursor, chunk))
			return -EFAULT;
		for (i = 0; i < chunk; i++) {
			if (buffer[i])
				return -E2BIG;
		}
		cursor += chunk;
		size -= chunk;
	}
	return 0;
}

static int kasumi_open_options(const struct pt_regs *regs, int nr,
			       int *flags, umode_t *mode, u64 *resolve)
{
#if defined(__aarch64__)
	unsigned long arg2 = regs->regs[2];
	unsigned long arg3 = regs->regs[3];
#elif defined(__x86_64__)
	unsigned long arg2 = regs->dx;
	unsigned long arg3 = regs->r10;
#else
	unsigned long arg2 = 0;
	unsigned long arg3 = 0;
#endif

#ifdef __NR_openat2
	if (nr == __NR_openat2) {
		struct open_how how = {};
		u64 normalized_flags;
		size_t copy_size;
		int ret;

		if (!arg2)
			return -EFAULT;
		if (arg3 < OPEN_HOW_SIZE_VER0)
			return -EINVAL;
		if (arg3 > PAGE_SIZE)
			return -E2BIG;
		copy_size = min_t(size_t, arg3, sizeof(how));
		if (copy_from_user(&how,
				   (const struct open_how __user *)arg2,
				   copy_size))
			return -EFAULT;
		if (arg3 > sizeof(how)) {
			ret = kasumi_user_tail_zero(
				(const u8 __user *)(uintptr_t)arg2 + sizeof(how),
				arg3 - sizeof(how));
			if (ret)
				return ret;
		}
		/* Mirror build_open_flags() validation before bypassing the
		 * ordinary VFS open path.  __FMODE_NONOTIFY is an internal bit
		 * which that helper strips before validating the remaining flags. */
		normalized_flags = how.flags & ~(u64)__FMODE_NONOTIFY;
		if (normalized_flags & ~(u64)VALID_OPEN_FLAGS)
			return -EINVAL;
		if (how.resolve & ~(u64)VALID_RESOLVE_FLAGS)
			return -EINVAL;
		if ((how.resolve & RESOLVE_BENEATH) &&
		    (how.resolve & RESOLVE_IN_ROOT))
			return -EINVAL;
		if (how.mode & ~(u64)S_IALLUGO)
			return -EINVAL;
		if (!(normalized_flags & (O_CREAT | __O_TMPFILE)) && how.mode)
			return -EINVAL;
		if ((how.resolve & RESOLVE_CACHED) &&
		    (normalized_flags & (O_TRUNC | O_CREAT | __O_TMPFILE)))
			return -EAGAIN;
		if ((normalized_flags & (O_CREAT | O_EXCL)) ==
		    (O_CREAT | O_EXCL))
			normalized_flags |= O_NOFOLLOW;
		*flags = (int)normalized_flags;
		*mode = (umode_t)how.mode;
		*resolve = how.resolve;
		return 0;
	}
#endif
	/* openat() deliberately masks unknown flags and mode bits. */
	*flags = (int)arg2 & VALID_OPEN_FLAGS;
	if (force_o_largefile())
		*flags |= O_LARGEFILE;
	if (*flags & O_PATH)
		*flags &= O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC;
	*mode = (umode_t)arg3 & S_IALLUGO;
	*resolve = 0;
	return 0;
}

static unsigned int kasumi_open_lookup_flags(int flags, u64 resolve)
{
	unsigned int lookup_flags = 0;

	if (flags & O_DIRECTORY)
		lookup_flags |= LOOKUP_DIRECTORY;
	if (!(flags & O_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;
	if (resolve & RESOLVE_NO_XDEV)
		lookup_flags |= LOOKUP_NO_XDEV;
	if (resolve & RESOLVE_NO_MAGICLINKS)
		lookup_flags |= LOOKUP_NO_MAGICLINKS;
	if (resolve & RESOLVE_NO_SYMLINKS)
		lookup_flags |= LOOKUP_NO_SYMLINKS;
	if (resolve & RESOLVE_BENEATH)
		lookup_flags |= LOOKUP_BENEATH;
	if (resolve & RESOLVE_IN_ROOT)
		lookup_flags |= LOOKUP_IN_ROOT;
	if (resolve & RESOLVE_CACHED)
		lookup_flags |= LOOKUP_CACHED;
	return lookup_flags;
}

static KASUMI_NOCFI long kasumi_copy_user_path_at_mode(
	int dirfd, const char __user *u, char *path, size_t size, bool in_root)
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
	if ((path[0] == '/' && !in_root) || !kasumi_d_path)
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
		if (kasumi_virtual_file_lookup_path(&pwd, page, PAGE_SIZE))
			dir = page;
		else if (kasumi_rule_get_visible_path(&pwd, page, PAGE_SIZE))
			dir = page;
		else
			dir = kasumi_d_path(&pwd, page, PAGE_SIZE);
		if (!IS_ERR_OR_NULL(dir) && dir[0] == '/') {
			char rel[KSM_MAX_LEN_PATHNAME];
			const char *relative = path;

			if (in_root)
				while (*relative == '/')
					relative++;
			strscpy(rel, relative, sizeof(rel));
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
	file = fget_raw(dirfd);
	if (!file)
		goto out_free;
	if (kasumi_virtual_file_get_visible_fd(
			(unsigned int)dirfd, page, PAGE_SIZE))
		dir = page;
	else if (kasumi_rule_get_visible_path(&file->f_path, page, PAGE_SIZE))
		dir = page;
	else
		dir = kasumi_d_path(&file->f_path, page, PAGE_SIZE);
	if (!IS_ERR_OR_NULL(dir) && dir[0] == '/') {
		char rel[KSM_MAX_LEN_PATHNAME];
		const char *relative = path;

		if (in_root)
			while (*relative == '/')
				relative++;
		strscpy(rel, relative, sizeof(rel));
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

static long kasumi_copy_user_path_at(int dirfd, const char __user *u,
				     char *path, size_t size)
{
	return kasumi_copy_user_path_at_mode(dirfd, u, path, size, false);
}

static bool kasumi_openat2_in_root(const struct pt_regs *regs, int nr)
{
#ifdef __NR_openat2
	struct open_how how = {};
	const void __user *how_user;
	size_t size;

	if (nr != __NR_openat2)
		return false;
	how_user = (const void __user *)(uintptr_t)kasumi_syscall_arg(regs, 2);
	size = (size_t)kasumi_syscall_arg(regs, 3);
	if (!how_user || size < OPEN_HOW_SIZE_VER0 ||
	    copy_from_user(&how, how_user, sizeof(how)))
		return false;
	return how.resolve & RESOLVE_IN_ROOT;
#else
	return false;
#endif
}

static int kasumi_virtual_parent_fd(const char *path, char *leaf,
				    size_t leaf_size, bool *handled);

static long kasumi_virtual_create_open(const struct pt_regs *regs, int nr,
				       const char *visible_path, int flags,
				       bool *handled)
{
	char leaf[KASUMI_PATH_BUF];
	char __user *leaf_user;
	struct pt_regs redirected;
	bool parent_handled;
	bool reopened;
	long created_fd;
	long ret;
	int parent_fd;

	*handled = false;
	parent_fd = kasumi_virtual_parent_fd(visible_path, leaf, sizeof(leaf),
					     &parent_handled);
	if (!parent_handled)
		return parent_fd < 0 ? parent_fd : 0;
	*handled = true;
	if (parent_fd < 0)
		return parent_fd;
	leaf_user = kasumi_userspace_stack_buffer(leaf, strlen(leaf) + 1);
	if (!leaf_user) {
		kasumi_close_private_fd((unsigned int)parent_fd);
		return -EFAULT;
	}

	redirected = *regs;
	kasumi_set_syscall_arg(&redirected, 0, (unsigned long)parent_fd);
	kasumi_set_syscall_arg(&redirected, 1, (unsigned long)leaf_user);
	redirected.syscallno = nr;
	PT_REGS_ORIG_SYSCALL(&redirected) = nr;
	atomic64_inc(&kasumi_virtual_mutation_handled_count);
	created_fd = kasumi_call_original(nr, &redirected);
	kasumi_close_private_fd((unsigned int)parent_fd);
	if (created_fd < 0)
		return created_fd;
	ret = kasumi_virtual_reopen_fd(visible_path, (unsigned int)created_fd,
					    flags, &reopened);
	kasumi_close_private_fd((unsigned int)created_fd);
	return reopened ? ret : -EOPNOTSUPP;
}

static long do_openat(const struct pt_regs *regs, int nr)
{
	char path[KSM_MAX_LEN_PATHNAME];
	const char __user *u = (void __user *)(uintptr_t)regs->regs[1];
	char first;
	char *t;
	char *target_path = NULL;
	long ret;
	int dirfd = (int)regs->regs[0];
	long tgid = (long)task_tgid_vnr(current);
	bool hidden;

	if (atomic_long_read(&kasumi_ioctl_tgid) == tgid ||
	    atomic_long_read(&kasumi_xattr_source_tgid) == tgid)
		return kasumi_call_original(nr, regs);
	if (kasumi_copy_user_path_at_mode(
			dirfd, u, path, sizeof(path),
			kasumi_openat2_in_root(regs, nr)) <= 0)
		return kasumi_call_original(nr, regs);

	hidden = unlikely(kasumi_should_hide(path));
	if (hidden) {
		char __user *n = kasumi_userspace_stack_buffer(
			KASUMI_HIDE_PATH, sizeof(KASUMI_HIDE_PATH));
		if (n)
			kasumi_set_path_arg1(regs, (unsigned long)n);
	}
	if (path[0] == '/' && atomic_read(&kasumi_rule_count) > 0 &&
	    !hidden) {
		bool handled = false;
		int flags;
		int options_ret;
		u64 resolve;
		umode_t mode;

		options_ret = kasumi_open_options(regs, nr, &flags, &mode,
						  &resolve);
		if (!options_ret) {
			unsigned int lookup_flags =
				kasumi_open_lookup_flags(flags, resolve);

			if ((resolve & RESOLVE_BENEATH) &&
			    get_user(first, u) == 0 && first == '/')
				return -EXDEV;
			if (flags & O_CREAT) {
				ret = kasumi_virtual_create_open(regs, nr, path,
							 flags, &handled);
				if (handled || ret < 0)
					return ret;
			}
			ret = kasumi_virtual_open_entry_fd_flags(
				path, flags, mode, lookup_flags, &handled);
			if (handled)
				return ret;
			if (kasumi_rule_path_is_virtual(path))
				return -ENOENT;
		} else if (kasumi_rule_path_is_virtual(path))
			return options_ret;
		t = kasumi_resolve_target_slow(path);
		if (t)
			target_path = t;
	}
	if (target_path && !hidden) {
		size_t l = strlen(target_path) + 1;
		char __user *n = NULL;

		if (l <= KASUMI_PATH_BUF)
			n = kasumi_userspace_stack_buffer(target_path, l);
		if (n) {
			kasumi_set_path_arg1(regs, (unsigned long)n);
			atomic64_inc(&kasumi_legacy_path_fallback_count);
			kasumi_log("legacy path fallback: %s -> %s\n", path,
				   target_path);
		}
	}

	ret = kasumi_call_original(nr, regs);
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
	struct pt_regs redirected;
	bool handled;
	long ret;
	int fd;

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
		fd = kasumi_virtual_open_entry_fd(
			path, O_PATH | O_CLOEXEC, 0, &handled);
		if (handled) {
			if (fd < 0)
				return fd;
#ifdef __NR_fstatfs
			redirected = *regs;
			kasumi_set_syscall_arg(&redirected, 0,
					       (unsigned long)fd);
			redirected.syscallno = __NR_fstatfs;
			PT_REGS_ORIG_SYSCALL(&redirected) = __NR_fstatfs;
			ret = kasumi_call_original(__NR_fstatfs, &redirected);
			kasumi_close_private_fd((unsigned int)fd);
			return ret;
#else
			kasumi_close_private_fd((unsigned int)fd);
			return -EOPNOTSUPP;
#endif
		}
		if (kasumi_rule_path_is_virtual(path))
			return -ENOENT;
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
	struct statx __user *statbuf;
	struct kstat stat;
	long path_len;
	unsigned int flags;
	unsigned int mask;
	int visible;
	int dirfd;

#if defined(__aarch64__)
	dirfd = (int)regs->regs[0];
	filename_user = (const char __user *)(uintptr_t)regs->regs[1];
	flags = (unsigned int)regs->regs[2];
	mask = (unsigned int)regs->regs[3];
	statbuf = (struct statx __user *)(uintptr_t)regs->regs[4];
#else
	dirfd = (int)regs->di;
	filename_user = (const char __user *)(uintptr_t)regs->si;
	flags = (unsigned int)regs->dx;
	mask = (unsigned int)regs->r10;
	statbuf = (struct statx __user *)(uintptr_t)regs->r8;
#endif
	if (mask & STATX__RESERVED)
		return -EINVAL;
	if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH |
		      AT_STATX_SYNC_TYPE))
		return -EINVAL;
	if ((flags & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE)
		return -EINVAL;

	/* statx(fd, NULL/"", AT_EMPTY_PATH, ...) is the fd form of statx.
	 * Answer virtual descriptors from their rule snapshot so an adopted
	 * backing path never leaks through fd metadata. */
	if (flags & AT_EMPTY_PATH) {
		char first = '\0';

		if (!filename_user ||
		    (get_user(first, filename_user) == 0 && first == '\0')) {
			if (kasumi_virtual_file_getattr_fd(dirfd, &stat))
				return kasumi_copy_kstat_to_user_statx(&stat,
								      statbuf);
		}
	}
	if (!filename_user)
		return kasumi_call_original(__NR_statx, regs);

	path_len = kasumi_copy_user_path_at(dirfd, filename_user, path, sizeof(path));
	if (path_len <= 0 || path_len >= sizeof(path))
		return kasumi_call_original(__NR_statx, regs);
	if (path[0] != '/')
		return kasumi_call_original(__NR_statx, regs);
	if (kasumi_should_hide(path))
		return -ENOENT;
	visible = kasumi_rule_get_visible_stat(
		path, (flags & AT_SYMLINK_NOFOLLOW) ? 0 : LOOKUP_FOLLOW,
		&stat);
	if (visible > 0)
		return kasumi_copy_kstat_to_user_statx(&stat, statbuf);
	if (visible < 0)
		return visible;
	if (kasumi_rule_path_is_virtual(path))
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
	char path[KSM_MAX_LEN_PATHNAME];
	const char __user *filename_user;
	struct stat __user *statbuf;
	struct kstat stat;
	unsigned int flags;
	int visible;
	int dirfd;

#if defined(__aarch64__)
	dirfd = (int)regs->regs[0];
	filename_user = (const char __user *)(uintptr_t)regs->regs[1];
	statbuf = (struct stat __user *)(uintptr_t)regs->regs[2];
	flags = (unsigned int)regs->regs[3];
#else
	dirfd = (int)regs->di;
	filename_user = (const char __user *)(uintptr_t)regs->si;
	statbuf = (struct stat __user *)(uintptr_t)regs->dx;
	flags = (unsigned int)regs->r10;
#endif
	if (flags & AT_EMPTY_PATH) {
		char first = '\0';

		if (!filename_user ||
		    (get_user(first, filename_user) == 0 && first == '\0')) {
			if (kasumi_virtual_file_getattr_fd(dirfd, &stat))
				return kasumi_copy_kstat_to_user_stat(&stat,
								     statbuf);
		}
	}
	if (!filename_user ||
	    kasumi_copy_user_path_at(dirfd, filename_user, path,
				     sizeof(path)) <= 0 || path[0] != '/')
		return do_path1_hide(regs, __NR_newfstatat);
	if ((READ_ONCE(kasumi_root_mask) & KASUMI_ROOT_KSU_RDR) &&
	    !strcmp(path, "/system/bin/su"))
		return kasumi_call_original(__NR_newfstatat, regs);
	if (kasumi_should_hide(path))
		return -ENOENT;
	if (!(flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |
			AT_EMPTY_PATH))) {
		visible = kasumi_rule_get_visible_stat(
			path, (flags & AT_SYMLINK_NOFOLLOW) ? 0 : LOOKUP_FOLLOW,
			&stat);
		if (visible > 0)
			return kasumi_copy_kstat_to_user_stat(&stat, statbuf);
		if (visible < 0)
			return visible;
		if (kasumi_rule_path_is_virtual(path))
			return -ENOENT;
	}
	return do_path1_hide(regs, __NR_newfstatat);
}
#endif

#ifdef __NR_fstat
static long h_fstat(const struct pt_regs *regs)
{
	struct stat __user *statbuf;
	struct kstat stat;
	unsigned int fd;

#if defined(__aarch64__)
	fd = (unsigned int)regs->regs[0];
	statbuf = (struct stat __user *)(uintptr_t)regs->regs[1];
#else
	fd = (unsigned int)regs->di;
	statbuf = (struct stat __user *)(uintptr_t)regs->si;
#endif
	if (kasumi_virtual_file_getattr_fd(fd, &stat))
		return kasumi_copy_kstat_to_user_stat(&stat, statbuf);
	return kasumi_call_original(__NR_fstat, regs);
}
#endif

#ifdef __NR_faccessat
static long do_faccessat(const struct pt_regs *regs, int nr, bool has_flags)
{
	const char __user *filename_user;
	char path[KSM_MAX_LEN_PATHNAME];
	struct kstat stat;
	unsigned int flags;
	int visible;
	int dirfd;
	int mode;

#if defined(__aarch64__)
	dirfd = (int)regs->regs[0];
	filename_user = (const char __user *)(uintptr_t)regs->regs[1];
	mode = (int)regs->regs[2];
	flags = has_flags ? (unsigned int)regs->regs[3] : 0;
#else
	dirfd = (int)regs->di;
	filename_user = (const char __user *)(uintptr_t)regs->si;
	mode = (int)regs->dx;
	flags = has_flags ? (unsigned int)regs->r10 : 0;
#endif
	if (mode & ~S_IRWXO)
		return -EINVAL;
	if (flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
		return -EINVAL;
	if (flags & AT_EMPTY_PATH) {
		char first = '\0';

		if (!filename_user ||
		    (get_user(first, filename_user) == 0 && first == '\0')) {
			if (kasumi_virtual_file_getattr_fd(dirfd, &stat)) {
				atomic64_inc(&kasumi_virtual_access_handled_count);
				return kasumi_visible_access(
					&stat, mode, flags & AT_EACCESS);
			}
		}
	}
	if (!filename_user ||
	    kasumi_copy_user_path_at(dirfd, filename_user, path,
				     sizeof(path)) <= 0 || path[0] != '/')
		return do_path1_hide(regs, nr);
	if ((READ_ONCE(kasumi_root_mask) & KASUMI_ROOT_KSU_RDR) &&
	    !strcmp(path, "/system/bin/su"))
		return kasumi_call_original(nr, regs);
	if (kasumi_should_hide(path))
		return -ENOENT;
	visible = kasumi_rule_get_visible_stat(
		path, (flags & AT_SYMLINK_NOFOLLOW) ? 0 : LOOKUP_FOLLOW,
		&stat);
	if (visible > 0) {
		atomic64_inc(&kasumi_virtual_access_handled_count);
		return kasumi_visible_access(&stat, mode, flags & AT_EACCESS);
	}
	if (visible < 0)
		return visible;
	if (kasumi_rule_path_is_virtual(path))
		return -ENOENT;
	return do_path1_hide(regs, nr);
}

static long h_faccessat(const struct pt_regs *regs)
{
	return do_faccessat(regs, __NR_faccessat, false);
}
#endif

#ifdef __NR_faccessat2
static long h_faccessat2(const struct pt_regs *regs)
{
	return do_faccessat(regs, __NR_faccessat2, true);
}
#endif

#ifdef __NR_access
static long h_access(const struct pt_regs *regs)
{
	const char __user *filename_user;
	char path[KSM_MAX_LEN_PATHNAME];
	struct kstat stat;
	int visible;
	int mode;

#if defined(__aarch64__)
	filename_user = (const char __user *)(uintptr_t)regs->regs[0];
	mode = (int)regs->regs[1];
#else
	filename_user = (const char __user *)(uintptr_t)regs->di;
	mode = (int)regs->si;
#endif
	if (mode & ~S_IRWXO)
		return -EINVAL;
	if (!filename_user ||
	    kasumi_copy_user_path_at(AT_FDCWD, filename_user, path,
				     sizeof(path)) <= 0 || path[0] != '/')
		return do_path0_hide(regs, __NR_access);
	if (kasumi_should_hide(path))
		return -ENOENT;
	visible = kasumi_rule_get_visible_stat(path, LOOKUP_FOLLOW, &stat);
	if (visible > 0) {
		atomic64_inc(&kasumi_virtual_access_handled_count);
		return kasumi_visible_access(&stat, mode, false);
	}
	if (visible < 0)
		return visible;
	if (kasumi_rule_path_is_virtual(path))
		return -ENOENT;
	return do_path0_hide(regs, __NR_access);
}
#endif

static int kasumi_virtual_parent_fd(const char *path, char *leaf,
				    size_t leaf_size, bool *handled)
{
	char *normalized;
	char *parent_path;
	char *component;
	char *slash;
	size_t component_len;
	size_t path_len;
	size_t trimmed_len;
	size_t trailing_len;
	bool leaf_fits;
	bool opened = false;
	int fd = 0;

	if (!path || path[0] != '/' || !leaf || !leaf_size || !handled)
		return -EINVAL;
	*handled = false;
	path_len = strlen(path);
	trimmed_len = path_len;
	while (trimmed_len > 1 && path[trimmed_len - 1] == '/')
		trimmed_len--;
	trailing_len = path_len - trimmed_len;
	normalized = kstrndup(path, trimmed_len, GFP_KERNEL);
	if (!normalized)
		return -ENOMEM;
	slash = strrchr(normalized, '/');
	if (!slash || !slash[1])
		goto exact_path;
	component = slash + 1;
	component_len = strlen(component);
	leaf_fits = component_len + trailing_len + 1 <= leaf_size;
	if (slash == normalized)
		parent_path = kstrdup("/", GFP_KERNEL);
	else
		parent_path = kstrndup(normalized,
				       (size_t)(slash - normalized), GFP_KERNEL);
	if (!parent_path) {
		kfree(normalized);
		return -ENOMEM;
	}
	if (leaf_fits) {
		memcpy(leaf, component, component_len);
		memcpy(leaf + component_len, path + trimmed_len,
		       trailing_len);
		leaf[component_len + trailing_len] = '\0';
	}
	fd = kasumi_virtual_open_entry_fd(parent_path,
					  O_PATH | O_DIRECTORY | O_CLOEXEC,
					  0, &opened);
	kfree(parent_path);
	if (opened) {
		*handled = true;
		if (!leaf_fits) {
			if (fd >= 0)
				kasumi_close_private_fd((unsigned int)fd);
			fd = -ENAMETOOLONG;
		}
		kfree(normalized);
		return fd;
	}

exact_path:
	if (kasumi_virtual_entry_matches(path) ||
	    kasumi_virtual_entry_matches(normalized)) {
		*handled = true;
		fd = -EBUSY;
	} else if (kasumi_rule_path_is_virtual(normalized)) {
		*handled = true;
		fd = -ENOENT;
	}
	kfree(normalized);
	return fd;
}

static long kasumi_parent_path_call(const struct pt_regs *regs, int nr,
				    unsigned int dirfd_arg,
				    unsigned int pathname_arg,
				    bool mutation)
{
	const char __user *pathname_user =
		(const char __user *)(uintptr_t)
			kasumi_syscall_arg(regs, pathname_arg);
	char path[KSM_MAX_LEN_PATHNAME];
	char leaf[KASUMI_PATH_BUF];
	char __user *leaf_user;
	struct pt_regs redirected;
	bool handled;
	long ret;
	int dirfd = (int)kasumi_syscall_arg(regs, dirfd_arg);
	int parent_fd;

	if (!pathname_user ||
	    kasumi_copy_user_path_at(dirfd, pathname_user, path,
				     sizeof(path)) <= 0 || path[0] != '/')
		return kasumi_call_original(nr, regs);
	if (kasumi_should_hide(path))
		return -ENOENT;
	parent_fd = kasumi_virtual_parent_fd(path, leaf, sizeof(leaf),
					     &handled);
	if (!handled && parent_fd < 0)
		return parent_fd;
	if (!handled)
		return kasumi_call_original(nr, regs);
	if (parent_fd < 0)
		return parent_fd;
	leaf_user = kasumi_userspace_stack_buffer(leaf, strlen(leaf) + 1);
	if (!leaf_user) {
		kasumi_close_private_fd((unsigned int)parent_fd);
		return -EFAULT;
	}

	redirected = *regs;
	kasumi_set_syscall_arg(&redirected, dirfd_arg,
			       (unsigned long)parent_fd);
	kasumi_set_syscall_arg(&redirected, pathname_arg,
			       (unsigned long)leaf_user);
	redirected.syscallno = nr;
	PT_REGS_ORIG_SYSCALL(&redirected) = nr;
	if (mutation)
		atomic64_inc(&kasumi_virtual_mutation_handled_count);
	ret = kasumi_call_original(nr, &redirected);
	kasumi_close_private_fd((unsigned int)parent_fd);
	return ret;
}

#ifdef __NR_mkdirat
static long h_mkdirat(const struct pt_regs *regs)
{
	return kasumi_parent_path_call(regs, __NR_mkdirat, 0, 1, true);
}
#endif

#ifdef __NR_unlinkat
static long h_unlinkat(const struct pt_regs *regs)
{
	return kasumi_parent_path_call(regs, __NR_unlinkat, 0, 1, true);
}
#endif

#ifdef __NR_mknodat
static long h_mknodat(const struct pt_regs *regs)
{
	return kasumi_parent_path_call(regs, __NR_mknodat, 0, 1, true);
}
#endif

#ifdef __NR_fchmodat
static long h_fchmodat(const struct pt_regs *regs)
{
	return kasumi_parent_path_call(regs, __NR_fchmodat, 0, 1, true);
}
#endif

#ifdef __NR_fchmodat2
static long h_fchmodat2(const struct pt_regs *regs)
{
	return kasumi_parent_path_call(regs, __NR_fchmodat2, 0, 1, true);
}
#endif

#ifdef __NR_fchownat
static long h_fchownat(const struct pt_regs *regs)
{
	return kasumi_parent_path_call(regs, __NR_fchownat, 0, 1, true);
}
#endif

#ifdef __NR_utimensat
static long h_utimensat(const struct pt_regs *regs)
{
	return kasumi_parent_path_call(regs, __NR_utimensat, 0, 1, true);
}
#endif

#ifdef __NR_readlinkat
static long kasumi_copy_virtual_readlink(char __user *buffer_user,
					 size_t buffer_size,
					 const char *target)
{
	size_t length;

	if (!buffer_size)
		return -EINVAL;
	length = min(strlen(target), buffer_size);
	if (copy_to_user(buffer_user, target, length))
		return -EFAULT;
	return (long)length;
}

static bool kasumi_proc_current_fd(const char *path, unsigned int *fd)
{
	static const char self_prefix[] = "/proc/self/fd/";
	static const char thread_prefix[] = "/proc/thread-self/fd/";
	char numeric_prefix[32];
	const char *cursor = NULL;
	unsigned int value = 0;
	int length;

	if (!path || !fd)
		return false;
	if (!strncmp(path, self_prefix, sizeof(self_prefix) - 1)) {
		cursor = path + sizeof(self_prefix) - 1;
	} else if (!strncmp(path, thread_prefix, sizeof(thread_prefix) - 1)) {
		cursor = path + sizeof(thread_prefix) - 1;
	} else {
		length = scnprintf(numeric_prefix, sizeof(numeric_prefix),
				   "/proc/%d/fd/", task_pid_vnr(current));
		if (length > 0 && !strncmp(path, numeric_prefix, length)) {
			cursor = path + length;
		} else if (task_tgid_vnr(current) != task_pid_vnr(current)) {
			length = scnprintf(numeric_prefix,
					   sizeof(numeric_prefix),
					   "/proc/%d/fd/",
					   task_tgid_vnr(current));
			if (length > 0 && !strncmp(path, numeric_prefix, length))
				cursor = path + length;
		}
	}
	if (!cursor || !*cursor)
		return false;
	while (*cursor) {
		unsigned int digit;

		if (*cursor < '0' || *cursor > '9')
			return false;
		digit = (unsigned int)(*cursor++ - '0');
		if (value > (UINT_MAX - digit) / 10)
			return false;
		value = value * 10 + digit;
	}
	*fd = value;
	return true;
}

static bool kasumi_proc_current_exe(const char *path)
{
	char numeric_path[32];
	int length;

	if (!path)
		return false;
	if (!strcmp(path, "/proc/self/exe") ||
	    !strcmp(path, "/proc/thread-self/exe"))
		return true;
	length = scnprintf(numeric_path, sizeof(numeric_path),
			   "/proc/%d/exe", task_pid_vnr(current));
	if (length > 0 && !strcmp(path, numeric_path))
		return true;
	if (task_tgid_vnr(current) == task_pid_vnr(current))
		return false;
	scnprintf(numeric_path, sizeof(numeric_path), "/proc/%d/exe",
		  task_tgid_vnr(current));
	return !strcmp(path, numeric_path);
}

static long h_readlinkat(const struct pt_regs *regs)
{
	const char __user *pathname_user =
		(const char __user *)(uintptr_t)kasumi_syscall_arg(regs, 1);
	char __user *buffer_user =
		(char __user *)(uintptr_t)kasumi_syscall_arg(regs, 2);
	size_t buffer_size = (size_t)kasumi_syscall_arg(regs, 3);
	struct kasumi_rule_source source = {};
	char path[KSM_MAX_LEN_PATHNAME];
	char __user *empty_user;
	struct pt_regs redirected;
	unsigned int proc_fd;
	bool handled;
	long ret;
	int dirfd = (int)kasumi_syscall_arg(regs, 0);
	int fd;

	if (!pathname_user ||
	    kasumi_copy_user_path_at(dirfd, pathname_user, path,
				     sizeof(path)) <= 0 || path[0] != '/')
		return kasumi_call_original(__NR_readlinkat, regs);
	if (kasumi_should_hide(path))
		return -ENOENT;
	if (kasumi_proc_current_exe(path) &&
	    kasumi_virtual_exec_get_current(path, sizeof(path)))
		return kasumi_copy_virtual_readlink(buffer_user, buffer_size,
						    path);
	if (kasumi_proc_current_fd(path, &proc_fd) &&
	    kasumi_virtual_file_get_visible_fd(proc_fd, path, sizeof(path)))
		return kasumi_copy_virtual_readlink(buffer_user, buffer_size,
						    path);
	if (!kasumi_rule_get_source_flags(path, 0, &source)) {
		if (source.error)
			return source.error;
		return kasumi_parent_path_call(regs, __NR_readlinkat, 0, 1,
					       false);
	}
	if (!S_ISLNK(source.source_mode)) {
		kasumi_path_put(&source.path);
		return -EINVAL;
	}
	kasumi_path_put(&source.path);
	fd = kasumi_virtual_open_entry_fd(path,
					  O_PATH | O_NOFOLLOW | O_CLOEXEC,
					  0, &handled);
	if (!handled)
		return -ENOENT;
	if (fd < 0)
		return fd;
	empty_user = kasumi_userspace_stack_buffer("", 1);
	if (!empty_user) {
		kasumi_close_private_fd((unsigned int)fd);
		return -EFAULT;
	}
	redirected = *regs;
	kasumi_set_syscall_arg(&redirected, 0, (unsigned long)fd);
	kasumi_set_syscall_arg(&redirected, 1, (unsigned long)empty_user);
	redirected.syscallno = __NR_readlinkat;
	PT_REGS_ORIG_SYSCALL(&redirected) = __NR_readlinkat;
	ret = kasumi_call_original(__NR_readlinkat, &redirected);
	kasumi_close_private_fd((unsigned int)fd);
	return ret;
}
#endif

#ifdef __NR_symlinkat
static long h_symlinkat(const struct pt_regs *regs)
{
	const char __user *target_user =
		(const char __user *)(uintptr_t)kasumi_syscall_arg(regs, 0);
	const char __user *link_user =
		(const char __user *)(uintptr_t)kasumi_syscall_arg(regs, 2);
	char target[KSM_MAX_LEN_PATHNAME];
	char link_path[KSM_MAX_LEN_PATHNAME];
	int dirfd = (int)kasumi_syscall_arg(regs, 1);
	long target_len;

	if (!link_user ||
	    kasumi_copy_user_path_at(dirfd, link_user, link_path,
				     sizeof(link_path)) <= 0 ||
	    link_path[0] != '/' || !kasumi_rule_path_is_virtual(link_path))
		return kasumi_call_original(__NR_symlinkat, regs);
	if (!target_user)
		return -EFAULT;
	target_len = strncpy_from_user(target, target_user, sizeof(target));
	if (target_len < 0)
		return target_len;
	if (!target_len)
		return -ENOENT;
	if ((size_t)target_len >= sizeof(target))
		return -ENAMETOOLONG;
	return kasumi_parent_path_call(regs, __NR_symlinkat, 1, 2, true);
}
#endif

#if defined(__NR_truncate) && defined(__NR_ftruncate)
static long h_truncate(const struct pt_regs *regs)
{
	const char __user *pathname_user =
		(const char __user *)(uintptr_t)kasumi_syscall_arg(regs, 0);
	char path[KSM_MAX_LEN_PATHNAME];
	struct pt_regs redirected;
	bool handled;
	long ret;
	int fd;

	if (!pathname_user ||
	    kasumi_copy_user_path_at(AT_FDCWD, pathname_user, path,
				     sizeof(path)) <= 0 || path[0] != '/')
		return kasumi_call_original(__NR_truncate, regs);
	if (kasumi_should_hide(path))
		return -ENOENT;
	fd = kasumi_virtual_open_entry_fd(path, O_WRONLY | O_CLOEXEC, 0,
					  &handled);
	if (!handled)
		return kasumi_rule_path_is_virtual(path) ? -ENOENT :
			kasumi_call_original(__NR_truncate, regs);
	if (fd < 0)
		return fd;
	redirected = *regs;
	kasumi_set_syscall_arg(&redirected, 0, (unsigned long)fd);
	redirected.syscallno = __NR_ftruncate;
	PT_REGS_ORIG_SYSCALL(&redirected) = __NR_ftruncate;
	atomic64_inc(&kasumi_virtual_mutation_handled_count);
	ret = kasumi_call_original(__NR_ftruncate, &redirected);
	kasumi_close_private_fd((unsigned int)fd);
	return ret;
}
#endif

#if defined(__NR_renameat) || defined(__NR_renameat2) || defined(__NR_linkat)
struct kasumi_two_path_buffers {
	char old_path[KSM_MAX_LEN_PATHNAME];
	char new_path[KSM_MAX_LEN_PATHNAME];
	char names[KASUMI_PATH_BUF * 2];
	char old_leaf[KASUMI_PATH_BUF];
	char new_leaf[KASUMI_PATH_BUF];
};

static long kasumi_two_parent_paths(const struct pt_regs *regs, int nr)
{
	const char __user *old_user =
		(const char __user *)(uintptr_t)kasumi_syscall_arg(regs, 1);
	const char __user *new_user =
		(const char __user *)(uintptr_t)kasumi_syscall_arg(regs, 3);
	struct kasumi_two_path_buffers *buffers;
	char __user *names_user;
	struct pt_regs redirected;
	size_t old_len;
	size_t new_len;
	bool old_handled;
	bool new_handled;
	long ret;
	int old_dirfd = (int)kasumi_syscall_arg(regs, 0);
	int new_dirfd = (int)kasumi_syscall_arg(regs, 2);
	int old_parent;
	int new_parent;

	buffers = kzalloc(sizeof(*buffers), GFP_KERNEL);
	if (!buffers)
		return -ENOMEM;
	if (!old_user || !new_user ||
	    kasumi_copy_user_path_at(old_dirfd, old_user, buffers->old_path,
				     sizeof(buffers->old_path)) <= 0 ||
	    kasumi_copy_user_path_at(new_dirfd, new_user, buffers->new_path,
				     sizeof(buffers->new_path)) <= 0 ||
	    buffers->old_path[0] != '/' || buffers->new_path[0] != '/') {
		kfree(buffers);
		return kasumi_call_original(nr, regs);
	}
	if (kasumi_should_hide(buffers->old_path) ||
	    kasumi_should_hide(buffers->new_path)) {
		kfree(buffers);
		return -ENOENT;
	}
	old_parent = kasumi_virtual_parent_fd(buffers->old_path,
					      buffers->old_leaf,
					      sizeof(buffers->old_leaf),
					      &old_handled);
	new_parent = kasumi_virtual_parent_fd(buffers->new_path,
					      buffers->new_leaf,
					      sizeof(buffers->new_leaf),
					      &new_handled);
	if (!old_handled && old_parent < 0) {
		kfree(buffers);
		return old_parent;
	}
	if (!new_handled && new_parent < 0) {
		if (old_handled && old_parent >= 0)
			kasumi_close_private_fd((unsigned int)old_parent);
		kfree(buffers);
		return new_parent;
	}
	if (!old_handled && !new_handled) {
		kfree(buffers);
		return kasumi_call_original(nr, regs);
	}
	if (old_parent < 0 || new_parent < 0) {
		ret = old_parent < 0 ? old_parent : new_parent;
		goto out_close;
	}
	if (!old_handled || !new_handled) {
		ret = -EXDEV;
		goto out_close;
	}
	old_len = strlen(buffers->old_leaf) + 1;
	new_len = strlen(buffers->new_leaf) + 1;
	memcpy(buffers->names, buffers->old_leaf, old_len);
	memcpy(buffers->names + old_len, buffers->new_leaf, new_len);
	names_user = kasumi_userspace_stack_buffer(buffers->names,
						  old_len + new_len);
	if (!names_user) {
		ret = -EFAULT;
		goto out_close;
	}

	redirected = *regs;
	kasumi_set_syscall_arg(&redirected, 0, (unsigned long)old_parent);
	kasumi_set_syscall_arg(&redirected, 1, (unsigned long)names_user);
	kasumi_set_syscall_arg(&redirected, 2, (unsigned long)new_parent);
	kasumi_set_syscall_arg(&redirected, 3,
			       (unsigned long)(names_user + old_len));
	redirected.syscallno = nr;
	PT_REGS_ORIG_SYSCALL(&redirected) = nr;
	atomic64_inc(&kasumi_virtual_mutation_handled_count);
	ret = kasumi_call_original(nr, &redirected);

out_close:
	if (old_handled && old_parent >= 0)
		kasumi_close_private_fd((unsigned int)old_parent);
	if (new_handled && new_parent >= 0)
		kasumi_close_private_fd((unsigned int)new_parent);
	kfree(buffers);
	return ret;
}
#endif

#ifdef __NR_renameat
static long h_renameat(const struct pt_regs *regs)
{
	return kasumi_two_parent_paths(regs, __NR_renameat);
}
#endif

#ifdef __NR_renameat2
static long h_renameat2(const struct pt_regs *regs)
{
	return kasumi_two_parent_paths(regs, __NR_renameat2);
}
#endif

#ifdef __NR_linkat
static long kasumi_linkat_empty_old(const struct pt_regs *regs)
{
	const char __user *new_user =
		(const char __user *)(uintptr_t)kasumi_syscall_arg(regs, 3);
	char new_path[KSM_MAX_LEN_PATHNAME];
	char new_leaf[KASUMI_PATH_BUF];
	char __user *new_leaf_user;
	struct pt_regs redirected;
	bool handled;
	long ret;
	int new_dirfd = (int)kasumi_syscall_arg(regs, 2);
	int new_parent;

	if (!new_user ||
	    kasumi_copy_user_path_at(new_dirfd, new_user, new_path,
				     sizeof(new_path)) <= 0 || new_path[0] != '/')
		return kasumi_call_original(__NR_linkat, regs);
	if (kasumi_should_hide(new_path))
		return -ENOENT;
	new_parent = kasumi_virtual_parent_fd(new_path, new_leaf,
					      sizeof(new_leaf), &handled);
	if (!handled && new_parent < 0)
		return new_parent;
	if (!handled)
		return kasumi_call_original(__NR_linkat, regs);
	if (new_parent < 0)
		return new_parent;
	new_leaf_user = kasumi_userspace_stack_buffer(new_leaf,
						      strlen(new_leaf) + 1);
	if (!new_leaf_user) {
		kasumi_close_private_fd((unsigned int)new_parent);
		return -EFAULT;
	}
	redirected = *regs;
	kasumi_set_syscall_arg(&redirected, 2, (unsigned long)new_parent);
	kasumi_set_syscall_arg(&redirected, 3,
			       (unsigned long)new_leaf_user);
	redirected.syscallno = __NR_linkat;
	PT_REGS_ORIG_SYSCALL(&redirected) = __NR_linkat;
	atomic64_inc(&kasumi_virtual_mutation_handled_count);
	ret = kasumi_call_original(__NR_linkat, &redirected);
	kasumi_close_private_fd((unsigned int)new_parent);
	return ret;
}

static long h_linkat(const struct pt_regs *regs)
{
	const char __user *old_user =
		(const char __user *)(uintptr_t)kasumi_syscall_arg(regs, 1);
	char first = '\0';
	int flags = (int)kasumi_syscall_arg(regs, 4);

	if ((flags & AT_EMPTY_PATH) && old_user &&
	    get_user(first, old_user) == 0 && first == '\0')
		return kasumi_linkat_empty_old(regs);
	return kasumi_two_parent_paths(regs, __NR_linkat);
}
#endif

#ifdef __NR_chdir
static long h_chdir(const struct pt_regs *regs)
{
	const char __user *filename_user;
	char path[KSM_MAX_LEN_PATHNAME];
	struct pt_regs fchdir_regs;
	bool handled = false;
	long ret;
	int fd;

#if defined(__aarch64__)
	filename_user = (const char __user *)(uintptr_t)regs->regs[0];
#else
	filename_user = (const char __user *)(uintptr_t)regs->di;
#endif
	if (!filename_user ||
	    kasumi_copy_user_path_at(AT_FDCWD, filename_user, path,
				     sizeof(path)) <= 0 || path[0] != '/')
		return kasumi_call_original(__NR_chdir, regs);
	if (kasumi_should_hide(path))
		return -ENOENT;
	fd = kasumi_virtual_open_entry_fd(path,
					  O_PATH | O_DIRECTORY | O_CLOEXEC,
					  0, &handled);
	if (!handled)
		return kasumi_call_original(__NR_chdir, regs);
	if (fd < 0)
		return fd;

	fchdir_regs = *regs;
	kasumi_set_path_arg0(&fchdir_regs, (unsigned long)fd);
	fchdir_regs.syscallno = __NR_fchdir;
	PT_REGS_ORIG_SYSCALL(&fchdir_regs) = __NR_fchdir;
	ret = kasumi_call_original(__NR_fchdir, &fchdir_regs);
	kasumi_close_private_fd((unsigned int)fd);
	return ret;
}
#endif

#if defined(__NR_execve) && defined(__NR_execveat)
static long kasumi_virtual_exec(const struct pt_regs *regs, int nr)
{
	struct kasumi_virtual_exec_binding binding = {};
	const char __user *filename_user;
	char exec_fd_path[32];
	char path[KSM_MAX_LEN_PATHNAME];
	char __user *exec_fd_path_user;
	struct pt_regs redirected;
	unsigned long argv;
	unsigned long envp;
	unsigned long exec_target_ino = 0;
	unsigned long exec_target_dev = 0;
	long path_length;
	bool handled;
	long ret;
	int binding_ret;
	int dirfd;
	int flags;
	int open_flags = O_RDONLY;
	int fd;

	if (nr == __NR_execveat) {
		dirfd = (int)kasumi_syscall_arg(regs, 0);
		filename_user = (const char __user *)(uintptr_t)
			kasumi_syscall_arg(regs, 1);
		argv = kasumi_syscall_arg(regs, 2);
		envp = kasumi_syscall_arg(regs, 3);
		flags = (int)kasumi_syscall_arg(regs, 4);
		if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
			return -EINVAL;
		if (flags & AT_SYMLINK_NOFOLLOW)
			open_flags |= O_NOFOLLOW;
	} else {
		dirfd = AT_FDCWD;
		filename_user = (const char __user *)(uintptr_t)
			kasumi_syscall_arg(regs, 0);
		argv = kasumi_syscall_arg(regs, 1);
		envp = kasumi_syscall_arg(regs, 2);
		flags = 0;
	}
	if (!filename_user)
		return kasumi_call_original(nr, regs);
	path_length = kasumi_copy_user_path_at(dirfd, filename_user, path,
					      sizeof(path));
	if (path_length <= 0 || path[0] != '/') {
		bool virtual_empty_fd = false;
		struct kstat exec_stat;

		if (nr == __NR_execveat && path_length == 0 &&
		    (flags & AT_EMPTY_PATH)) {
			virtual_empty_fd = kasumi_virtual_file_get_visible_fd(
				(unsigned int)dirfd, path, sizeof(path));
			if (virtual_empty_fd)
				(void)kasumi_virtual_file_get_target_fd(
					(unsigned int)dirfd, &exec_target_ino,
					&exec_target_dev);
			if (virtual_empty_fd &&
			    kasumi_virtual_file_getattr_fd((unsigned int)dirfd,
							&exec_stat)) {
				ret = kasumi_visible_open_access(&exec_stat, MAY_EXEC);
				if (ret)
					return ret;
			}
		}
		if (virtual_empty_fd) {
			binding_ret = kasumi_virtual_exec_begin_current(
				path, exec_target_ino, exec_target_dev, &binding);
			if (binding_ret)
				return binding_ret;
		}
		ret = kasumi_call_original(nr, regs);
		if (virtual_empty_fd)
			kasumi_virtual_exec_finish_current(&binding, !ret);
		else if (!ret)
			kasumi_virtual_exec_clear_current();
		return ret;
	}
	if (kasumi_should_hide(path))
		return -ENOENT;
	fd = kasumi_virtual_open_exec_fd(path, open_flags, &handled);
	if (!handled) {
		if (kasumi_rule_path_is_virtual(path))
			return -ENOENT;
		ret = kasumi_call_original(nr, regs);
		if (!ret)
			kasumi_virtual_exec_clear_current();
		return ret;
	}
	if (fd < 0)
		return fd;
	(void)kasumi_virtual_file_get_target_fd((unsigned int)fd,
					       &exec_target_ino,
					       &exec_target_dev);
	ret = scnprintf(exec_fd_path, sizeof(exec_fd_path),
			"/proc/self/fd/%d", fd);
	if (ret <= 0 || ret >= sizeof(exec_fd_path)) {
		kasumi_close_private_fd((unsigned int)fd);
		return -ENAMETOOLONG;
	}
	exec_fd_path_user = kasumi_userspace_exec_buffer(
		exec_fd_path, (size_t)ret + 1);
	if (!exec_fd_path_user) {
		kasumi_close_private_fd((unsigned int)fd);
		return -EFAULT;
	}
	binding_ret = kasumi_virtual_exec_begin_current(
		path, exec_target_ino, exec_target_dev, &binding);
	if (binding_ret) {
		kasumi_close_private_fd((unsigned int)fd);
		return binding_ret;
	}
	redirected = *regs;
	kasumi_set_syscall_arg(&redirected, 0,
			       (unsigned long)exec_fd_path_user);
	kasumi_set_syscall_arg(&redirected, 1, argv);
	kasumi_set_syscall_arg(&redirected, 2, envp);
	redirected.syscallno = __NR_execve;
	PT_REGS_ORIG_SYSCALL(&redirected) = __NR_execve;
	ret = kasumi_call_original(__NR_execve, &redirected);
	kasumi_virtual_exec_finish_current(&binding, !ret);
	kasumi_close_private_fd((unsigned int)fd);
	return ret;
}

static long h_execve(const struct pt_regs *regs)
{
	return kasumi_virtual_exec(regs, __NR_execve);
}

static long h_execveat(const struct pt_regs *regs)
{
	return kasumi_virtual_exec(regs, __NR_execveat);
}
#endif

#ifdef __NR_getcwd
static long h_getcwd(const struct pt_regs *regs)
{
	char visible_path[KSM_MAX_LEN_PATHNAME];
	char __user *buffer_user;
	struct path pwd;
	size_t length;
	size_t size;
	bool found;

#if defined(__aarch64__)
	buffer_user = (char __user *)(uintptr_t)regs->regs[0];
	size = (size_t)regs->regs[1];
#else
	buffer_user = (char __user *)(uintptr_t)regs->di;
	size = (size_t)regs->si;
#endif
	if (!current->fs || !kasumi_path_get_ptr)
		return kasumi_call_original(__NR_getcwd, regs);
	spin_lock(&current->fs->lock);
	pwd = current->fs->pwd;
	kasumi_path_get(&pwd);
	spin_unlock(&current->fs->lock);
	found = kasumi_virtual_file_lookup_path(&pwd, visible_path,
					       sizeof(visible_path));
	if (!found)
		found = kasumi_rule_get_visible_path(&pwd, visible_path,
						     sizeof(visible_path));
	kasumi_path_put(&pwd);
	if (!found)
		return kasumi_call_original(__NR_getcwd, regs);
	length = strlen(visible_path) + 1;
	if (length > size)
		return -ERANGE;
	if (copy_to_user(buffer_user, visible_path, length))
		return -EFAULT;
	return length;
}
#endif

#ifdef __NR_getxattr
static KASUMI_NOCFI ssize_t
kasumi_captured_getxattr(const struct path *source, const char *name,
			 void *value, size_t size)
{
	if (!source || !source->dentry || !source->mnt ||
	    !kasumi_vfs_getxattr_addr)
		return -EOPNOTSUPP;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	return ((ssize_t (*)(void *, struct dentry *, const char *, void *,
			      size_t))kasumi_vfs_getxattr_addr)(
		mnt_idmap(source->mnt), source->dentry, name, value, size);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	return ((ssize_t (*)(void *, struct dentry *, const char *, void *,
			      size_t))kasumi_vfs_getxattr_addr)(
		mnt_user_ns(source->mnt), source->dentry, name, value, size);
#else
	return ((ssize_t (*)(struct dentry *, const char *, void *,
			      size_t))kasumi_vfs_getxattr_addr)(
		source->dentry, name, value, size);
#endif
}

static KASUMI_NOCFI ssize_t
kasumi_captured_listxattr(const struct path *source, char *list, size_t size)
{
	if (!source || !source->dentry || !source->mnt ||
	    !kasumi_vfs_listxattr_addr)
		return -EOPNOTSUPP;
	return ((ssize_t (*)(struct dentry *, char *, size_t))
		kasumi_vfs_listxattr_addr)(source->dentry, list, size);
}

static KASUMI_NOCFI int
kasumi_captured_setxattr(const struct path *source, const char *name,
			 const void *value, size_t size, int flags)
{
	int ret;

	if (!source || !source->dentry || !source->mnt ||
	    !kasumi_vfs_setxattr_addr || !kasumi_mnt_want_write_addr ||
	    !kasumi_mnt_drop_write_addr)
		return -EOPNOTSUPP;
	ret = ((int (*)(struct vfsmount *))kasumi_mnt_want_write_addr)(
		source->mnt);
	if (ret)
		return ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ret = ((int (*)(void *, struct dentry *, const char *, const void *,
			 size_t, int))kasumi_vfs_setxattr_addr)(
		mnt_idmap(source->mnt), source->dentry, name, value, size,
		flags);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	ret = ((int (*)(void *, struct dentry *, const char *, const void *,
			 size_t, int))kasumi_vfs_setxattr_addr)(
		mnt_user_ns(source->mnt), source->dentry, name, value, size,
		flags);
#else
	ret = ((int (*)(struct dentry *, const char *, const void *, size_t,
			 int))kasumi_vfs_setxattr_addr)(
		source->dentry, name, value, size, flags);
#endif
	((void (*)(struct vfsmount *))kasumi_mnt_drop_write_addr)(source->mnt);
	return ret;
}

static KASUMI_NOCFI int
kasumi_captured_removexattr(const struct path *source, const char *name)
{
	int ret;

	if (!source || !source->dentry || !source->mnt ||
	    !kasumi_vfs_removexattr_addr || !kasumi_mnt_want_write_addr ||
	    !kasumi_mnt_drop_write_addr)
		return -EOPNOTSUPP;
	ret = ((int (*)(struct vfsmount *))kasumi_mnt_want_write_addr)(
		source->mnt);
	if (ret)
		return ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ret = ((int (*)(void *, struct dentry *, const char *))
		kasumi_vfs_removexattr_addr)(mnt_idmap(source->mnt),
					     source->dentry, name);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	ret = ((int (*)(void *, struct dentry *, const char *))
		kasumi_vfs_removexattr_addr)(mnt_user_ns(source->mnt),
					     source->dentry, name);
#else
	ret = ((int (*)(struct dentry *, const char *))
		kasumi_vfs_removexattr_addr)(source->dentry, name);
#endif
	((void (*)(struct vfsmount *))kasumi_mnt_drop_write_addr)(source->mnt);
	return ret;
}

static int kasumi_copy_xattr_name(const char __user *name_user,
				  char name[XATTR_NAME_MAX + 1])
{
	ssize_t length;

	length = strncpy_from_user(name, name_user, XATTR_NAME_MAX + 1);
	if (length == 0 || length == XATTR_NAME_MAX + 1)
		return -ERANGE;
	return length < 0 ? (int)length : 0;
}

static long kasumi_getxattr_to_user(const struct path *source,
				    const char __user *name_user,
				    void __user *value_user, size_t size)
{
	char name[XATTR_NAME_MAX + 1];
	void *value = NULL;
	ssize_t ret;

	ret = kasumi_copy_xattr_name(name_user, name);
	if (ret)
		return ret;
	if (size) {
		size = min_t(size_t, size, XATTR_SIZE_MAX);
		value = kvzalloc(size, GFP_KERNEL);
		if (!value)
			return -ENOMEM;
	}
	ret = kasumi_captured_getxattr(source, name, value, size);
	if (ret > (ssize_t)size && size)
		ret = -EIO;
	else if (ret > 0 && size && copy_to_user(value_user, value, ret))
		ret = -EFAULT;
	else if (ret == -ERANGE && size >= XATTR_SIZE_MAX)
		ret = -E2BIG;
	kvfree(value);
	return ret;
}

static long kasumi_setxattr_from_user(const struct path *source,
				      const char __user *name_user,
				      const void __user *value_user,
				      size_t size, int flags)
{
	char name[XATTR_NAME_MAX + 1];
	void *value = NULL;
	long ret;

	if (size > XATTR_SIZE_MAX)
		return -E2BIG;
	if (flags & ~(XATTR_CREATE | XATTR_REPLACE))
		return -EINVAL;
	ret = kasumi_copy_xattr_name(name_user, name);
	if (ret)
		return ret;
	if (size) {
		value = kvmalloc(size, GFP_KERNEL);
		if (!value)
			return -ENOMEM;
		if (copy_from_user(value, value_user, size)) {
			kvfree(value);
			return -EFAULT;
		}
	}
	ret = kasumi_captured_setxattr(source, name, value, size, flags);
	kvfree(value);
	return ret;
}

static long kasumi_removexattr_from_user(const struct path *source,
					 const char __user *name_user)
{
	char name[XATTR_NAME_MAX + 1];
	int ret;

	ret = kasumi_copy_xattr_name(name_user, name);
	if (ret)
		return ret;
	return kasumi_captured_removexattr(source, name);
}

static long kasumi_listxattr_to_user(const struct path *source,
				     char __user *list_user, size_t size)
{
	char *list = NULL;
	ssize_t ret;

	if (size) {
		size = min_t(size_t, size, XATTR_LIST_MAX);
		list = kvmalloc(size, GFP_KERNEL);
		if (!list)
			return -ENOMEM;
	}
	ret = kasumi_captured_listxattr(source, list, size);
	if (ret > (ssize_t)size && size)
		ret = -EIO;
	else if (ret > 0 && size && copy_to_user(list_user, list, ret))
		ret = -EFAULT;
	else if (ret == -ERANGE && size >= XATTR_LIST_MAX)
		ret = -E2BIG;
	kvfree(list);
	return ret;
}

static long do_getxattr(const struct pt_regs *regs, int nr)
{
	const char __user *pathname_user;
	const char __user *name_user;
	void __user *value_user;
	struct kasumi_rule_source source = {};
	char path[KSM_MAX_LEN_PATHNAME];
	unsigned int lookup_flags = LOOKUP_FOLLOW;
	size_t size;
	long ret;

#if defined(__aarch64__)
	pathname_user = (const char __user *)(uintptr_t)regs->regs[0];
	name_user = (const char __user *)(uintptr_t)regs->regs[1];
	value_user = (void __user *)(uintptr_t)regs->regs[2];
	size = (size_t)regs->regs[3];
#else
	pathname_user = (const char __user *)(uintptr_t)regs->di;
	name_user = (const char __user *)(uintptr_t)regs->si;
	value_user = (void __user *)(uintptr_t)regs->dx;
	size = (size_t)regs->r10;
#endif
	if (!pathname_user ||
	    kasumi_copy_user_path_at(AT_FDCWD, pathname_user, path,
				     sizeof(path)) <= 0 || path[0] != '/')
		return do_path0_hide(regs, nr);
	if (kasumi_should_hide(path))
		return -ENOENT;
#ifdef __NR_lgetxattr
	if (nr == __NR_lgetxattr)
		lookup_flags = 0;
#endif
	if (!kasumi_rule_get_source_flags(path, lookup_flags, &source)) {
		if (source.error)
			return source.error;
		if (kasumi_rule_path_is_virtual(path))
			return -ENOENT;
		return do_path0_hide(regs, nr);
	}
	atomic64_inc(&kasumi_virtual_xattr_handled_count);
	ret = kasumi_getxattr_to_user(&source.path, name_user, value_user,
				      size);
	kasumi_path_put(&source.path);
	return ret;
}

static long h_getxattr(const struct pt_regs *regs)
{
	return do_getxattr(regs, __NR_getxattr);
}
#endif

#ifdef __NR_lgetxattr
static long h_lgetxattr(const struct pt_regs *regs)
{
	return do_getxattr(regs, __NR_lgetxattr);
}
#endif

/*
 * fgetxattr/flistxattr/fsetxattr/fremovexattr are intentionally NOT TSR routes.
 * A virtual descriptor adopts the captured source inode and mount (see
 * kasumi_virtual_adopt_real_file), so the ordinary VFS fd xattr path already
 * dispatches on exactly the (dentry, mnt) these handlers used to forward to.
 * Serving them at the syscall boundary duplicated that work and left an extra
 * observable route; the VFS layer produces identical results with no seam.
 */

#ifdef __NR_listxattr
static long do_listxattr(const struct pt_regs *regs, int nr)
{
	const char __user *pathname_user;
	char __user *list_user;
	struct kasumi_rule_source source = {};
	char path[KSM_MAX_LEN_PATHNAME];
	unsigned int lookup_flags = LOOKUP_FOLLOW;
	size_t size;
	long ret;

#if defined(__aarch64__)
	pathname_user = (const char __user *)(uintptr_t)regs->regs[0];
	list_user = (char __user *)(uintptr_t)regs->regs[1];
	size = (size_t)regs->regs[2];
#else
	pathname_user = (const char __user *)(uintptr_t)regs->di;
	list_user = (char __user *)(uintptr_t)regs->si;
	size = (size_t)regs->dx;
#endif
	if (!pathname_user ||
	    kasumi_copy_user_path_at(AT_FDCWD, pathname_user, path,
				     sizeof(path)) <= 0 || path[0] != '/')
		return do_path0_hide(regs, nr);
	if (kasumi_should_hide(path))
		return -ENOENT;
#ifdef __NR_llistxattr
	if (nr == __NR_llistxattr)
		lookup_flags = 0;
#endif
	if (!kasumi_rule_get_source_flags(path, lookup_flags, &source)) {
		if (source.error)
			return source.error;
		if (kasumi_rule_path_is_virtual(path))
			return -ENOENT;
		return do_path0_hide(regs, nr);
	}
	atomic64_inc(&kasumi_virtual_xattr_handled_count);
	ret = kasumi_listxattr_to_user(&source.path, list_user, size);
	kasumi_path_put(&source.path);
	return ret;
}

static long h_listxattr(const struct pt_regs *regs)
{
	return do_listxattr(regs, __NR_listxattr);
}
#endif

#ifdef __NR_llistxattr
static long h_llistxattr(const struct pt_regs *regs)
{
	return do_listxattr(regs, __NR_llistxattr);
}
#endif

/* flistxattr: not a TSR route; served by VFS via the adopted inode (see above). */

#ifdef __NR_setxattr
static long do_setxattr(const struct pt_regs *regs, int nr)
{
	const char __user *pathname_user;
	const char __user *name_user;
	const void __user *value_user;
	struct kasumi_rule_source source = {};
	char path[KSM_MAX_LEN_PATHNAME];
	unsigned int lookup_flags = LOOKUP_FOLLOW;
	size_t size;
	int flags;
	long ret;

#if defined(__aarch64__)
	pathname_user = (const char __user *)(uintptr_t)regs->regs[0];
	name_user = (const char __user *)(uintptr_t)regs->regs[1];
	value_user = (const void __user *)(uintptr_t)regs->regs[2];
	size = (size_t)regs->regs[3];
	flags = (int)regs->regs[4];
#else
	pathname_user = (const char __user *)(uintptr_t)regs->di;
	name_user = (const char __user *)(uintptr_t)regs->si;
	value_user = (const void __user *)(uintptr_t)regs->dx;
	size = (size_t)regs->r10;
	flags = (int)regs->r8;
#endif
	if (!pathname_user ||
	    kasumi_copy_user_path_at(AT_FDCWD, pathname_user, path,
				     sizeof(path)) <= 0 || path[0] != '/')
		return do_path0_hide(regs, nr);
	if (kasumi_should_hide(path))
		return -ENOENT;
#ifdef __NR_lsetxattr
	if (nr == __NR_lsetxattr)
		lookup_flags = 0;
#endif
	if (!kasumi_rule_get_source_flags(path, lookup_flags, &source)) {
		if (source.error)
			return source.error;
		if (kasumi_rule_path_is_virtual(path))
			return -ENOENT;
		return do_path0_hide(regs, nr);
	}
	atomic64_inc(&kasumi_virtual_xattr_handled_count);
	ret = kasumi_setxattr_from_user(&source.path, name_user, value_user,
				       size, flags);
	kasumi_path_put(&source.path);
	return ret;
}

static long h_setxattr(const struct pt_regs *regs)
{
	return do_setxattr(regs, __NR_setxattr);
}
#endif

#ifdef __NR_lsetxattr
static long h_lsetxattr(const struct pt_regs *regs)
{
	return do_setxattr(regs, __NR_lsetxattr);
}
#endif

/* fsetxattr: not a TSR route; served by VFS via the adopted inode (see above). */

#ifdef __NR_removexattr
static long do_removexattr(const struct pt_regs *regs, int nr)
{
	const char __user *pathname_user;
	const char __user *name_user;
	struct kasumi_rule_source source = {};
	char path[KSM_MAX_LEN_PATHNAME];
	unsigned int lookup_flags = LOOKUP_FOLLOW;
	long ret;

#if defined(__aarch64__)
	pathname_user = (const char __user *)(uintptr_t)regs->regs[0];
	name_user = (const char __user *)(uintptr_t)regs->regs[1];
#else
	pathname_user = (const char __user *)(uintptr_t)regs->di;
	name_user = (const char __user *)(uintptr_t)regs->si;
#endif
	if (!pathname_user ||
	    kasumi_copy_user_path_at(AT_FDCWD, pathname_user, path,
				     sizeof(path)) <= 0 || path[0] != '/')
		return do_path0_hide(regs, nr);
	if (kasumi_should_hide(path))
		return -ENOENT;
#ifdef __NR_lremovexattr
	if (nr == __NR_lremovexattr)
		lookup_flags = 0;
#endif
	if (!kasumi_rule_get_source_flags(path, lookup_flags, &source)) {
		if (source.error)
			return source.error;
		if (kasumi_rule_path_is_virtual(path))
			return -ENOENT;
		return do_path0_hide(regs, nr);
	}
	atomic64_inc(&kasumi_virtual_xattr_handled_count);
	ret = kasumi_removexattr_from_user(&source.path, name_user);
	kasumi_path_put(&source.path);
	return ret;
}

static long h_removexattr(const struct pt_regs *regs)
{
	return do_removexattr(regs, __NR_removexattr);
}
#endif

#ifdef __NR_lremovexattr
static long h_lremovexattr(const struct pt_regs *regs)
{
	return do_removexattr(regs, __NR_lremovexattr);
}
#endif

/* fremovexattr: not a TSR route; served by VFS via the adopted inode (see above). */

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
#ifdef __NR_fstat
		kasumi_add_syscall_hook_counted(__NR_fstat, h_fstat, &n);
#endif
#ifdef __NR_faccessat
		kasumi_add_syscall_hook_counted(__NR_faccessat, h_faccessat, &n);
#endif
#ifdef __NR_faccessat2
		kasumi_add_syscall_hook_counted(__NR_faccessat2, h_faccessat2, &n);
#endif
#ifdef __NR_access
		kasumi_add_syscall_hook_counted(__NR_access, h_access, &n);
#endif
#ifdef __NR_getcwd
		kasumi_add_syscall_hook_counted(__NR_getcwd, h_getcwd, &n);
#endif
#ifdef __NR_chdir
		kasumi_add_syscall_hook_counted(__NR_chdir, h_chdir, &n);
#endif
#if defined(__NR_execve) && defined(__NR_execveat)
		kasumi_add_syscall_hook_counted(__NR_execve, h_execve, &n);
		kasumi_add_syscall_hook_counted(__NR_execveat, h_execveat, &n);
#endif
#ifdef __NR_mkdirat
		kasumi_add_syscall_hook_counted(__NR_mkdirat, h_mkdirat, &n);
#endif
#ifdef __NR_unlinkat
		kasumi_add_syscall_hook_counted(__NR_unlinkat, h_unlinkat, &n);
#endif
#ifdef __NR_mknodat
		kasumi_add_syscall_hook_counted(__NR_mknodat, h_mknodat, &n);
#endif
#ifdef __NR_renameat
		kasumi_add_syscall_hook_counted(__NR_renameat, h_renameat, &n);
#endif
#ifdef __NR_renameat2
		kasumi_add_syscall_hook_counted(__NR_renameat2, h_renameat2, &n);
#endif
#ifdef __NR_linkat
		kasumi_add_syscall_hook_counted(__NR_linkat, h_linkat, &n);
#endif
#ifdef __NR_readlinkat
		kasumi_add_syscall_hook_counted(__NR_readlinkat, h_readlinkat, &n);
#endif
#ifdef __NR_symlinkat
		kasumi_add_syscall_hook_counted(__NR_symlinkat, h_symlinkat, &n);
#endif
#if defined(__NR_truncate) && defined(__NR_ftruncate)
		kasumi_add_syscall_hook_counted(__NR_truncate, h_truncate, &n);
#endif
#ifdef __NR_fchmodat
		kasumi_add_syscall_hook_counted(__NR_fchmodat, h_fchmodat, &n);
#endif
#ifdef __NR_fchmodat2
		kasumi_add_syscall_hook_counted(__NR_fchmodat2, h_fchmodat2, &n);
#endif
#ifdef __NR_fchownat
		kasumi_add_syscall_hook_counted(__NR_fchownat, h_fchownat, &n);
#endif
#ifdef __NR_utimensat
		kasumi_add_syscall_hook_counted(__NR_utimensat, h_utimensat, &n);
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
#ifdef __NR_setxattr
		kasumi_add_syscall_hook_counted(__NR_setxattr, h_setxattr, &n);
#endif
#ifdef __NR_lsetxattr
		kasumi_add_syscall_hook_counted(__NR_lsetxattr, h_lsetxattr, &n);
#endif
#ifdef __NR_removexattr
		kasumi_add_syscall_hook_counted(__NR_removexattr, h_removexattr, &n);
#endif
#ifdef __NR_lremovexattr
		kasumi_add_syscall_hook_counted(__NR_lremovexattr, h_lremovexattr, &n);
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
