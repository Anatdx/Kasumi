/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - module bootstrap, symbol resolution, and top-level lifecycle orchestration.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "kasumi_bootstrap.h"
#include "kasumi_runtime.h"
#include "kasumi_store.h"
#include "kasumi_file_view.h"
#include "kasumi_entrypoints.h"
#include "kasumi_proc_hooks.h"
#include "kasumi_vfs_hooks.h"
#include "kasumi_uname.h"
#include "kasumi_sop_override.h"
#include "kasumi_dop_override.h"
#include "kasumi_xattr_sid_override.h"
#include "kasumi_iop_override.h"
#include "kasumi_fop_override.h"
#include "kasumi_fake_mountinfo.h"
#include "kasumi_syscall_redirect.h"
#include "kasumi_tracepoint_hooks.h"

#ifndef KASUMI_VERSION
#define KASUMI_VERSION "0.1.0-dev"
#endif

static int kasumi_no_tracepoint_param;
module_param_named(kasumi_no_tracepoint, kasumi_no_tracepoint_param, int, 0600);
MODULE_PARM_DESC(kasumi_no_tracepoint, "1=skip sys_enter tracepoint, use kprobe. 0=try tracepoint first (default).");

static int kasumi_skip_vfs_param;
module_param_named(kasumi_skip_vfs, kasumi_skip_vfs_param, int, 0600);
MODULE_PARM_DESC(kasumi_skip_vfs, "1=skip VFS hooks (ftrace+kprobes). For debugging crash.");

static int kasumi_skip_extra_kprobes_param;
module_param_named(kasumi_skip_extra_kprobes, kasumi_skip_extra_kprobes_param, int, 0600);
MODULE_PARM_DESC(kasumi_skip_extra_kprobes, "1=skip extra kprobes (reboot,prctl,uname,cmdline). For debugging.");

static int kasumi_skip_getfd_param;
module_param_named(kasumi_skip_getfd, kasumi_skip_getfd_param, int, 0600);
MODULE_PARM_DESC(kasumi_skip_getfd, "1=skip GET_FD kprobe/tracepoint. For debugging crash.");

static int kasumi_skip_kallsyms_param;
module_param_named(kasumi_skip_kallsyms, kasumi_skip_kallsyms_param, int, 0600);
MODULE_PARM_DESC(kasumi_skip_kallsyms, "1=skip kallsyms resolution, use per-symbol kprobe. For GKI compatibility.");

static int kasumi_dummy_mode_param;
module_param_named(kasumi_dummy_mode, kasumi_dummy_mode_param, int, 0600);
MODULE_PARM_DESC(kasumi_dummy_mode, "1=exit immediately after init starts (for testing).");

static void kasumi_resolve_system_dev(void)
{
	struct path sys_path = {};
	struct dentry *dentry;
	struct vfsmount *mnt;
	struct super_block *sb;
	int ret;

	if (!kasumi_kern_path)
		return;

	ret = kasumi_kern_path("/system", LOOKUP_FOLLOW, &sys_path);
	if (ret) {
		pr_warn("Kasumi: could not resolve /system for stat spoofing: %d\n", ret);
		return;
	}

	dentry = READ_ONCE(sys_path.dentry);
	mnt = READ_ONCE(sys_path.mnt);
	sb = dentry ? READ_ONCE(dentry->d_sb) : NULL;
	if (!dentry || !mnt || !sb) {
		pr_warn("Kasumi: /system resolved to incomplete path (mnt=%p dentry=%p sb=%p), stat spoofing dev disabled\n",
			mnt, dentry, sb);
		if (dentry && mnt)
			path_put(&sys_path);
		return;
	}

	kasumi_system_dev = sb->s_dev;
	pr_info("Kasumi: /system dev=%u:%u\n",
		MAJOR(kasumi_system_dev), MINOR(kasumi_system_dev));
	path_put(&sys_path);
}

static int kasumi_resolve_runtime_symbols(void)
{
	kasumi_kern_path = (void *)kasumi_lookup_name("kern_path");
	if (!kasumi_kern_path) {
		pr_err("Kasumi: FATAL - kern_path not found\n");
		return -ENOENT;
	}

	kasumi_strndup_user = (void *)kasumi_lookup_name("strndup_user");
	if (!kasumi_strndup_user) {
		pr_err("Kasumi: FATAL - strndup_user not found\n");
		return -ENOENT;
	}

	kasumi_ihold = (void *)kasumi_lookup_name("ihold");
	if (!kasumi_ihold) {
		pr_err("Kasumi: FATAL - ihold not found\n");
		return -ENOENT;
	}

	kasumi_getname_kernel = (void *)kasumi_lookup_name("getname_kernel");
	if (!kasumi_getname_kernel)
		pr_warn("Kasumi: getname_kernel not found, path redirect may fail\n");

	kasumi_filp_open = (void *)kasumi_lookup_name("filp_open");
	kasumi_filp_close = (void *)kasumi_lookup_name("filp_close");
	kasumi_kernel_read = (void *)kasumi_lookup_name("kernel_read");
	kasumi_vfs_getattr = (void *)kasumi_lookup_name("vfs_getattr");
	kasumi_dentry_open = (void *)kasumi_lookup_name("dentry_open");
	kasumi_d_absolute_path = (void *)kasumi_lookup_name("d_absolute_path");
	kasumi_dentry_path_raw = (void *)kasumi_lookup_name("dentry_path_raw");
	kasumi_strncpy_from_user_nofault = (void *)kasumi_lookup_name("strncpy_from_user_nofault");
	if (!kasumi_strncpy_from_user_nofault)
		pr_warn("Kasumi: strncpy_from_user_nofault not found, falling back to copy_from_user\n");
	kasumi_d_path = (void *)kasumi_lookup_name("d_path");
	kasumi_d_hash_and_lookup = (void *)kasumi_lookup_name("d_hash_and_lookup");
	if (!kasumi_d_path)
		pr_warn("Kasumi: d_path not found, path resolution in populate/merge/hide may fail\n");
	if (!kasumi_d_hash_and_lookup)
		pr_warn("Kasumi: d_hash_and_lookup not found, merge dedup and hide filter disabled\n");
	if (!kasumi_filp_open || !kasumi_kernel_read)
		pr_warn("Kasumi: filp_open/kernel_read not found, allowlist disabled\n");

	{
		unsigned long addr = kasumi_lookup_name("ksu_uid_should_umount");
		if (addr && kasumi_valid_kernel_addr(addr))
			kasumi_ksu_uid_should_umount_ptr = (kasumi_ksu_uid_should_umount_fn)addr;
	}
	{
		unsigned long addr = kasumi_lookup_name("__ksu_is_allow_uid_for_current");
		if (addr && kasumi_valid_kernel_addr(addr))
			kasumi_ksu_is_allow_uid_ptr = (kasumi_ksu_is_allow_uid_fn)addr;
	}
	if (!kasumi_ksu_is_allow_uid_ptr) {
		unsigned long addr = kasumi_lookup_name("__ksu_is_allow_uid");
		if (addr && kasumi_valid_kernel_addr(addr))
			kasumi_ksu_is_allow_uid_ptr = (kasumi_ksu_is_allow_uid_fn)addr;
	}

	if (!kasumi_vfs_getattr || !kasumi_dentry_open)
		pr_warn("Kasumi: vfs_getattr/dentry_open not found, merge whiteout/iterate disabled\n");
	if (!kasumi_d_absolute_path && !kasumi_dentry_path_raw)
		pr_warn("Kasumi: neither d_absolute_path nor dentry_path_raw found, inject/merge listing disabled\n");

	return 0;
}

int kasumi_bootstrap_init(void)
{
	int ret;

	pr_alert("Kasumi: === INIT START v%s ===\n", KASUMI_VERSION);
	if (kasumi_dummy_mode_param) {
		pr_alert("Kasumi: DUMMY MODE - exiting immediately\n");
		return 0;
	}

	kasumi_filldir_cache = kmem_cache_create("kasumi_filldir",
		sizeof(struct kasumi_filldir_wrapper), 0,
		SLAB_HWCACHE_ALIGN, NULL);
	if (!kasumi_filldir_cache) {
		pr_alert("Kasumi: failed to create filldir slab cache\n");
		return -ENOMEM;
	}

	pr_alert("Kasumi: skip_kallsyms=%d skip_vfs=%d skip_extra=%d skip_getfd=%d\n",
		kasumi_skip_kallsyms_param, kasumi_skip_vfs_param,
		kasumi_skip_extra_kprobes_param, kasumi_skip_getfd_param);

	if (!kasumi_skip_kallsyms_param)
		kasumi_resolve_kallsyms_lookup();
	else
		pr_alert("Kasumi: skipping kallsyms (using per-symbol kprobe)\n");

	ret = kasumi_resolve_runtime_symbols();
	if (ret)
		goto err_cache;

	hash_init(kasumi_paths);
	hash_init(kasumi_targets);
	hash_init(kasumi_hide_paths);
	hash_init(kasumi_inject_dirs);
	hash_init(kasumi_xattr_sbs);
	hash_init(kasumi_merge_dirs);

	kasumi_percpu_base = vmalloc(nr_cpu_ids * sizeof(struct kasumi_percpu));
	kasumi_getname_buf_base = vmalloc(nr_cpu_ids * KASUMI_PATH_BUF);
	kasumi_iterate_buf_base = vmalloc(nr_cpu_ids * KASUMI_ITERATE_PATH_BUF);
	if (!kasumi_percpu_base || !kasumi_getname_buf_base || !kasumi_iterate_buf_base) {
		ret = -ENOMEM;
		pr_err("Kasumi: failed to allocate per-CPU buffers\n");
		goto err_buffers;
	}
	memset(kasumi_percpu_base, 0, nr_cpu_ids * sizeof(struct kasumi_percpu));

	kasumi_resolve_system_dev();

	(void)kasumi_syscall_redirect_init();

	ret = kasumi_proc_hooks_init(kasumi_skip_getfd_param, kasumi_no_tracepoint_param,
				     kasumi_skip_extra_kprobes_param);
	if (ret)
		goto err_buffers;

	ret = kasumi_vfs_hooks_init(kasumi_skip_vfs_param);
	if (ret)
		goto err_proc;

	(void)kasumi_sop_override_init();
	(void)kasumi_dop_override_init();
	(void)kasumi_xattr_sid_override_init();
	(void)kasumi_iop_override_init();
	(void)kasumi_fop_override_init();
	(void)kasumi_fake_mi_init();
	pr_alert("Kasumi: Chikyuu ga buttobu kurai tanoshinjaoo!!\n");
	return 0;

err_proc:
	kasumi_proc_hooks_exit();
err_buffers:
	vfree(kasumi_percpu_base);
	vfree(kasumi_getname_buf_base);
	vfree(kasumi_iterate_buf_base);
	kasumi_percpu_base = NULL;
	kasumi_getname_buf_base = NULL;
	kasumi_iterate_buf_base = NULL;
err_cache:
	if (kasumi_filldir_cache) {
		kmem_cache_destroy(kasumi_filldir_cache);
		kasumi_filldir_cache = NULL;
	}
	return ret;
}

void kasumi_bootstrap_exit(void)
{
	struct kasumi_cmdline_rcu *old_cmdline;

	pr_info("Kasumi: shutting down\n");

	/*
	 * PHASE 1: Sever every entry point that can drive a syscall hook.
	 *
	 *  1. tracepoint_path_exit() unregisters sys_enter/sys_exit and calls
	 *     tracepoint_synchronize_unregister(), so no new syscall will have
	 *     its syscallno rewritten to the dispatcher slot.
	 *  2. syscall_redirect_exit() restores the patched ni_syscall slot and
	 *     waits via synchronize_srcu() for in-flight dispatcher invocations
	 *     and their handlers to drain.
	 *
	 * Ordering matters: relative to KSU's manager_exit, this is the
	 * tracepoint -> syscall_table -> hooks teardown.  Any cleanup that frees
	 * resources reachable from h_openat/h_statfs/etc. (proc fd proxies,
	 * fake mountinfo, fop/iop shadows, vfs ftrace hooks) MUST run after
	 * this phase, otherwise a high-frequency syscall (e.g. read) will UAF
	 * those resources mid-teardown.
	 */
	kasumi_tracepoint_path_exit();
	kasumi_syscall_redirect_exit();

	/* PHASE 2: handlers can no longer be reached, free their dependencies. */
	kasumi_file_view_shutdown();
	kasumi_proc_hooks_exit();
	kasumi_vfs_hooks_exit(kasumi_skip_vfs_param);
	kasumi_fop_override_exit();
	kasumi_iop_override_exit();
	kasumi_xattr_sid_override_exit();
	kasumi_dop_override_exit();
	kasumi_sop_override_exit();
	kasumi_fake_mi_exit();
	kasumi_uname_exit();

	mutex_lock(&kasumi_config_mutex);
	kasumi_cleanup_locked();
	old_cmdline = rcu_dereference_protected(kasumi_spoof_cmdline_ptr,
						lockdep_is_held(&kasumi_config_mutex));
	rcu_assign_pointer(kasumi_spoof_cmdline_ptr, NULL);
	mutex_unlock(&kasumi_config_mutex);

	rcu_barrier();
	kfree(old_cmdline);
	if (kasumi_filldir_cache)
		kmem_cache_destroy(kasumi_filldir_cache);
	vfree(kasumi_percpu_base);
	vfree(kasumi_getname_buf_base);
	vfree(kasumi_iterate_buf_base);
	kasumi_percpu_base = NULL;
	kasumi_getname_buf_base = NULL;
	kasumi_iterate_buf_base = NULL;
	pr_alert("Kasumi: Goseichou thank you!!!\n");
}
