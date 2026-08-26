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
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "kasumi_bootstrap.h"
#include "kasumi_runtime.h"
#include "kasumi_root_detection.h"
#include "kasumi_path_policy.h"
#include "kasumi_store.h"
#include "kasumi_fop_bridge.h"
#include "kasumi_entrypoints.h"
#include "kasumi_proc_hooks.h"
#include "kasumi_vfs_hooks.h"
#include "kasumi_iop_override.h"
#include "kasumi_dirhijack.h"
#include "kasumi_fop_override.h"
#include "kasumi_fake_mountinfo.h"
#include "kasumi_fake_selinuxfs_access.h"

#ifndef KASUMI_VERSION
#define KASUMI_VERSION "0.1.0-dev"
#endif

static int kasumi_no_tracepoint_param;
module_param_named(kasumi_no_tracepoint, kasumi_no_tracepoint_param, int, 0600);
MODULE_PARM_DESC(kasumi_no_tracepoint, "1=disable TSR; virtual path redirect is unavailable.");

static int kasumi_skip_kallsyms_param;
module_param_named(kasumi_skip_kallsyms, kasumi_skip_kallsyms_param, int, 0600);
MODULE_PARM_DESC(kasumi_skip_kallsyms, "1=skip kallsyms resolution, use per-symbol kprobe. For GKI compatibility.");

static int kasumi_dummy_mode_param;
module_param_named(kasumi_dummy_mode, kasumi_dummy_mode_param, int, 0600);
MODULE_PARM_DESC(kasumi_dummy_mode, "1=exit immediately after init starts (for testing).");

module_param_named(kasumi_fscaps, kasumi_fscaps_enabled, int, 0644);
MODULE_PARM_DESC(kasumi_fscaps, "1=replay a redirected source's file capabilities onto exec (default 1).");

module_param_named(kasumi_device_sources, kasumi_device_sources_enabled, int, 0644);
MODULE_PARM_DESC(kasumi_device_sources, "1=serve char/blk/fifo source redirects via a vnode wrapper (default 1).");

static char kasumi_owner_nonce[33];
module_param_string(kasumi_owner_nonce, kasumi_owner_nonce,
		    sizeof(kasumi_owner_nonce), 0400);
MODULE_PARM_DESC(kasumi_owner_nonce, "Per-load userspace ownership token.");

/* Keep ordinary delete_module() out of module_exit until PREPARE_UNLOAD has
 * severed every external callback entry point.  The loader drops its initial
 * reference only after ->init returns, leaving this one lifecycle reference.
 */
static bool kasumi_unload_pin_held;

bool kasumi_bootstrap_quiesce_supported(void)
{
	if (!kasumi_module_refcount_ptr)
		return false;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	return true;
#else
	return kasumi_fop_bridge_capable();
#endif
}

bool kasumi_bootstrap_unload_pin_held(void)
{
	return READ_ONCE(kasumi_unload_pin_held);
}

void kasumi_bootstrap_release_unload_pin(void)
{
	if (WARN_ON_ONCE(!READ_ONCE(kasumi_unload_pin_held)))
		return;
	WRITE_ONCE(kasumi_unload_pin_held, false);
	module_put(THIS_MODULE);
}

static noinline KASUMI_NOCFI void kasumi_resolve_system_dev(void)
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
			kasumi_path_put(&sys_path);
		return;
	}

	kasumi_system_dev = sb->s_dev;
	pr_info("Kasumi: /system dev=%u:%u\n",
		MAJOR(kasumi_system_dev), MINOR(kasumi_system_dev));
	kasumi_path_put(&sys_path);
}

static int kasumi_resolve_runtime_symbols(void)
{
	kasumi_kern_path = (void *)kasumi_lookup_callable("kern_path");
	if (!kasumi_kern_path) {
		pr_err("Kasumi: FATAL - kern_path not found\n");
		return -ENOENT;
	}

	kasumi_strndup_user = (void *)kasumi_lookup_callable("strndup_user");
	if (!kasumi_strndup_user) {
		pr_err("Kasumi: FATAL - strndup_user not found\n");
		return -ENOENT;
	}

	kasumi_ihold = (void *)kasumi_lookup_callable("ihold");
	if (!kasumi_ihold) {
		pr_err("Kasumi: FATAL - ihold not found\n");
		return -ENOENT;
	}

	kasumi_filp_open = (void *)kasumi_lookup_callable("filp_open");
	kasumi_filp_close = (void *)kasumi_lookup_callable("filp_close");
	kasumi_vfs_getattr = (void *)kasumi_lookup_callable("vfs_getattr");
	kasumi_notify_change =
		(void *)kasumi_lookup_callable_quiet("notify_change");
	kasumi_vfs_getxattr_addr =
		(void *)kasumi_lookup_callable_quiet("vfs_getxattr");
	kasumi_vfs_listxattr_addr =
		(void *)kasumi_lookup_callable_quiet("vfs_listxattr");
	kasumi_vfs_setxattr_addr =
		(void *)kasumi_lookup_callable_quiet("vfs_setxattr");
	kasumi_vfs_removexattr_addr =
		(void *)kasumi_lookup_callable_quiet("vfs_removexattr");
	kasumi_mnt_want_write_addr =
		(void *)kasumi_lookup_callable_quiet("mnt_want_write");
	kasumi_mnt_drop_write_addr =
		(void *)kasumi_lookup_callable_quiet("mnt_drop_write");
	kasumi_vfs_path_lookup =
		(void *)kasumi_lookup_callable_quiet("vfs_path_lookup");
	kasumi_vfs_get_link =
		(void *)kasumi_lookup_callable_quiet("vfs_get_link");
	/* Directory-mutation delegates for redirected directory-source vnodes
	 * (Final Phase 1b).  Quiet: absence only disables create/remove inside a
	 * redirected directory (the op returns -EOPNOTSUPP), never crashes. */
	kasumi_lookup_one_len =
		(void *)kasumi_lookup_callable_quiet("lookup_one_len");
	kasumi_vfs_create = (void *)kasumi_lookup_callable_quiet("vfs_create");
	kasumi_vfs_mkdir = (void *)kasumi_lookup_callable_quiet("vfs_mkdir");
	kasumi_vfs_mknod = (void *)kasumi_lookup_callable_quiet("vfs_mknod");
	kasumi_vfs_symlink = (void *)kasumi_lookup_callable_quiet("vfs_symlink");
	kasumi_vfs_unlink = (void *)kasumi_lookup_callable_quiet("vfs_unlink");
	kasumi_vfs_rmdir = (void *)kasumi_lookup_callable_quiet("vfs_rmdir");
	kasumi_vfs_link = (void *)kasumi_lookup_callable_quiet("vfs_link");
	kasumi_vfs_rename = (void *)kasumi_lookup_callable_quiet("vfs_rename");
	kasumi_dentry_open = (void *)kasumi_lookup_callable("dentry_open");
	/* Data-plane delegates for char/blk/fifo source wrappers (special fops).
	 * Optional: absence only disables read/write on a device/fifo redirect. */
	kasumi_vfs_read = (void *)kasumi_lookup_callable_quiet("vfs_read");
	kasumi_vfs_write = (void *)kasumi_lookup_callable_quiet("vfs_write");
	/* Source file-capability reader for exec-path fscap replay (Item A).
	 * Optional: absence only disables carrying a redirected setcap binary's
	 * capabilities across exec, never crashes. */
	kasumi_get_vfs_caps_from_disk =
		(void *)kasumi_lookup_callable_quiet("get_vfs_caps_from_disk");
	if (!kasumi_get_vfs_caps_from_disk)
		pr_info("Kasumi: get_vfs_caps_from_disk unavailable, redirected file capabilities not carried across exec\n");
	/* Public LSM secctx round-trip for cloning a source's SELinux context onto
	 * a vnode.  Optional: absence only means vnodes fall back to the default
	 * label (no crash), so resolve quietly and let callers null-check. */
	kasumi_security_inode_getsecctx =
		(void *)kasumi_lookup_callable_quiet("security_inode_getsecctx");
	kasumi_security_inode_notifysecctx =
		(void *)kasumi_lookup_callable_quiet("security_inode_notifysecctx");
	kasumi_security_release_secctx =
		(void *)kasumi_lookup_callable_quiet("security_release_secctx");
	if (!kasumi_security_inode_getsecctx || !kasumi_security_inode_notifysecctx)
		pr_info("Kasumi: secctx clone unavailable, vnode SELinux label falls back to default\n");
	kasumi_d_absolute_path = (void *)kasumi_lookup_callable("d_absolute_path");
	kasumi_dentry_path_raw = (void *)kasumi_lookup_callable("dentry_path_raw");
	kasumi_strncpy_from_user_nofault = (void *)kasumi_lookup_callable("strncpy_from_user_nofault");
	if (!kasumi_strncpy_from_user_nofault)
		pr_warn("Kasumi: strncpy_from_user_nofault not found, falling back to copy_from_user\n");
	kasumi_copy_from_user_nofault = (void *)kasumi_lookup_callable("copy_from_user_nofault");
	kasumi_copy_to_user_nofault = (void *)kasumi_lookup_callable("copy_to_user_nofault");
	if (!kasumi_copy_from_user_nofault || !kasumi_copy_to_user_nofault)
		pr_warn("Kasumi: user nofault copy helpers not found, statx mount-id spoof disabled\n");
	kasumi_task_work_add_ptr = (void *)kasumi_lookup_callable_quiet("task_work_add");
	if (!kasumi_task_work_add_ptr) {
		pr_err("Kasumi: FATAL - task_work_add not found\n");
		return -ENOENT;
	}
	kasumi_llist_del_first_ptr =
		(void *)kasumi_lookup_callable("llist_del_first");
	if (!kasumi_llist_del_first_ptr) {
		pr_err("Kasumi: FATAL - llist_del_first not found\n");
		return -ENOENT;
	}
	kasumi_seq_read_iter_ptr =
		(void *)kasumi_lookup_callable_quiet("seq_read_iter");
	if (!kasumi_seq_read_iter_ptr)
		pr_warn("Kasumi: seq_read_iter not found, legacy proc stream fallback disabled\n");
	kasumi_call_srcu_ptr = (void *)kasumi_lookup_callable("call_srcu");
	kasumi_srcu_barrier_ptr = (void *)kasumi_lookup_callable("srcu_barrier");
	if (!kasumi_call_srcu_ptr || !kasumi_srcu_barrier_ptr) {
		pr_err("Kasumi: FATAL - call_srcu/srcu_barrier not found\n");
		return -ENOENT;
	}
	kasumi_synchronize_rcu_tasks_ptr =
		(void *)kasumi_lookup_callable("synchronize_rcu_tasks");
	if (!kasumi_synchronize_rcu_tasks_ptr) {
		pr_err("Kasumi: FATAL - synchronize_rcu_tasks not found\n");
		return -ENOENT;
	}
	kasumi_module_refcount_ptr =
		(void *)kasumi_lookup_callable_quiet("module_refcount");
	if (!kasumi_module_refcount_ptr) {
		pr_err("Kasumi: FATAL - module_refcount not found\n");
		return -ENOENT;
	}
	kasumi_d_path = (void *)kasumi_lookup_callable("d_path");
	kasumi_d_hash_and_lookup = (void *)kasumi_lookup_callable("d_hash_and_lookup");
	kasumi_path_get_ptr = (void *)kasumi_lookup_callable("path_get");
	kasumi_path_put_ptr = (void *)kasumi_lookup_callable("path_put");
	kasumi_free_inode_nonrcu_ptr = (void *)kasumi_lookup_callable("free_inode_nonrcu");
	if (!kasumi_d_path)
		pr_warn("Kasumi: d_path not found, path resolution in populate/merge/hide may fail\n");
	if (!kasumi_d_hash_and_lookup)
		pr_warn("Kasumi: d_hash_and_lookup not found, merge dedup and hide filter disabled\n");
	if (!kasumi_path_get_ptr)
		pr_warn("Kasumi: path_get not found, AT_FDCWD relative redirect disabled\n");
	if (!kasumi_path_put_ptr) {
		pr_err("Kasumi: FATAL - path_put not found\n");
		return -ENOENT;
	}
	if (!kasumi_free_inode_nonrcu_ptr)
		pr_warn("Kasumi: free_inode_nonrcu not found, sop fallback disabled\n");
	if (!kasumi_vfs_getattr || !kasumi_dentry_open)
		pr_warn("Kasumi: vfs_getattr/dentry_open not found, merge whiteout/iterate disabled\n");
	if (!kasumi_vfs_path_lookup)
		pr_warn("Kasumi: vfs_path_lookup not found, virtual directory descendants disabled\n");
	if (!kasumi_lookup_one_len || !kasumi_vfs_mkdir || !kasumi_vfs_unlink ||
	    !kasumi_vfs_create)
		pr_warn("Kasumi: dir-mutation delegates unavailable, create/remove inside a redirected directory disabled\n");
	if (!kasumi_vfs_getxattr_addr || !kasumi_vfs_listxattr_addr ||
	    !kasumi_vfs_setxattr_addr || !kasumi_vfs_removexattr_addr ||
	    !kasumi_mnt_want_write_addr || !kasumi_mnt_drop_write_addr)
		pr_warn("Kasumi: captured xattr helpers unavailable\n");
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

	if (!kasumi_skip_kallsyms_param)
		kasumi_resolve_kallsyms_lookup();
	else
		pr_alert("Kasumi: skipping kallsyms (using per-symbol kprobe)\n");

	kasumi_root_detect();

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
	kasumi_iterate_buf_base = vmalloc(nr_cpu_ids * KASUMI_ITERATE_PATH_BUF);
	if (!kasumi_percpu_base || !kasumi_iterate_buf_base) {
		ret = -ENOMEM;
		pr_err("Kasumi: failed to allocate per-CPU buffers\n");
		goto err_buffers;
	}
	memset(kasumi_percpu_base, 0, nr_cpu_ids * sizeof(struct kasumi_percpu));

	kasumi_resolve_system_dev();

	ret = kasumi_fake_mi_init();
	if (ret)
		pr_warn("Kasumi: fake mountinfo unavailable: %d\n", ret);

	ret = kasumi_proc_hooks_init(0, kasumi_no_tracepoint_param, 0);
	if (ret)
		goto err_redirect;

	ret = kasumi_vfs_hooks_init(0);
	if (ret)
		goto err_active;

	(void)kasumi_iop_override_init();
	ret = kasumi_fop_bridge_init();
	if (ret) {
		pr_err("Kasumi: FATAL - old-KMI fops bridge unavailable: %d\n",
		       ret);
		goto err_fop_bridge;
	}
	(void)kasumi_fop_override_init();
	(void)kasumi_dirhijack_init();

	/* On old KMI, the first ingress table published below is the module-init
	 * commit point: bridge-open files may already pin THIS_MODULE. Keep every
	 * later initialization step non-fatal.
	 */
	(void)kasumi_fake_selinuxfs_access_init();
	if (kasumi_bootstrap_quiesce_supported()) {
		__module_get(THIS_MODULE);
		WRITE_ONCE(kasumi_unload_pin_held, true);
	}
	kasumi_proc_hooks_start();
	pr_alert("Kasumi: Chikyuu ga buttobu kurai tanoshinjaoo!!\n");
	return 0;

err_fop_bridge:
	kasumi_fop_bridge_exit();
	kasumi_iop_override_exit();
	kasumi_vfs_hooks_exit(0);
err_active:
	kasumi_proc_hooks_exit();
	kasumi_fake_mi_exit();
	goto err_buffers;
err_redirect:
	kasumi_fake_mi_exit();
err_buffers:
	vfree(kasumi_percpu_base);
	vfree(kasumi_iterate_buf_base);
	kasumi_percpu_base = NULL;
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
	WARN_ON_ONCE(READ_ONCE(kasumi_unload_pin_held));

	/*
	 * The path view is served entirely through the VFS lookup/vnode layer and
	 * the proc/mountinfo kprobes; there is no syscall dispatcher or sys_enter
	 * tracepoint to sever.  Tear down handler-reachable state directly: free
	 * the resources those VFS/proc hooks depend on (proc fd proxies, fake
	 * mountinfo, fop/iop shadows, vfs hooks).
	 */
	kasumi_proc_hooks_exit();
	kasumi_vfs_hooks_exit(0);
	kasumi_fake_selinuxfs_access_stop_new();
	kasumi_fop_override_stop_new();
	kasumi_fop_bridge_stop_new();
	kasumi_fake_selinuxfs_access_exit();
	kasumi_fop_override_exit();
	kasumi_fop_bridge_exit();
	kasumi_iop_override_exit();
	kasumi_dirhijack_exit();
	kasumi_fake_mi_exit();
	mutex_lock(&kasumi_config_mutex);
	kasumi_cleanup_locked();
	kasumi_policy_shutdown_locked();
	old_cmdline = rcu_dereference_protected(kasumi_spoof_cmdline_ptr,
						lockdep_is_held(&kasumi_config_mutex));
	rcu_assign_pointer(kasumi_spoof_cmdline_ptr, NULL);
	mutex_unlock(&kasumi_config_mutex);

	rcu_barrier();
	kfree(old_cmdline);
	if (kasumi_filldir_cache)
		kmem_cache_destroy(kasumi_filldir_cache);
	vfree(kasumi_percpu_base);
	vfree(kasumi_iterate_buf_base);
	kasumi_percpu_base = NULL;
	kasumi_iterate_buf_base = NULL;
	pr_alert("Kasumi: Goseichou thank you!!!\n");
}
