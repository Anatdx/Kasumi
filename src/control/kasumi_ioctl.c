/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - userspace control plane, ioctl dispatch, and daemon-facing anon-fd setup.
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
#include <linux/mount.h>
#include <linux/xattr.h>
#include <linux/seq_file.h>
#include <uapi/linux/magic.h>
#ifndef EROFS_SUPER_MAGIC
#define EROFS_SUPER_MAGIC 0xe0f5e1e2
#endif
#include <asm/unistd.h>
#include "kasumi_runtime.h"
#include "kasumi_bootstrap.h"
#include "kasumi_store.h"
#include "kasumi_entrypoints.h"
#include "kasumi_path_policy.h"
#include "kasumi_overlay.h"
#include "kasumi_syscall_redirect.h"
#include "kasumi_task_marker.h"
#include "kasumi_tracepoint_hooks.h"
#include "kasumi_proc_hooks.h"
#include "kasumi_vfs_hooks.h"
#include "kasumi_file_view.h"
#include "kasumi_fop_bridge.h"
#include "kasumi_iop_override.h"
#include "kasumi_fop_override.h"
#include "kasumi_fake_mountinfo.h"
#include "kasumi_fake_selinuxfs_access.h"
/* ======================================================================
 * Part 15: Dispatch Handler (ioctl only; all commands use KSM_IOC_* from kasumi_uapi.h)
 * GET_FD is delivered by reboot task_work -> kasumi_install_anon_fd()
 * ====================================================================== */

static bool kasumi_policy_header_valid(u32 version, u32 size, size_t min_size)
{
	return version == KSM_POLICY_API_VERSION && size >= min_size;
}

static bool kasumi_u32_reserved_zero(const u32 *reserved, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		if (reserved[i])
			return false;
	return true;
}

static int kasumi_ioctl_set_policy(void __user *arg)
{
	struct kasumi_policy_config_arg a;
	int ret;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (!kasumi_policy_header_valid(a.version, a.size, sizeof(a)) ||
	    !kasumi_u32_reserved_zero(a.reserved, ARRAY_SIZE(a.reserved)))
		ret = -EINVAL;
	else
		ret = kasumi_set_policy_owner(a.owner, a.flags);
	a.err = ret;
	if (copy_to_user(arg, &a, sizeof(a)))
		return -EFAULT;
	return ret;
}

static int kasumi_ioctl_get_policy(void __user *arg)
{
	struct kasumi_policy_state_arg input;
	struct kasumi_policy_state_arg a = { };
	int ret = 0;

	if (copy_from_user(&input, arg, sizeof(input)))
		return -EFAULT;
	if (!kasumi_policy_header_valid(input.version, input.size,
					sizeof(input)) ||
	    input.enabled ||
	    !kasumi_u32_reserved_zero(input.reserved,
				      ARRAY_SIZE(input.reserved)))
		ret = -EINVAL;
	else
		kasumi_policy_get_state(&a);
	a.version = KSM_POLICY_API_VERSION;
	a.size = sizeof(a);
	a.err = ret;
	if (copy_to_user(arg, &a, sizeof(a)))
		return -EFAULT;
	return ret;
}

static int kasumi_ioctl_set_policy_uids(void __user *arg)
{
	struct kasumi_policy_uid_list_arg a;
	u32 *uids = NULL;
	int ret;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (!kasumi_policy_header_valid(a.version, a.size, sizeof(a)) ||
	    a.reserved || a.generation || a.total ||
	    (!a.count && a.uids)) {
		ret = -EINVAL;
		goto out;
	}
	if (a.count > KASUMI_ALLOWLIST_UID_MAX) {
		ret = -E2BIG;
		goto out;
	}
	if (a.count) {
		if (!a.uids) {
			ret = -EINVAL;
			goto out;
		}
		uids = kmalloc_array(a.count, sizeof(*uids), GFP_KERNEL);
		if (!uids) {
			ret = -ENOMEM;
			goto out;
		}
		if (copy_from_user(uids,
				   (const void __user *)(unsigned long)a.uids,
				   a.count * sizeof(*uids))) {
			ret = -EFAULT;
			goto out;
		}
	}
	ret = kasumi_replace_policy_uid_list(a.list, uids, a.count);
	if (!ret) {
		u32 copied;

		ret = kasumi_policy_copy_uids(a.list, NULL, 0, &copied,
					      &a.total, &a.generation);
	}

out:
	a.version = KSM_POLICY_API_VERSION;
	a.size = sizeof(a);
	a.err = ret;
	if (copy_to_user(arg, &a, sizeof(a)))
		ret = -EFAULT;
	kfree(uids);
	return ret;
}

static int kasumi_ioctl_clear_policy_uids(void __user *arg)
{
	struct kasumi_policy_uid_list_arg a;
	int ret;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (!kasumi_policy_header_valid(a.version, a.size, sizeof(a)) ||
	    a.reserved || a.generation || a.count || a.total || a.uids)
		ret = -EINVAL;
	else
		ret = kasumi_clear_policy_uid_list(a.list);
	a.count = 0;
	a.total = 0;
	if (!ret) {
		struct kasumi_policy_state_arg state = { };

		kasumi_policy_get_state(&state);
		a.generation = state.generation;
	}
	a.version = KSM_POLICY_API_VERSION;
	a.size = sizeof(a);
	a.err = ret;
	if (copy_to_user(arg, &a, sizeof(a)))
		return -EFAULT;
	return ret;
}

static int kasumi_ioctl_get_policy_uids(void __user *arg)
{
	struct kasumi_policy_uid_list_arg input;
	struct kasumi_policy_uid_list_arg a = { };
	u32 *uids = NULL;
	u32 copied = 0;
	u32 total = 0;
	u64 generation = 0;
	int ret = 0;

	if (copy_from_user(&input, arg, sizeof(input)))
		return -EFAULT;
	if (!kasumi_policy_header_valid(input.version, input.size,
					sizeof(input)) || input.reserved ||
	    input.generation || input.total || (!input.count && input.uids)) {
		ret = -EINVAL;
		goto out;
	}
	if (input.count > KASUMI_ALLOWLIST_UID_MAX) {
		ret = -E2BIG;
		goto out;
	}
	if (input.count && !input.uids) {
		ret = -EINVAL;
		goto out;
	}
	if (input.count) {
		uids = kmalloc_array(input.count, sizeof(*uids), GFP_KERNEL);
		if (!uids) {
			ret = -ENOMEM;
			goto out;
		}
	}
	ret = kasumi_policy_copy_uids(input.list, uids, input.count,
				      &copied, &total, &generation);
	if (!ret && copied &&
	    copy_to_user((void __user *)(unsigned long)input.uids, uids,
			 copied * sizeof(*uids)))
		ret = -EFAULT;

out:
	a.version = KSM_POLICY_API_VERSION;
	a.size = sizeof(a);
	a.list = input.list;
	a.count = copied;
	a.total = total;
	a.uids = input.uids;
	a.generation = generation;
	a.err = ret;
	kfree(uids);
	if (copy_to_user(arg, &a, sizeof(a)))
		return -EFAULT;
	return ret;
}

static int kasumi_ioctl_replace_policy(void __user *arg)
{
	struct kasumi_policy_replace_arg a;
	u32 *allow_uids = NULL;
	u32 *deny_uids = NULL;
	int ret;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (!kasumi_policy_header_valid(a.version, a.size, sizeof(a)) ||
	    !kasumi_u32_reserved_zero(a.reserved, ARRAY_SIZE(a.reserved))) {
		ret = -EINVAL;
		goto out;
	}
	if (a.allow_count > KASUMI_ALLOWLIST_UID_MAX ||
	    a.deny_count > KASUMI_ALLOWLIST_UID_MAX) {
		ret = -E2BIG;
		goto out;
	}
	if ((a.allow_count && !a.allow_uids) ||
	    (a.deny_count && !a.deny_uids) ||
	    (!a.allow_count && a.allow_uids) ||
	    (!a.deny_count && a.deny_uids)) {
		ret = -EINVAL;
		goto out;
	}
	if (a.allow_count) {
		allow_uids = kmalloc_array(a.allow_count, sizeof(*allow_uids),
					   GFP_KERNEL);
		if (!allow_uids) {
			ret = -ENOMEM;
			goto out;
		}
		if (copy_from_user(allow_uids,
				   (const void __user *)(unsigned long)a.allow_uids,
				   a.allow_count * sizeof(*allow_uids))) {
			ret = -EFAULT;
			goto out;
		}
	}
	if (a.deny_count) {
		deny_uids = kmalloc_array(a.deny_count, sizeof(*deny_uids),
					  GFP_KERNEL);
		if (!deny_uids) {
			ret = -ENOMEM;
			goto out;
		}
		if (copy_from_user(deny_uids,
				   (const void __user *)(unsigned long)a.deny_uids,
				   a.deny_count * sizeof(*deny_uids))) {
			ret = -EFAULT;
			goto out;
		}
	}
	ret = kasumi_policy_replace(a.owner, a.flags, allow_uids, a.allow_count,
				    deny_uids, a.deny_count);

out:
	a.version = KSM_POLICY_API_VERSION;
	a.size = sizeof(a);
	a.err = ret;
	if (copy_to_user(arg, &a, sizeof(a)))
		ret = -EFAULT;
	kfree(allow_uids);
	kfree(deny_uids);
	return ret;
}

static int kasumi_ioctl_reset_policy(void __user *arg)
{
	struct kasumi_policy_config_arg a;
	int ret;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (!kasumi_policy_header_valid(a.version, a.size, sizeof(a)) ||
	    a.owner || a.flags ||
	    !kasumi_u32_reserved_zero(a.reserved, ARRAY_SIZE(a.reserved)))
		ret = -EINVAL;
	else
		ret = kasumi_policy_reset();
	a.owner = KSM_POLICY_OWNER_AUTO;
	a.flags = 0;
	a.version = KSM_POLICY_API_VERSION;
	a.size = sizeof(a);
	a.err = ret;
	if (copy_to_user(arg, &a, sizeof(a)))
		return -EFAULT;
	return ret;
}

static KASUMI_NOCFI int kasumi_dispatch_cmd(unsigned int cmd, void __user *arg)
{
	struct kasumi_syscall_arg req;
	struct kasumi_entry *entry;
	struct kasumi_hide_entry *hide_entry;
	struct kasumi_inject_entry *inject_entry;
	char *src = NULL, *target = NULL;
	u32 hash;
	bool found = false;
	int ret = 0;

	if (cmd == KSM_IOC_CLEAR_ALL) {
		mutex_lock(&kasumi_config_mutex);
		kasumi_cleanup_locked();
		strscpy(kasumi_mirror_path_buf, KASUMI_DEFAULT_MIRROR_PATH, PATH_MAX);
		strscpy(kasumi_mirror_name_buf, KASUMI_DEFAULT_MIRROR_NAME, NAME_MAX);
		kasumi_current_mirror_path = kasumi_mirror_path_buf;
		kasumi_current_mirror_name = kasumi_mirror_name_buf;
		mutex_unlock(&kasumi_config_mutex);
		kasumi_fake_mi_invalidate_all();
		rcu_barrier();
		return 0;
	}

	if (cmd == KSM_IOC_GET_VERSION) {
		int ver = KSM_PROTOCOL_VERSION;
		if (copy_to_user(arg, &ver, sizeof(ver)))
			return -EFAULT;
		return 0;
	}

	if (cmd == KSM_IOC_SET_POLICY)
		return kasumi_ioctl_set_policy(arg);
	if (cmd == KSM_IOC_GET_POLICY)
		return kasumi_ioctl_get_policy(arg);
	if (cmd == KSM_IOC_SET_POLICY_UIDS)
		return kasumi_ioctl_set_policy_uids(arg);
	if (cmd == KSM_IOC_CLEAR_POLICY_UIDS)
		return kasumi_ioctl_clear_policy_uids(arg);
	if (cmd == KSM_IOC_GET_POLICY_UIDS)
		return kasumi_ioctl_get_policy_uids(arg);
	if (cmd == KSM_IOC_REPLACE_POLICY)
		return kasumi_ioctl_replace_policy(arg);
	if (cmd == KSM_IOC_RESET_POLICY)
		return kasumi_ioctl_reset_policy(arg);

	if (cmd == KSM_IOC_SET_DEBUG) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		kasumi_debug_enabled = !!val;
		kasumi_log("debug mode %s\n", kasumi_debug_enabled ? "enabled" : "disabled");
		return 0;
	}

	if (cmd == KSM_IOC_SET_STEALTH) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		kasumi_stealth_enabled = !!val;
		kasumi_log("stealth mode %s\n", kasumi_stealth_enabled ? "enabled" : "disabled");
		return 0;
	}

	if (cmd == KSM_IOC_SET_ENABLED) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		if (val) {
			if (kasumi_policy_view_tsr_demand() &&
			    (!kasumi_tracepoint_hooks_available() ||
			     !kasumi_task_marker_ready()))
				return -ENODEV;
			mutex_lock(&kasumi_config_mutex);
			if (READ_ONCE(kasumi_enabled)) {
				if (kasumi_policy_view_tsr_demand()) {
					if (kasumi_tracepoint_hooks_set_enabled(true)) {
						mutex_unlock(&kasumi_config_mutex);
						return -ENODEV;
					}
					kasumi_task_marker_refresh_scopes();
				} else {
					(void)kasumi_tracepoint_hooks_set_enabled(false);
				}
				mutex_unlock(&kasumi_config_mutex);
				return 0;
			}
			if (!kasumi_policy_prepare_enable_locked()) {
				mutex_unlock(&kasumi_config_mutex);
				return -ENODEV;
			}
			if (kasumi_policy_view_tsr_demand() &&
			    kasumi_tracepoint_hooks_set_enabled(true)) {
				kasumi_policy_disable_provider_locked();
				mutex_unlock(&kasumi_config_mutex);
				return -ENODEV;
			}
			/* The lifecycle marker also applies non-TSR scoped spoof state. */
			kasumi_task_marker_set_enabled(true);
			/* Publish provider state and completed task scan together. */
			smp_store_release(&kasumi_enabled, true);
			mutex_unlock(&kasumi_config_mutex);
		} else {
			mutex_lock(&kasumi_config_mutex);
			if (!READ_ONCE(kasumi_enabled) &&
			    !kasumi_task_marker_active()) {
				mutex_unlock(&kasumi_config_mutex);
				return 0;
			}
			/* Stop policy readers before provider pointers are withdrawn. */
			smp_store_release(&kasumi_enabled, false);
			kasumi_task_marker_set_enabled(false);
			(void)kasumi_tracepoint_hooks_set_enabled(false);
			kasumi_policy_disable_provider_locked();
			mutex_unlock(&kasumi_config_mutex);
		}
		kasumi_log("Kasumi %s\n", READ_ONCE(kasumi_enabled) ?
			   "enabled" : "disabled");
		return 0;
	}

	if (cmd == KSM_IOC_REORDER_MNT_ID) {
		/* struct mnt_namespace/mount not exposed to LKM; only KPM (built-in) supports this */
		return -EOPNOTSUPP;
	}

	if (cmd == KSM_IOC_LIST_RULES) {
		struct kasumi_syscall_list_arg list_arg;
		struct kasumi_xattr_sb_entry *sb_entry;
		struct kasumi_merge_entry *merge_entry;
		char *kbuf;
		size_t buf_size, written = 0;
		int bkt;

		if (copy_from_user(&list_arg, arg, sizeof(list_arg)))
			return -EFAULT;

		buf_size = list_arg.size;
		if (buf_size > 64 * 1024)
			buf_size = 64 * 1024;

		kbuf = kzalloc(buf_size, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;

		rcu_read_lock();
		written += scnprintf(kbuf + written, buf_size - written,
				     "Kasumi Protocol: %d\n", KSM_PROTOCOL_VERSION);
		written += scnprintf(kbuf + written, buf_size - written,
				     "Kasumi Enabled: %d\n", kasumi_enabled ? 1 : 0);
		hash_for_each_rcu(kasumi_paths, bkt, entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "add %s %s %d\n", entry->src,
					     entry->target, entry->type);
		}
		hash_for_each_rcu(kasumi_hide_paths, bkt, hide_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "hide %s\n", hide_entry->path);
		}
		hash_for_each_rcu(kasumi_inject_dirs, bkt, inject_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "inject %s\n", inject_entry->dir);
		}
		hash_for_each_rcu(kasumi_merge_dirs, bkt, merge_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "merge %s %s\n", merge_entry->src,
					     merge_entry->target);
		}
		hash_for_each_rcu(kasumi_xattr_sbs, bkt, sb_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "hide_xattr_sb %p\n", sb_entry->sb);
		}
		/* Feature rules: mount_hide, maps_spoof, statfs_spoof, selinux_fix, stealth */
		if (kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "mount_hide enabled mode=%s\n",
						     READ_ONCE(kasumi_mount_hide_mode) ==
							     KSM_MOUNT_HIDE_MODE_AGGRESSIVE ?
							     "aggressive" : "normal");
		}
		if (kasumi_feature_enabled_mask & KSM_FEATURE_MAPS_SPOOF) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "maps_spoof enabled\n");
		}
		if (kasumi_feature_enabled_mask & KSM_FEATURE_STATFS_SPOOF) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "statfs_spoof enabled\n");
		}
		if (kasumi_feature_enabled_mask & KSM_FEATURE_SELINUX_FIX) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "selinux_fix enabled\n");
		}
		if (kasumi_stealth_enabled) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "stealth enabled\n");
		}
		rcu_read_unlock();

		if (copy_to_user(list_arg.buf, kbuf, written)) {
			kfree(kbuf);
			return -EFAULT;
		}
		list_arg.size = written;
		if (copy_to_user(arg, &list_arg, sizeof(list_arg))) {
			kfree(kbuf);
			return -EFAULT;
		}
		kfree(kbuf);
		return 0;
	}

	if (cmd == KSM_IOC_SET_MIRROR_PATH) {
		char *new_path, *new_name, *slash;
		size_t len;

		if (copy_from_user(&req, arg, sizeof(req)))
			return -EFAULT;
		if (!req.src)
			return -EINVAL;
		new_path = kasumi_strndup_user(req.src, PATH_MAX);
		if (IS_ERR(new_path))
			return PTR_ERR(new_path);

		len = strlen(new_path);
		if (len > 1 && new_path[len - 1] == '/')
			new_path[len - 1] = '\0';

		slash = strrchr(new_path, '/');
		new_name = kstrdup(slash ? slash + 1 : new_path, GFP_KERNEL);
		if (!new_name) {
			kfree(new_path);
			return -ENOMEM;
		}

		mutex_lock(&kasumi_config_mutex);
		strscpy(kasumi_mirror_path_buf, new_path, PATH_MAX);
		strscpy(kasumi_mirror_name_buf, new_name, NAME_MAX);
		kasumi_current_mirror_path = kasumi_mirror_path_buf;
		kasumi_current_mirror_name = kasumi_mirror_name_buf;
		mutex_unlock(&kasumi_config_mutex);

		kasumi_log("setting mirror path to: %s\n", kasumi_mirror_path_buf);
		kfree(new_path);
		kfree(new_name);
		return 0;
	}

	if (cmd == KSM_IOC_SET_CMDLINE) {
		struct kasumi_spoof_cmdline *c = kmalloc(sizeof(*c), GFP_KERNEL);
		struct kasumi_cmdline_rcu *new_cmdline, *old_cmdline;

		if (!c)
			return -ENOMEM;
		if (copy_from_user(c, arg, sizeof(*c))) {
			kfree(c);
			return -EFAULT;
		}
		new_cmdline = kmalloc(sizeof(*new_cmdline), GFP_KERNEL);
		if (!new_cmdline) {
			kfree(c);
			return -ENOMEM;
		}
		strscpy(new_cmdline->cmdline, c->cmdline, sizeof(new_cmdline->cmdline));
		mutex_lock(&kasumi_config_mutex);
		old_cmdline = rcu_dereference_protected(kasumi_spoof_cmdline_ptr,
							lockdep_is_held(&kasumi_config_mutex));
		rcu_assign_pointer(kasumi_spoof_cmdline_ptr, new_cmdline);
		mutex_unlock(&kasumi_config_mutex);
		if (old_cmdline)
			kfree_rcu(old_cmdline, rcu);
		kasumi_cmdline_spoof_active = (c->cmdline[0] != '\0');
		kfree(c);
		if (kasumi_cmdline_spoof_active)
			kasumi_log("cmdline: spoofed\n");
		return 0;
	}

	if (cmd == KSM_IOC_ADD_SPOOF_KSTAT || cmd == KSM_IOC_UPDATE_SPOOF_KSTAT) {
		struct kasumi_spoof_kstat __user *u = (struct kasumi_spoof_kstat __user *)arg;
		struct kasumi_spoof_kstat *k;
		struct kasumi_spoof_kstat_entry *e, *existing = NULL;
		size_t plen;
		u32 phash = 0;
		bool have_path;
		struct path resolved;
		unsigned long auto_ino = 0;

		k = kmalloc(sizeof(*k), GFP_KERNEL);
		if (!k)
			return -ENOMEM;
		if (copy_from_user(k, u, sizeof(*k))) {
			kfree(k);
			return -EFAULT;
		}
		k->target_pathname[KSM_MAX_LEN_PATHNAME - 1] = '\0';
		have_path = (k->target_pathname[0] != '\0');

		/* Auto-resolve target_ino from path if userspace did not supply one. */
		if (have_path && k->target_ino == 0 && kasumi_kern_path) {
			if (kasumi_kern_path(k->target_pathname, LOOKUP_FOLLOW, &resolved) == 0) {
				if (resolved.dentry && d_inode(resolved.dentry)) {
					struct inode *inode = d_inode(resolved.dentry);

					auto_ino = (unsigned long)inode->i_ino;
					(void)kasumi_iop_mark_spoof(inode);
				}
				kasumi_path_put(&resolved);
			}
			if (auto_ino)
				k->target_ino = auto_ino;
		}
		if (have_path && k->target_ino != 0 && kasumi_kern_path) {
			if (kasumi_kern_path(k->target_pathname, LOOKUP_FOLLOW, &resolved) == 0) {
				if (resolved.dentry && d_inode(resolved.dentry))
					(void)kasumi_iop_mark_spoof(d_inode(resolved.dentry));
				kasumi_path_put(&resolved);
			}
		}

		if (!have_path && !k->target_ino) {
			k->err = -EINVAL;
			(void)copy_to_user(u, k, sizeof(*k));
			kfree(k);
			return -EINVAL;
		}

		if (have_path) {
			plen = strlen(k->target_pathname);
			phash = full_name_hash(NULL, k->target_pathname, plen);
		}

		mutex_lock(&kasumi_config_mutex);

		/* Look for existing entry by path, then by ino. */
		if (have_path) {
			hlist_for_each_entry(e,
				&kasumi_spoof_kstat_path[hash_min(phash, KASUMI_HASH_BITS)], path_node) {
				if (e->path_hash == phash && e->target_pathname &&
				    strcmp(e->target_pathname, k->target_pathname) == 0) {
					existing = e;
					break;
				}
			}
		}
		if (!existing && k->target_ino) {
			hlist_for_each_entry(e,
				&kasumi_spoof_kstat_ino[hash_min(k->target_ino, KASUMI_HASH_BITS)],
				ino_node) {
				if (e->target_ino == k->target_ino &&
				    e->target_dev == 0) {
					existing = e;
					break;
				}
			}
		}

		if (existing && cmd == KSM_IOC_ADD_SPOOF_KSTAT) {
			/* Idempotent ADD: treat as UPDATE. */
		}

		if (!existing) {
			e = kzalloc(sizeof(*e), GFP_KERNEL);
			if (!e) {
				mutex_unlock(&kasumi_config_mutex);
				k->err = -ENOMEM;
				(void)copy_to_user(u, k, sizeof(*k));
				kfree(k);
				return -ENOMEM;
			}
			if (have_path) {
				e->target_pathname = kstrdup(k->target_pathname, GFP_KERNEL);
				if (!e->target_pathname) {
					kfree(e);
					mutex_unlock(&kasumi_config_mutex);
					k->err = -ENOMEM;
					(void)copy_to_user(u, k, sizeof(*k));
					kfree(k);
					return -ENOMEM;
				}
				e->path_hash = phash;
			}
			e->target_ino = k->target_ino;
			e->target_dev = 0;
			e->spoofed_ino     = k->spoofed_ino;
			e->spoofed_dev     = k->spoofed_dev;
			e->spoofed_nlink   = k->spoofed_nlink;
			e->spoofed_size    = k->spoofed_size;
			e->spoofed_atime_sec  = k->spoofed_atime_sec;
			e->spoofed_atime_nsec = k->spoofed_atime_nsec;
			e->spoofed_mtime_sec  = k->spoofed_mtime_sec;
			e->spoofed_mtime_nsec = k->spoofed_mtime_nsec;
			e->spoofed_ctime_sec  = k->spoofed_ctime_sec;
			e->spoofed_ctime_nsec = k->spoofed_ctime_nsec;
			e->spoofed_blksize = k->spoofed_blksize;
			e->spoofed_blocks  = k->spoofed_blocks;
			e->is_static       = k->is_static;

			if (have_path)
				hlist_add_head_rcu(&e->path_node,
					&kasumi_spoof_kstat_path[hash_min(phash, KASUMI_HASH_BITS)]);
			if (e->target_ino)
				hlist_add_head_rcu(&e->ino_node,
					&kasumi_spoof_kstat_ino[hash_min(e->target_ino, KASUMI_HASH_BITS)]);
			atomic_inc(&kasumi_spoof_kstat_count);
			kasumi_log("spoof_kstat: add path=%s ino=%lu->%lu\n",
				 have_path ? k->target_pathname : "(none)",
				 e->target_ino, e->spoofed_ino);
		} else {
			/* Update fields in place; readers may see torn values
			 * briefly, acceptable for stat() spoof. */
			existing->spoofed_ino     = k->spoofed_ino;
			existing->spoofed_dev     = k->spoofed_dev;
			existing->spoofed_nlink   = k->spoofed_nlink;
			existing->spoofed_size    = k->spoofed_size;
			existing->spoofed_atime_sec  = k->spoofed_atime_sec;
			existing->spoofed_atime_nsec = k->spoofed_atime_nsec;
			existing->spoofed_mtime_sec  = k->spoofed_mtime_sec;
			existing->spoofed_mtime_nsec = k->spoofed_mtime_nsec;
			existing->spoofed_ctime_sec  = k->spoofed_ctime_sec;
			existing->spoofed_ctime_nsec = k->spoofed_ctime_nsec;
			existing->spoofed_blksize = k->spoofed_blksize;
			existing->spoofed_blocks  = k->spoofed_blocks;
			existing->is_static       = k->is_static;

			/* If newly-resolved ino became available, link into ino table. */
			if (existing->target_ino == 0 && k->target_ino) {
				existing->target_ino = k->target_ino;
				hlist_add_head_rcu(&existing->ino_node,
					&kasumi_spoof_kstat_ino[hash_min(k->target_ino, KASUMI_HASH_BITS)]);
			}
			kasumi_log("spoof_kstat: update path=%s ino=%lu->%lu\n",
				 have_path ? k->target_pathname : "(none)",
				 existing->target_ino, existing->spoofed_ino);
		}

		mutex_unlock(&kasumi_config_mutex);

		k->err = 0;
		if (copy_to_user(u, k, sizeof(*k))) {
			kfree(k);
			return -EFAULT;
		}
		kfree(k);
		return 0;
	}

	if (cmd == KSM_IOC_ADD_MAPS_RULE) {
		struct kasumi_maps_rule __user *u = (struct kasumi_maps_rule __user *)arg;
		struct kasumi_maps_rule k;
		struct kasumi_maps_rule_entry *e;

		if (copy_from_user(&k, u, sizeof(k)))
			return -EFAULT;
		e = kmalloc(sizeof(*e), GFP_KERNEL);
		if (!e) {
			k.err = -ENOMEM;
			if (copy_to_user(u, &k, sizeof(k)))
				return -EFAULT;
			return -ENOMEM;
		}
		e->target_ino = k.target_ino;
		e->target_dev = k.target_dev;
		e->spoofed_ino = k.spoofed_ino;
		e->spoofed_dev = k.spoofed_dev;
		strscpy(e->spoofed_pathname, k.spoofed_pathname, sizeof(e->spoofed_pathname));
		k.err = 0;
		if (copy_to_user(u, &k, sizeof(k))) {
			kfree(e);
			return -EFAULT;
		}
		mutex_lock(&kasumi_maps_mutex);
		list_add_tail(&e->list, &kasumi_maps_rules);
		mutex_unlock(&kasumi_maps_mutex);
		return 0;
	}

	if (cmd == KSM_IOC_CLEAR_MAPS_RULES) {
		struct kasumi_maps_rule_entry *e, *tmp;

		mutex_lock(&kasumi_maps_mutex);
		list_for_each_entry_safe(e, tmp, &kasumi_maps_rules, list) {
			list_del(&e->list);
			kfree(e);
		}
		mutex_unlock(&kasumi_maps_mutex);
		return 0;
	}

	if (cmd == KSM_IOC_SET_MOUNT_HIDE) {
		struct kasumi_mount_hide_arg a;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.enable)
			kasumi_feature_enabled_mask |= KSM_FEATURE_MOUNT_HIDE;
		else
			kasumi_feature_enabled_mask &= ~KSM_FEATURE_MOUNT_HIDE;
		kasumi_fake_mi_invalidate_all();
		/* path_pattern reserved for future custom hide rules */
		return 0;
	}

	if (cmd == KSM_IOC_SET_MOUNT_HIDE_MODE) {
		int mode;

		if (copy_from_user(&mode, arg, sizeof(mode)))
			return -EFAULT;
		if (mode != KSM_MOUNT_HIDE_MODE_NORMAL &&
		    mode != KSM_MOUNT_HIDE_MODE_AGGRESSIVE)
			return -EINVAL;
		if (mode == KSM_MOUNT_HIDE_MODE_AGGRESSIVE &&
		    (!kasumi_proc_proxy_registered ||
		     !kasumi_proc_ns_readlink_registered ||
		     !kasumi_fake_mi_active()))
			return -EOPNOTSUPP;
		WRITE_ONCE(kasumi_mount_hide_mode, mode);
		kasumi_fake_mi_invalidate_all();
		return 0;
	}

	if (cmd == KSM_IOC_SET_MAPS_SPOOF) {
		struct kasumi_maps_spoof_arg a;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.enable)
			kasumi_feature_enabled_mask |= KSM_FEATURE_MAPS_SPOOF;
		else
			kasumi_feature_enabled_mask &= ~KSM_FEATURE_MAPS_SPOOF;
		/* reserved for future inline rule */
		return 0;
	}

	if (cmd == KSM_IOC_SET_STATFS_SPOOF) {
		struct kasumi_statfs_spoof_arg a;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.enable)
			kasumi_feature_enabled_mask |= KSM_FEATURE_STATFS_SPOOF;
		else
			kasumi_feature_enabled_mask &= ~KSM_FEATURE_STATFS_SPOOF;
		/* path/spoof_f_type reserved for future custom mappings */
		return 0;
	}

	if (cmd == KSM_IOC_SELINUX_FIX) {
		int enable;

		if (copy_from_user(&enable, arg, sizeof(enable)))
			return -EFAULT;
		if (enable)
			kasumi_feature_enabled_mask |= KSM_FEATURE_SELINUX_FIX;
		else
			kasumi_feature_enabled_mask &= ~KSM_FEATURE_SELINUX_FIX;
		return 0;
	}

	if (cmd == KSM_IOC_GET_FEATURES) {
		int features = kasumi_bootstrap_quiesce_supported() ?
			KSM_FEATURE_QUIESCE : 0;
		if (kasumi_cmdline_kprobe_registered)
			features |= KSM_FEATURE_CMDLINE_SPOOF;
		features |= KSM_FEATURE_KSTAT_SPOOF;
		features |= KSM_FEATURE_MERGE_DIR;
		if (kasumi_getxattr_kprobe_registered)
			features |= KSM_FEATURE_SELINUX_BYPASS;
		if (kasumi_proc_proxy_registered ||
		    kasumi_mount_hide_vfsmnt_registered ||
		    kasumi_mount_hide_mountinfo_registered)
			features |= KSM_FEATURE_MOUNT_HIDE;
		if (kasumi_proc_proxy_registered && kasumi_fake_mi_active())
			features |= KSM_FEATURE_FAKE_MOUNTINFO;
		if (kasumi_proc_proxy_registered &&
		    kasumi_proc_ns_readlink_registered &&
		    kasumi_fake_mi_active())
			features |= KSM_FEATURE_MOUNT_HIDE_AGGRESSIVE;
		if (kasumi_proc_proxy_registered)
			features |= KSM_FEATURE_MAPS_SPOOF;
		if (kasumi_statfs_kretprobe_registered)
			features |= KSM_FEATURE_STATFS_SPOOF;
		if (kasumi_fake_selinuxfs_access_active() ||
		    kasumi_fake_selinuxfs_proc_attr_active())
			features |= KSM_FEATURE_SELINUX_FIX;
		if (copy_to_user(arg, &features, sizeof(features)))
			return -EFAULT;
		return 0;
	}

	if (cmd == KSM_IOC_GET_HOOKS) {
		struct kasumi_syscall_list_arg list_arg;
		char *kbuf;
		size_t buf_size, written = 0;
		int n;
		bool path_tsr = false;
		bool xattr_path_tsr = false;

		if (copy_from_user(&list_arg, arg, sizeof(list_arg)))
			return -EFAULT;

		buf_size = list_arg.size;
		if (buf_size > 4096)
			buf_size = 4096;

		kbuf = kzalloc(buf_size, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;

		/* GET_FD */
		if (kasumi_reboot_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "GET_FD: kprobe (reboot nr=%d)\n", __NR_reboot);
		else
			n = scnprintf(kbuf + written, buf_size - written, "GET_FD: none\n");
		written += n;

		/* Path redirect */
		if (kasumi_tracepoint_hooks_active() &&
		    kasumi_task_marker_ready() &&
		    kasumi_syscall_dispatcher_nr >= 0 &&
		    kasumi_has_syscall_hook(__NR_openat))
			path_tsr = true;
#ifdef __NR_getxattr
		if (kasumi_tracepoint_hooks_active() &&
		    kasumi_task_marker_ready() &&
		    kasumi_syscall_dispatcher_nr >= 0 &&
		    kasumi_has_syscall_hook(__NR_getxattr))
			xattr_path_tsr = true;
#endif
#ifdef __NR_listxattr
		if (kasumi_tracepoint_hooks_active() &&
		    kasumi_task_marker_ready() &&
		    kasumi_syscall_dispatcher_nr >= 0 &&
		    kasumi_has_syscall_hook(__NR_listxattr))
			xattr_path_tsr = true;
#endif
		if (path_tsr)
			n = scnprintf(kbuf + written, buf_size - written, "path: TSR\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "path: none\n");
		written += n;
		n = scnprintf(kbuf + written, buf_size - written, "xattr path: %s\n",
			      xattr_path_tsr ? "TSR" : "none");
		written += n;
		n = scnprintf(kbuf + written, buf_size - written,
			      "task marker: %s%s\n",
			      kasumi_task_marker_ready() ? "uid lifecycle" : "none",
			      kasumi_task_marker_active() ? " (active)" : "");
		written += n;

		/* VFS hooks */
		if (kasumi_vfs_use_ftrace)
			n = scnprintf(kbuf + written, buf_size - written,
				     "vfs_getattr,d_path,iterate_dir,vfs_getxattr: ftrace+kretprobe\n");
		else if (kasumi_getxattr_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "vfs: getattr=iop readdir=fop d_path=none getxattr=kretprobe\n");
		else
			n = scnprintf(kbuf + written, buf_size - written,
				     "vfs: getattr=iop readdir=fop d_path=none getxattr=none\n");
		written += n;
		n = scnprintf(kbuf + written, buf_size - written,
			      "selinuxfs: access=%s status=%s attr/current=%s\n",
			      kasumi_fake_selinuxfs_access_active() ? "shadow fop" : "none",
			      kasumi_fake_selinuxfs_status_active() ? "shadow fop" : "none",
			      kasumi_fake_selinuxfs_proc_attr_active() ?
				      "proc op kprobe" : "none");
		written += n;

		/* cmdline */
		if (kasumi_cmdline_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written, "cmdline: kprobe (cmdline_proc_show)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "cmdline: none\n");
		written += n;

		/* mountinfo/mounts hide */
		if (kasumi_proc_proxy_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo/mounts: fd_install fop proxy\n");
		else if (kasumi_mount_hide_vfsmnt_registered && kasumi_mount_hide_mountinfo_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo/mounts: kprobe (show_mountinfo, show_vfsmnt)\n");
		else if (kasumi_mount_hide_vfsmnt_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mounts: kprobe (show_vfsmnt)\n");
		else if (kasumi_mount_hide_mountinfo_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo: kprobe (show_mountinfo)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "mountinfo/mounts: none\n");
		written += n;
		n = scnprintf(kbuf + written, buf_size - written,
			      "fake mountinfo: %s (mode=%s)\n",
			      kasumi_proc_proxy_registered &&
			      kasumi_fake_mi_active() ?
				      "root-owned mounts hidden, compact ids" : "none",
			      READ_ONCE(kasumi_mount_hide_mode) ==
				      KSM_MOUNT_HIDE_MODE_AGGRESSIVE ?
				      "aggressive" : "normal");
		written += n;
		n = scnprintf(kbuf + written, buf_size - written,
			      "mount namespace links: %s\n",
			      kasumi_proc_ns_readlink_registered ?
				      (READ_ONCE(kasumi_mount_hide_mode) ==
				       KSM_MOUNT_HIDE_MODE_AGGRESSIVE ?
				       "projected" : "available") : "none");
		written += n;

		/* maps spoof */
		if (kasumi_proc_proxy_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "maps: fd_install fop proxy\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "maps: none\n");
		written += n;
		if (kasumi_statfs_kretprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "statfs/fstatfs: kretprobe (vfs_statfs)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "statfs: none\n");
		written += n;

		list_arg.size = written;
		if (copy_to_user(arg, &list_arg, sizeof(list_arg))) {
			kfree(kbuf);
			return -EFAULT;
		}
		if (written && copy_to_user(list_arg.buf, kbuf, written)) {
			kfree(kbuf);
			return -EFAULT;
		}
		kfree(kbuf);
		return 0;
	}

	/* Commands that use kasumi_syscall_arg */
	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	if (req.src) {
		src = kasumi_strndup_user(req.src, PAGE_SIZE);
		if (IS_ERR(src))
			return PTR_ERR(src);
	}
	if (req.target) {
		target = kasumi_strndup_user(req.target, PAGE_SIZE);
		if (IS_ERR(target)) {
			kfree(src);
			return PTR_ERR(target);
		}
	}

	switch (cmd) {
	case KSM_IOC_ADD_MERGE_RULE: {
		struct kasumi_merge_entry *me;
		char *mat_src = NULL, *mat_tgt = NULL;

		if (!src || !target) { ret = -EINVAL; break; }

		/* Resolve symlinks: d_absolute_path in iterate_dir returns
		 * canonical paths (e.g. /product/overlay), while userspace sends
		 * symlink paths (e.g. /system/product/overlay). Store the
		 * canonical form as resolved_src for iterate_dir matching. */
		{
			char *resolved_src = NULL;
			struct dentry *tgt_dentry = NULL;
			struct path mpath;

			if (kasumi_kern_path(src, LOOKUP_FOLLOW, &mpath) == 0) {
				char *rbuf = kmalloc(PATH_MAX, GFP_KERNEL);
				if (rbuf && kasumi_d_path) {
					char *res = kasumi_d_path(&mpath, rbuf, PATH_MAX);
					if (!IS_ERR(res) && res[0] == '/' &&
					    strcmp(res, src) != 0)
						resolved_src = kstrdup(res, GFP_KERNEL);
					kfree(rbuf);
				}
				kasumi_path_put(&mpath);
			}
			if (kasumi_kern_path(target, LOOKUP_FOLLOW, &mpath) == 0) {
				tgt_dentry = dget(mpath.dentry);
				kasumi_path_put(&mpath);
			}

			hash = full_name_hash(NULL, src, strlen(src));
			mutex_lock(&kasumi_config_mutex);

			hlist_for_each_entry(me,
				&kasumi_merge_dirs[hash_min(hash, KASUMI_HASH_BITS)], node) {
				if (strcmp(me->src, src) == 0 &&
				    strcmp(me->target, target) == 0) {
					found = true;
					break;
				}
			}
			if (!found) {
				me = kmalloc(sizeof(*me), GFP_KERNEL);
				if (me) {
					mat_src = kstrdup(src, GFP_KERNEL);
					mat_tgt = kstrdup(target, GFP_KERNEL);
					me->src = src;
					me->target = target;
					me->resolved_src = resolved_src;
					me->target_dentry = tgt_dentry;
					resolved_src = NULL;
					tgt_dentry = NULL;
					hlist_add_head_rcu(&me->node,
						&kasumi_merge_dirs[hash_min(hash, KASUMI_HASH_BITS)]);
					src = NULL;
					target = NULL;
				} else {
					ret = -ENOMEM;
				}
			} else {
				ret = -EEXIST;
			}
			mutex_unlock(&kasumi_config_mutex);
			if (!found && !ret) {
				kasumi_log("add merge rule: src=%s, target=%s\n", me->src, me->target);
				kasumi_add_inject_rule(kstrdup(me->src, GFP_KERNEL));
				if (me->resolved_src)
					kasumi_add_inject_rule(kstrdup(me->resolved_src, GFP_KERNEL));
				kasumi_mark_dir_has_inject(me->src);
				if (me->resolved_src)
					kasumi_mark_dir_has_inject(me->resolved_src);
				if (mat_src && mat_tgt)
					kasumi_materialize_merge(mat_src, mat_tgt, 0);
			}
			kfree(resolved_src);
			if (tgt_dentry)
				dput(tgt_dentry);
			kfree(mat_src);
			kfree(mat_tgt);
		}
		break;
	}

	case KSM_IOC_ADD_RULE: {
		char *parent_dir = NULL;
		char *resolved_src = NULL;
		struct kasumi_entry *new_entry = NULL;
		struct path path;
		struct inode *target_inode = NULL;
		bool install_side_effects = true;
		char *tmp_buf;

		if (!src || !target) { ret = -EINVAL; break; }

		tmp_buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!tmp_buf) { ret = -ENOMEM; break; }

		/* Try to resolve full path */
		if (kasumi_kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
			char *res = kasumi_d_path ? kasumi_d_path(&path, tmp_buf, PATH_MAX) : ERR_PTR(-ENOENT);
			if (!IS_ERR(res)) {
				resolved_src = kstrdup(res, GFP_KERNEL);
				{
					char *ls = strrchr(res, '/');
					if (ls) {
						if (ls == res)
							parent_dir = kstrdup("/", GFP_KERNEL);
						else {
							size_t l = ls - res;
							parent_dir = kmalloc(l + 1, GFP_KERNEL);
							if (parent_dir) {
								memcpy(parent_dir, res, l);
								parent_dir[l] = '\0';
							}
						}
					}
				}
			}
			kasumi_path_put(&path);
		} else {
			char *ls = strrchr(src, '/');
			if (ls && ls != src) {
				size_t l = ls - src;
				char *p_str = kmalloc(l + 1, GFP_KERNEL);
				if (p_str) {
					memcpy(p_str, src, l);
					p_str[l] = '\0';
					if (kasumi_kern_path(p_str, LOOKUP_FOLLOW, &path) == 0) {
						char *res = kasumi_d_path ? kasumi_d_path(&path, tmp_buf, PATH_MAX) : ERR_PTR(-ENOENT);
						if (!IS_ERR(res)) {
							size_t rl = strlen(res);
							size_t nl = strlen(ls);
							resolved_src = kmalloc(rl + nl + 1, GFP_KERNEL);
							if (resolved_src) {
								strcpy(resolved_src, res);
								strcat(resolved_src, ls);
							}
							parent_dir = kstrdup(res, GFP_KERNEL);
						}
						kasumi_path_put(&path);
					}
					kfree(p_str);
				}
			}
		}
		kfree(tmp_buf);

		if (resolved_src) {
			kfree(src);
			src = resolved_src;
		}

		hash = full_name_hash(NULL, src, strlen(src));
		new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
		if (!new_entry) {
			ret = -ENOMEM;
			goto add_rule_done;
		}
		new_entry->src = kstrdup(src, GFP_KERNEL);
		new_entry->target = kstrdup(target, GFP_KERNEL);
		new_entry->type = req.type;
		new_entry->src_hash = hash;
		if (!new_entry->src || !new_entry->target) {
			ret = -ENOMEM;
			goto add_rule_done;
		}

		mutex_lock(&kasumi_config_mutex);

		hlist_for_each_entry(entry,
			&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
			if (entry->src_hash == hash && strcmp(entry->src, src) == 0) {
				hlist_add_head_rcu(&new_entry->node,
					&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)]);
				hlist_add_head_rcu(&new_entry->target_node,
					&kasumi_targets[hash_min(
						full_name_hash(NULL, new_entry->target,
							       strlen(new_entry->target)),
						KASUMI_HASH_BITS)]);
				hlist_del_rcu(&entry->node);
				hlist_del_rcu(&entry->target_node);
				install_side_effects =
					strcmp(entry->target, new_entry->target) != 0;
				if (install_side_effects) {
					kasumi_clear_inode_flags_for_path(
						entry->target, AS_FLAGS_KASUMI_SPOOF_KSTAT);
				}
				call_rcu(&entry->rcu, kasumi_entry_free_rcu);
				new_entry = NULL;
				found = true;
				kasumi_log("replace rule: src=%s, target=%s, type=%d\n",
					   src, target, req.type);
				break;
			}
		}
		if (!found) {
			unsigned long h1, h2;

			hlist_add_head_rcu(&new_entry->node,
				&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)]);
			hlist_add_head_rcu(&new_entry->target_node,
				&kasumi_targets[hash_min(
					full_name_hash(NULL, new_entry->target,
						       strlen(new_entry->target)),
					KASUMI_HASH_BITS)]);
			h1 = jhash(src, strlen(src), 0) & (KASUMI_BLOOM_SIZE - 1);
			h2 = jhash(src, strlen(src), 1) & (KASUMI_BLOOM_SIZE - 1);
			set_bit(h1, kasumi_path_bloom);
			set_bit(h2, kasumi_path_bloom);
			atomic_inc(&kasumi_rule_count);
			atomic_inc(&kasumi_tsr_path_count);
			new_entry = NULL;
			kasumi_log("add rule: src=%s, target=%s, type=%d\n",
				   src, target, req.type);
		}
		mutex_unlock(&kasumi_config_mutex);

		if (install_side_effects && parent_dir) {
			kasumi_mark_dir_has_inject(parent_dir);
			kasumi_add_inject_rule(parent_dir);
			parent_dir = NULL;
		}
		if (install_side_effects && target && kasumi_kern_path &&
		    kasumi_kern_path(target, LOOKUP_FOLLOW, &path) == 0) {
			if (path.dentry && d_inode(path.dentry)) {
				target_inode = d_inode(path.dentry);
				kasumi_ihold(target_inode);
			}
			kasumi_path_put(&path);
		}
		if (target_inode) {
			(void)kasumi_iop_mark_spoof(target_inode);
			iput(target_inode);
		}

		/* Do not mark redirect source as hidden: we do not inject a virtual
		 * entry for simple ADD_RULE, so hiding would make the file disappear
		 * from the listing. Open of the path is still redirected by exact TSR. */
add_rule_done:
		if (new_entry) {
			kfree(new_entry->src);
			kfree(new_entry->target);
			kfree(new_entry);
		}
		kfree(parent_dir);
		break;
	}

	case KSM_IOC_HIDE_RULE: {
		char *resolved_src = NULL;
		char *parent_dir = NULL;
		struct path path;
		struct inode *target_inode = NULL;
		struct inode *parent_inode = NULL;
		char *tmp_buf;

		if (!src) { ret = -EINVAL; break; }

		tmp_buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!tmp_buf) { ret = -ENOMEM; break; }

		if (kasumi_kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
			char *res = kasumi_d_path ? kasumi_d_path(&path, tmp_buf, PATH_MAX) : ERR_PTR(-ENOENT);
			if (!IS_ERR(res))
				resolved_src = kstrdup(res, GFP_KERNEL);
			if (d_inode(path.dentry)) {
				target_inode = d_inode(path.dentry);
				kasumi_ihold(target_inode);
			}
			if (path.dentry->d_parent && d_inode(path.dentry->d_parent)) {
				parent_inode = d_inode(path.dentry->d_parent);
				kasumi_ihold(parent_inode);
			}
			kasumi_path_put(&path);
		}
		kfree(tmp_buf);

		if (resolved_src) {
			kfree(src);
			src = resolved_src;
		}
		{
			char *ls = strrchr(src, '/');

			if (ls) {
				if (ls == src)
					parent_dir = kstrdup("/", GFP_KERNEL);
				else {
					size_t l = ls - src;

					parent_dir = kmalloc(l + 1, GFP_KERNEL);
					if (parent_dir) {
						memcpy(parent_dir, src, l);
						parent_dir[l] = '\0';
					}
				}
			}
		}

		if (target_inode) {
			kasumi_mark_inode_hidden(target_inode);
			iput(target_inode);
		}
		if (parent_inode) {
			if (parent_inode->i_mapping) {
				set_bit(AS_FLAGS_KASUMI_DIR_HAS_HIDDEN,
					&parent_inode->i_mapping->flags);
				(void)kasumi_fop_install(parent_inode);
			}
			iput(parent_inode);
		}

		hash = full_name_hash(NULL, src, strlen(src));
		mutex_lock(&kasumi_config_mutex);
		hlist_for_each_entry(hide_entry,
			&kasumi_hide_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
			if (hide_entry->path_hash == hash &&
			    strcmp(hide_entry->path, src) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			hide_entry = kmalloc(sizeof(*hide_entry), GFP_KERNEL);
			if (hide_entry) {
				hide_entry->path = kstrdup(src, GFP_KERNEL);
				hide_entry->path_hash = hash;
				if (hide_entry->path) {
					unsigned long h1 = jhash(src, strlen(src), 0) & (KASUMI_BLOOM_SIZE - 1);
					unsigned long h2 = jhash(src, strlen(src), 1) & (KASUMI_BLOOM_SIZE - 1);
					set_bit(h1, kasumi_hide_bloom);
					set_bit(h2, kasumi_hide_bloom);
					atomic_inc(&kasumi_hide_count);
					hlist_add_head_rcu(&hide_entry->node,
						&kasumi_hide_paths[hash_min(hash, KASUMI_HASH_BITS)]);
					kasumi_log("hide rule: src=%s\n", src);
				} else {
					kfree(hide_entry);
				}
			}
		}
		mutex_unlock(&kasumi_config_mutex);
		if (parent_dir) {
			kasumi_mark_dir_has_inject(parent_dir);
			kasumi_add_inject_rule(parent_dir);
		}
		break;
	}

	case KSM_IOC_HIDE_OVERLAY_XATTRS: {
		struct path path;
		struct kasumi_xattr_sb_entry *sb_entry;
		bool xfound = false;

		if (!src) { ret = -EINVAL; break; }

		if (kasumi_kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
			struct super_block *sb = path.dentry->d_sb;

			mutex_lock(&kasumi_config_mutex);
			hlist_for_each_entry(sb_entry,
				&kasumi_xattr_sbs[hash_min((unsigned long)sb, KASUMI_HASH_BITS)], node) {
				if (sb_entry->sb == sb) {
					xfound = true;
					break;
				}
			}
			if (!xfound) {
				sb_entry = kmalloc(sizeof(*sb_entry), GFP_KERNEL);
				if (sb_entry) {
					sb_entry->sb = sb;
					hlist_add_head_rcu(&sb_entry->node,
						&kasumi_xattr_sbs[hash_min((unsigned long)sb,
							KASUMI_HASH_BITS)]);
					kasumi_log("hide xattrs for sb %p (path: %s)\n", sb, src);
				}
			}
			mutex_unlock(&kasumi_config_mutex);
			kasumi_path_put(&path);
		} else {
			ret = -ENOENT;
		}
		break;
	}

	case KSM_IOC_DEL_RULE: {
		struct inode *del_inode = NULL;
		struct inode *del_parent_inode = NULL;

		if (!src) { ret = -EINVAL; break; }

		/* Resolve symlinks so the path matches what ADD_RULE stored */
		if (kasumi_kern_path) {
			struct path dpath;
			if (kasumi_kern_path(src, LOOKUP_FOLLOW, &dpath) == 0) {
				char *rbuf = kmalloc(PATH_MAX, GFP_KERNEL);
				if (rbuf && kasumi_d_path) {
					char *res = kasumi_d_path(&dpath, rbuf, PATH_MAX);
					if (!IS_ERR(res) && res[0] == '/') {
						char *resolved = kstrdup(res, GFP_KERNEL);
						if (resolved) {
							kfree(src);
							src = resolved;
						}
					}
				}
				if (d_inode(dpath.dentry)) {
					del_inode = d_inode(dpath.dentry);
					kasumi_ihold(del_inode);
				}
				if (dpath.dentry->d_parent &&
				    d_inode(dpath.dentry->d_parent)) {
					del_parent_inode = d_inode(dpath.dentry->d_parent);
					kasumi_ihold(del_parent_inode);
				}
				kfree(rbuf);
				kasumi_path_put(&dpath);
			}
		}

		hash = full_name_hash(NULL, src, strlen(src));
		mutex_lock(&kasumi_config_mutex);

		hlist_for_each_entry(entry,
			&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
			if (entry->src_hash == hash && strcmp(entry->src, src) == 0) {
				kasumi_clear_inode_flags_for_path(entry->target,
								AS_FLAGS_KASUMI_SPOOF_KSTAT);
				hlist_del_rcu(&entry->node);
				hlist_del_rcu(&entry->target_node);
				atomic_dec(&kasumi_rule_count);
				atomic_dec(&kasumi_tsr_path_count);
				kasumi_log("del rule: src=%s\n", src);
				call_rcu(&entry->rcu, kasumi_entry_free_rcu);
				goto del_done;
			}
		}
		hlist_for_each_entry(hide_entry,
			&kasumi_hide_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
			if (hide_entry->path_hash == hash &&
			    strcmp(hide_entry->path, src) == 0) {
				hlist_del_rcu(&hide_entry->node);
				atomic_dec(&kasumi_hide_count);
				kasumi_log("del rule: src=%s\n", src);
				call_rcu(&hide_entry->rcu, kasumi_hide_entry_free_rcu);
				goto del_done;
			}
		}
		hlist_for_each_entry(inject_entry,
			&kasumi_inject_dirs[hash_min(hash, KASUMI_HASH_BITS)], node) {
			if (strcmp(inject_entry->dir, src) == 0) {
				hlist_del_rcu(&inject_entry->node);
				atomic_dec(&kasumi_rule_count);
				kasumi_log("del rule: src=%s\n", src);
				call_rcu(&inject_entry->rcu, kasumi_inject_entry_free_rcu);
				goto del_done;
			}
		}
del_done:
		mutex_unlock(&kasumi_config_mutex);
		if (del_inode) {
			if (del_inode->i_mapping)
				clear_bit(AS_FLAGS_KASUMI_HIDE,
					  &del_inode->i_mapping->flags);
			iput(del_inode);
		}
		if (del_parent_inode) {
			iput(del_parent_inode);
		}
		break;
	}

	default:
		ret = -EINVAL;
		break;
	}

	kfree(src);
	kfree(target);
	return ret;
}

/* ======================================================================
 * Part 16: Ioctl Handler
 * ====================================================================== */

/*
 * Rule updates have side effects outside kasumi_config_mutex (inode/dentry
 * overrides and injected-directory state). Serialize the control plane so a
 * concurrent CLEAR_ALL cannot return while an older update is still applying
 * those side effects or re-enable the module afterwards.
 */
static DEFINE_MUTEX(kasumi_ioctl_mutex);
static atomic_t kasumi_control_files = ATOMIC_INIT(0);
static u32 kasumi_quiesce_state = KSM_QUIESCE_STATE_ACTIVE;
static int kasumi_quiesce_error;

static bool kasumi_control_accepting(void)
{
	return READ_ONCE(kasumi_quiesce_state) == KSM_QUIESCE_STATE_ACTIVE;
}

static void kasumi_quiesce_stop_new(void)
{
	if (READ_ONCE(kasumi_quiesce_state) != KSM_QUIESCE_STATE_ACTIVE)
		return;
	WRITE_ONCE(kasumi_quiesce_state, KSM_QUIESCE_STATE_DRAINING);

	/* Stop routed execution before withdrawing any handler-owned state. */
	smp_store_release(&kasumi_enabled, false);
	kasumi_task_marker_set_enabled(false);
	(void)kasumi_tracepoint_hooks_set_enabled(false);
	kasumi_tracepoint_hooks_exit();
	kasumi_task_marker_exit();

	/* The dispatcher slot remains installed until every guard created before
	 * sys_enter unregister has released.  A guard covers both the pre-dispatch
	 * window and the complete redirected syscall.
	 */

	/* No new object may acquire module-owned callbacks after this point. */
	kasumi_file_view_stop_new();
	kasumi_proc_hooks_stop_new();
	kasumi_vfs_hooks_exit(0);
	kasumi_fake_selinuxfs_access_stop_new();
	kasumi_fop_override_stop_new();
	kasumi_fop_bridge_stop_new();
	kasumi_iop_override_stop_new();

	mutex_lock(&kasumi_config_mutex);
	kasumi_cleanup_locked();
	mutex_unlock(&kasumi_config_mutex);
	kasumi_fake_mi_invalidate_all();
}

static int kasumi_ioctl_prepare_unload(void __user *arg)
{
	struct kasumi_quiesce_arg a;
	unsigned int control_files;
	unsigned int getfd;
	unsigned int marker;
	unsigned int redirect;
	unsigned int proxies;
	unsigned int file_views;
	unsigned int iop_active;
	bool iop_quiesced;
	unsigned int known_refs;
	unsigned int module_refs;
	bool dispatcher_detached;
	bool unload_pin_held;
	bool ready;
	int ret;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (a.version != KSM_QUIESCE_API_VERSION || a.size < sizeof(a) ||
	    a.flags || !kasumi_u32_reserved_zero(a.reserved,
						 ARRAY_SIZE(a.reserved))) {
		a.err = -EINVAL;
		if (copy_to_user(arg, &a, sizeof(a)))
			return -EFAULT;
		return -EINVAL;
	}
	if (!kasumi_bootstrap_quiesce_supported()) {
		a.state = KSM_QUIESCE_STATE_ACTIVE;
		a.busy_mask = 0;
		a.err = -EOPNOTSUPP;
		if (copy_to_user(arg, &a, sizeof(a)))
			return -EFAULT;
		return -EOPNOTSUPP;
	}

	kasumi_quiesce_stop_new();
	control_files = (unsigned int)atomic_read(&kasumi_control_files);
	getfd = kasumi_proc_getfd_pending();
	marker = kasumi_task_marker_pending_work_count();
	redirect = kasumi_tracepoint_hooks_pending_guard_count();
	if (!redirect && !kasumi_quiesce_error) {
		ret = kasumi_syscall_redirect_stop_new();
		if (ret)
			kasumi_quiesce_error = ret;
	}
	/* The pending count only decreases after producers have stopped.  If it
	 * reached zero just after the first sample, this poll remains DRAINING and
	 * the next one performs the detach.
	 */
	redirect = kasumi_tracepoint_hooks_pending_guard_count();
	dispatcher_detached = kasumi_syscall_redirect_detached();
	proxies = kasumi_proc_proxy_live();
	file_views = kasumi_file_view_live();
	iop_active = kasumi_iop_override_active();
	iop_quiesced = kasumi_iop_override_quiesced();
	unload_pin_held = kasumi_bootstrap_unload_pin_held();
	module_refs = (unsigned int)kasumi_module_refcount(THIS_MODULE);
	known_refs = control_files + getfd + marker + redirect + proxies +
		file_views + (unload_pin_held ? 1U : 0U);

	a.state = KSM_QUIESCE_STATE_DRAINING;
	a.busy_mask = 0;
	if (getfd)
		a.busy_mask |= KSM_QUIESCE_BUSY_GETFD;
	if (marker)
		a.busy_mask |= KSM_QUIESCE_BUSY_MARKER;
	if (redirect)
		a.busy_mask |= KSM_QUIESCE_BUSY_REDIRECT;
	if (proxies)
		a.busy_mask |= KSM_QUIESCE_BUSY_PROC_PROXY;
	if (file_views)
		a.busy_mask |= KSM_QUIESCE_BUSY_FILE_VIEW;
	if (control_files != 1)
		a.busy_mask |= KSM_QUIESCE_BUSY_CONTROL_FD;
	if (module_refs > known_refs || iop_active || !iop_quiesced ||
	    !dispatcher_detached)
		a.busy_mask |= KSM_QUIESCE_BUSY_OTHER;

	ready = !getfd && !marker && !redirect && !proxies && !file_views &&
		dispatcher_detached && iop_quiesced && control_files == 1 &&
		module_refs == control_files + (unload_pin_held ? 1U : 0U);

	if (kasumi_quiesce_error) {
		a.state = KSM_QUIESCE_STATE_FAILED;
		a.err = kasumi_quiesce_error;
	} else if (ready) {
		/* Publish READY before releasing the lifecycle pin.  This ioctl is
		 * serialized with all control operations, and its own anon file keeps
		 * module text alive through copy_to_user and return to VFS.
		 */
		WRITE_ONCE(kasumi_quiesce_state, KSM_QUIESCE_STATE_READY);
		if (unload_pin_held) {
			kasumi_bootstrap_release_unload_pin();
			module_refs--;
		}
		a.state = KSM_QUIESCE_STATE_READY;
		a.busy_mask = 0;
		a.err = 0;
	} else {
		a.err = 0;
	}
	if (a.state != KSM_QUIESCE_STATE_READY)
		WRITE_ONCE(kasumi_quiesce_state, a.state);
	a.pending_getfd = getfd;
	a.pending_marker = marker;
	a.pending_redirect = redirect;
	a.live_proc_proxy = proxies;
	a.live_file_view = file_views;
	a.control_files = control_files;
	a.module_refs = module_refs;
	if (copy_to_user(arg, &a, sizeof(a)))
		return -EFAULT;
	return 0;
}

static bool kasumi_cmd_changes_view_scope(unsigned int cmd)
{
	switch (cmd) {
	case KSM_IOC_ADD_RULE:
	case KSM_IOC_DEL_RULE:
	case KSM_IOC_HIDE_RULE:
	case KSM_IOC_CLEAR_ALL:
	case KSM_IOC_ADD_MERGE_RULE:
	case KSM_IOC_SET_POLICY_OWNER:
	case KSM_IOC_SET_POLICY_UIDS:
	case KSM_IOC_CLEAR_POLICY_UIDS:
	case KSM_IOC_REPLACE_POLICY:
	case KSM_IOC_RESET_POLICY:
		return true;
	default:
		return false;
	}
}

static bool kasumi_cmd_changes_spoof_state(unsigned int cmd)
{
	return cmd == KSM_IOC_SET_MOUNT_HIDE ||
	       cmd == KSM_IOC_SET_MOUNT_HIDE_MODE;
}

static void kasumi_reconcile_view_tsr(void)
{
	if (!READ_ONCE(kasumi_enabled))
		return;
	if (!kasumi_policy_view_tsr_demand()) {
		(void)kasumi_tracepoint_hooks_set_enabled(false);
		return;
	}
	if (kasumi_tracepoint_hooks_set_enabled(true)) {
		pr_warn("Kasumi: VIEW rules active without TSR transport\n");
		return;
	}
	kasumi_task_marker_refresh_scopes();
}

static KASUMI_NOCFI long kasumi_dev_ioctl(struct file *file, unsigned int cmd,
					unsigned long arg)
{
	long ret;

	mutex_lock(&kasumi_ioctl_mutex);
	atomic_long_set(&kasumi_ioctl_tgid, (long)task_tgid_vnr(current));
	if (!kasumi_control_accepting() && cmd != KSM_IOC_GET_VERSION &&
	    cmd != KSM_IOC_GET_FEATURES && cmd != KSM_IOC_PREPARE_UNLOAD) {
		ret = -ESHUTDOWN;
		goto out;
	}
	switch (cmd) {
	case KSM_IOC_GET_VERSION:
	case KSM_IOC_SET_ENABLED:
	case KSM_IOC_ADD_RULE:
	case KSM_IOC_DEL_RULE:
	case KSM_IOC_HIDE_RULE:
	case KSM_IOC_CLEAR_ALL:
	case KSM_IOC_LIST_RULES:
	case KSM_IOC_SET_DEBUG:
	case KSM_IOC_REORDER_MNT_ID:
	case KSM_IOC_SET_STEALTH:
	case KSM_IOC_HIDE_OVERLAY_XATTRS:
	case KSM_IOC_ADD_MERGE_RULE:
	case KSM_IOC_SET_MIRROR_PATH:
	case KSM_IOC_SET_CMDLINE:
	case KSM_IOC_GET_HOOKS:
	case KSM_IOC_ADD_MAPS_RULE:
	case KSM_IOC_CLEAR_MAPS_RULES:
	case KSM_IOC_GET_FEATURES:
	case KSM_IOC_SET_MOUNT_HIDE:
	case KSM_IOC_SET_MOUNT_HIDE_MODE:
	case KSM_IOC_SET_MAPS_SPOOF:
	case KSM_IOC_SET_STATFS_SPOOF:
	case KSM_IOC_SELINUX_FIX:
	case KSM_IOC_SET_POLICY_OWNER:
	case KSM_IOC_SET_POLICY_UIDS:
	case KSM_IOC_CLEAR_POLICY_UIDS:
	case KSM_IOC_GET_POLICY:
	case KSM_IOC_GET_POLICY_UIDS:
	case KSM_IOC_REPLACE_POLICY:
	case KSM_IOC_RESET_POLICY:
	case KSM_IOC_ADD_SPOOF_KSTAT:
	case KSM_IOC_UPDATE_SPOOF_KSTAT:
		ret = kasumi_dispatch_cmd(cmd, (void __user *)arg);
		break;
	case KSM_IOC_PREPARE_UNLOAD:
		ret = kasumi_ioctl_prepare_unload((void __user *)arg);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	if (!ret && kasumi_cmd_changes_view_scope(cmd))
		kasumi_reconcile_view_tsr();
	else if (!ret && kasumi_cmd_changes_spoof_state(cmd) &&
		 READ_ONCE(kasumi_enabled))
		kasumi_task_marker_refresh_scopes();
out:
	atomic_long_set(&kasumi_ioctl_tgid, 0);
	mutex_unlock(&kasumi_ioctl_mutex);
	return ret;
}

/* ======================================================================
 * Part 17: Anonymous fd (no device node; reboot task_work installs it)
 * ====================================================================== */

static int kasumi_anon_release(struct inode *inode, struct file *file)
{
	(void)inode;
	(void)file;
	if (atomic_dec_and_test(&kasumi_control_files))
		WRITE_ONCE(kasumi_daemon_pid, 0);
	return 0;
}

static const struct file_operations kasumi_anon_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = kasumi_dev_ioctl,
	.compat_ioctl   = kasumi_dev_ioctl,
	.release        = kasumi_anon_release,
	.llseek         = noop_llseek,
};

/**
 * kasumi_install_anon_fd - Install a Kasumi fd and publish its number.
 * @outp: userspace pointer receiving the new fd
 *
 * The fd number is copied before fd_install(), so a failed userspace write can
 * release both the reserved descriptor and file without requiring close_fd().
 * Returns fd on success, negative errno on failure.
 */
int kasumi_install_anon_fd(int __user *outp)
{
	struct file *file;
	int fd;
	pid_t pid;

	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return -EPERM;
	if (!kasumi_control_accepting())
		return -ESHUTDOWN;
	if (!outp)
		return -EINVAL;

	file = anon_inode_getfile("kasumi", &kasumi_anon_fops, NULL, O_RDWR);
	if (IS_ERR(file))
		return PTR_ERR(file);
	atomic_inc(&kasumi_control_files);

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		goto err_file;
	if (put_user(fd, outp)) {
		put_unused_fd(fd);
		fd = -EFAULT;
		goto err_file;
	}

	fd_install(fd, file);
	pid = task_tgid_vnr(current);
	WRITE_ONCE(kasumi_daemon_pid, pid);
	kasumi_log("Controller PID auto-registered: %d\n", pid);
	return fd;

err_file:
	fput(file);
	return fd;
}
