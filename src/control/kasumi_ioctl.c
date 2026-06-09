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
#include "kasumi_path_policy.h"
#include "kasumi_overlay.h"
#include "kasumi_syscall_redirect.h"
#include "kasumi_uname.h"
#include "kasumi_dop_override.h"
#include "kasumi_xattr_sid_override.h"
#include "kasumi_iop_override.h"
#include "kasumi_fop_override.h"
#include "kasumi_fake_mountinfo.h"
#include "kasumi_fake_selinuxfs_access.h"
/* ======================================================================
 * Part 15: Dispatch Handler (ioctl only; all commands use KSM_IOC_* from kasumi_uapi.h)
 * GET_FD is syscall-only -> kasumi_get_anon_fd()
 * ====================================================================== */

static int kasumi_dispatch_cmd(unsigned int cmd, void __user *arg)
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
		rcu_barrier();
		return 0;
	}

	if (cmd == KSM_IOC_GET_VERSION) {
		int ver = KSM_PROTOCOL_VERSION;
		if (copy_to_user(arg, &ver, sizeof(ver)))
			return -EFAULT;
		return 0;
	}

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
		mutex_lock(&kasumi_config_mutex);
		kasumi_enabled = !!val;
		mutex_unlock(&kasumi_config_mutex);
		kasumi_log("Kasumi %s\n", kasumi_enabled ? "enabled" : "disabled");
		if (kasumi_enabled)
			kasumi_reload_ksu_allowlist();
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
						     "mount_hide enabled\n");
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

	if (cmd == KSM_IOC_SET_UNAME) {
		/* Scoped mode: stored config is applied per-task on first syscall
		 * from a hidden-uid process by unsharing CLONE_NEWUTS and writing
		 * the fake fields into the task's private uts_ns. */
		struct kasumi_spoof_uname u;

		if (copy_from_user(&u, arg, sizeof(u)))
			return -EFAULT;
		return kasumi_uname_set_scoped_config(&u);
	}

	if (cmd == KSM_IOC_SET_UNAME_GLOBAL) {
		/* Global mode: rewrite init_uts_ns in place. All-empty struct
		 * restores originals. */
		struct kasumi_spoof_uname u;

		if (copy_from_user(&u, arg, sizeof(u)))
			return -EFAULT;
		if (u.sysname[0] || u.nodename[0] || u.release[0] ||
		    u.version[0] || u.machine[0] || u.domainname[0])
			return kasumi_uname_apply_global(&u);
		return kasumi_uname_restore_global();
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

		kasumi_enabled = true;
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
		int features = 0;
		if (kasumi_uname_capable())
			features |= KSM_FEATURE_UNAME_SPOOF;
		if (kasumi_cmdline_kprobe_registered || kasumi_cmdline_kretprobe_registered ||
		    (kasumi_syscall_dispatcher_nr >= 0 &&
		     kasumi_has_syscall_hook(__NR_read)))
			features |= KSM_FEATURE_CMDLINE_SPOOF;
		features |= KSM_FEATURE_KSTAT_SPOOF;
		features |= KSM_FEATURE_MERGE_DIR;
		if (kasumi_getxattr_kprobe_registered)
			features |= KSM_FEATURE_SELINUX_BYPASS;
		if (kasumi_proc_proxy_registered ||
		    kasumi_mount_hide_vfsmnt_registered || kasumi_mount_hide_mountinfo_registered ||
		    kasumi_mount_hide_vfs_read_registered ||
		    kasumi_mount_hide_read_fallback_registered ||
		    kasumi_mount_hide_pread_fallback_registered)
			features |= KSM_FEATURE_MOUNT_HIDE;
		if (kasumi_proc_proxy_registered ||
		    kasumi_mount_hide_vfs_read_registered ||
		    kasumi_mount_hide_read_fallback_registered ||
		    kasumi_mount_hide_pread_fallback_registered ||
		    kasumi_maps_seq_read_registered)
			features |= KSM_FEATURE_MAPS_SPOOF;
		if (kasumi_statfs_kretprobe_registered ||
		    kasumi_statfs_tracepoint_registered)
			features |= KSM_FEATURE_STATFS_SPOOF;
		if (kasumi_fake_selinuxfs_access_active())
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
		if (kasumi_syscall_dispatcher_nr >= 0 &&
		    (kasumi_has_syscall_hook(__NR_reboot) ||
		     kasumi_has_syscall_hook(__NR_prctl)))
			n = scnprintf(kbuf + written, buf_size - written, "GET_FD: TSR\n");
		else if (kasumi_ni_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "GET_FD: kprobe (ni_syscall nr=%d)\n", kasumi_syscall_nr_param);
		else if (kasumi_reboot_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "GET_FD: kprobe (reboot nr=%d)\n", kasumi_syscall_nr_param);
		else
			n = scnprintf(kbuf + written, buf_size - written, "GET_FD: none\n");
		written += n;

		/* Path redirect */
		if (kasumi_syscall_dispatcher_nr >= 0 &&
		    kasumi_has_syscall_hook(__NR_openat))
			path_tsr = true;
#ifdef __NR_getxattr
		if (kasumi_syscall_dispatcher_nr >= 0 &&
		    kasumi_has_syscall_hook(__NR_getxattr))
			xattr_path_tsr = true;
#endif
#ifdef __NR_listxattr
		if (kasumi_syscall_dispatcher_nr >= 0 &&
		    kasumi_has_syscall_hook(__NR_listxattr))
			xattr_path_tsr = true;
#endif
		if (path_tsr)
			n = scnprintf(kbuf + written, buf_size - written, "path: TSR\n");
		else if (kasumi_getname_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written, "path: kprobe (getname_flags)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "path: none\n");
		written += n;
		n = scnprintf(kbuf + written, buf_size - written, "xattr path: %s\n",
			      xattr_path_tsr ? "TSR" : "none");
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
			      "selinuxfs/access,context,proc_attr_current: %s\n",
			      kasumi_fake_selinuxfs_access_active() ? "shadow fop" : "none");
		written += n;

		/* uname */
		{
			const char *mode = "none";
			bool g = kasumi_uname_global_active();
			bool s = kasumi_uname_scoped_active();
			if (g && s)       mode = "utsname (global+scoped)";
			else if (g)        mode = "utsname (global)";
			else if (s)        mode = "utsname (scoped/uts_ns)";
			n = scnprintf(kbuf + written, buf_size - written,
				     "uname: %s\n", mode);
			written += n;
		}

		/* cmdline */
		if (kasumi_syscall_dispatcher_nr >= 0 &&
		    kasumi_has_syscall_hook(__NR_read))
			n = scnprintf(kbuf + written, buf_size - written, "cmdline: TSR\n");
		else if (kasumi_cmdline_kretprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written, "cmdline: kretprobe (read)\n");
		else if (kasumi_cmdline_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written, "cmdline: kprobe (cmdline_proc_show)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "cmdline: none\n");
		written += n;

		/* mountinfo/mounts hide */
		if (kasumi_proc_proxy_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo/mounts: proxy (open fd read filter)\n");
		else if (kasumi_mount_hide_vfsmnt_registered && kasumi_mount_hide_mountinfo_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo/mounts: kprobe (show_mountinfo, show_vfsmnt)\n");
		else if (kasumi_mount_hide_vfsmnt_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mounts: kprobe (show_vfsmnt)\n");
		else if (kasumi_mount_hide_mountinfo_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo: kprobe (show_mountinfo)\n");
		else if (kasumi_mount_hide_vfs_read_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo/mounts: kretprobe (vfs_read buffer filter)\n");
		else if (kasumi_mount_hide_read_fallback_registered &&
			 kasumi_mount_hide_pread_fallback_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo/mounts: kretprobe (read/pread64 syscall buffer filter)\n");
		else if (kasumi_mount_hide_read_fallback_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo/mounts: kretprobe (read syscall buffer filter)\n");
		else if (kasumi_mount_hide_pread_fallback_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo/mounts: kretprobe (pread64 syscall buffer filter)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "mountinfo/mounts: none\n");
		written += n;

		/* maps spoof (read kretprobe or seq_read fallback) */
		if (kasumi_proc_proxy_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "maps: proxy (open fd read filter)\n");
		else if (kasumi_maps_seq_read_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "maps: kretprobe (seq_read fallback)\n");
		else if (kasumi_mount_hide_vfs_read_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "maps: kretprobe (vfs_read buffer filter)\n");
		else if (kasumi_mount_hide_read_fallback_registered &&
		    kasumi_mount_hide_pread_fallback_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "maps: kretprobe (read/pread64 buffer filter)\n");
		else if (kasumi_mount_hide_read_fallback_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "maps: kretprobe (read buffer filter)\n");
		else if (kasumi_mount_hide_pread_fallback_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "maps: kretprobe (pread64 buffer filter)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "maps: none\n");
		written += n;
		if (kasumi_syscall_dispatcher_nr >= 0 &&
		    kasumi_has_syscall_hook(__NR_statfs))
			n = scnprintf(kbuf + written, buf_size - written, "statfs: TSR\n");
		else if (kasumi_statfs_kretprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "statfs: kretprobe (f_type spoof for INCONSISTENT_MOUNT)\n");
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
		mutex_lock(&kasumi_config_mutex);
		kasumi_enabled = true;
		mutex_unlock(&kasumi_config_mutex);
		break;
	}

	case KSM_IOC_ADD_RULE: {
		char *parent_dir = NULL;
		char *resolved_src = NULL;
		struct path path;
		struct inode *src_inode = NULL;
		struct inode *parent_inode = NULL;
		struct inode *target_inode = NULL;
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
			if (d_inode(path.dentry)) {
				src_inode = d_inode(path.dentry);
				kasumi_ihold(src_inode);
			}
			if (path.dentry->d_parent && d_inode(path.dentry->d_parent)) {
				parent_inode = d_inode(path.dentry->d_parent);
				kasumi_ihold(parent_inode);
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
		mutex_lock(&kasumi_config_mutex);

		hlist_for_each_entry(entry,
			&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
			if (entry->src_hash == hash && strcmp(entry->src, src) == 0) {
				char *old_t = entry->target;
				char *new_t = kstrdup(target, GFP_KERNEL);
				if (new_t) {
					hlist_del_rcu(&entry->target_node);
					rcu_assign_pointer(entry->target, new_t);
					entry->type = req.type;
					hlist_add_head_rcu(&entry->target_node,
						&kasumi_targets[hash_min(
							full_name_hash(NULL, new_t, strlen(new_t)),
							KASUMI_HASH_BITS)]);
					kfree(old_t);
				}
				found = true;
				break;
			}
		}
		if (!found) {
			entry = kmalloc(sizeof(*entry), GFP_KERNEL);
			if (entry) {
				entry->src = kstrdup(src, GFP_KERNEL);
				entry->target = kstrdup(target, GFP_KERNEL);
				entry->type = req.type;
				entry->src_hash = hash;
				if (entry->src && entry->target) {
					unsigned long h1, h2;
					hlist_add_head_rcu(&entry->node,
						&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)]);
					hlist_add_head_rcu(&entry->target_node,
						&kasumi_targets[hash_min(
							full_name_hash(NULL, entry->target,
								strlen(entry->target)),
							KASUMI_HASH_BITS)]);
					h1 = jhash(src, strlen(src), 0) & (KASUMI_BLOOM_SIZE - 1);
					h2 = jhash(src, strlen(src), 1) & (KASUMI_BLOOM_SIZE - 1);
					set_bit(h1, kasumi_path_bloom);
					set_bit(h2, kasumi_path_bloom);
					atomic_inc(&kasumi_rule_count);
					kasumi_log("add rule: src=%s, target=%s, type=%d\n", src, target, req.type);
				} else {
					kfree(entry->src);
					kfree(entry->target);
					kfree(entry);
				}
			}
		}
		mutex_unlock(&kasumi_config_mutex);

		if (parent_dir) {
			kasumi_mark_dir_has_inject(parent_dir);
			kasumi_add_inject_rule(parent_dir);
		}
		if (target && kasumi_kern_path &&
		    kasumi_kern_path(target, LOOKUP_FOLLOW, &path) == 0) {
			if (path.dentry && d_inode(path.dentry)) {
				target_inode = d_inode(path.dentry);
				kasumi_ihold(target_inode);
				if (src_inode)
					(void)kasumi_clone_source_inode_attrs(target_inode,
									       src_inode);
				(void)kasumi_dop_install(path.dentry, src);
				(void)kasumi_xattr_sid_install_path_ancestors(target, src);
			}
			kasumi_path_put(&path);
		}
		if (target_inode) {
			(void)kasumi_iop_mark_spoof(target_inode);
			iput(target_inode);
		}

		/* Do not mark redirect source as hidden: we do not inject a virtual
		 * entry for simple ADD_RULE, so hiding would make the file disappear
		 * from the listing. Open of the path is still redirected via getname. */
		if (src_inode)
			iput(src_inode);
		if (parent_inode)
			iput(parent_inode);

		mutex_lock(&kasumi_config_mutex);
		kasumi_enabled = true;
		mutex_unlock(&kasumi_config_mutex);
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
		kasumi_enabled = true;
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
			kasumi_enabled = true;
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
				(void)kasumi_dop_uninstall_path(entry->target);
				(void)kasumi_xattr_sid_uninstall_path_ancestors(entry->target);
				hlist_del_rcu(&entry->node);
				hlist_del_rcu(&entry->target_node);
				atomic_dec(&kasumi_rule_count);
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

static KASUMI_NOCFI long kasumi_dev_ioctl(struct file *file, unsigned int cmd,
					unsigned long arg)
{
	long ret;

	atomic_long_set(&kasumi_ioctl_tgid, (long)task_tgid_vnr(current));
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
	case KSM_IOC_GET_HOOKS:
	case KSM_IOC_SET_UNAME:
	case KSM_IOC_SET_UNAME_GLOBAL:
	case KSM_IOC_ADD_MAPS_RULE:
	case KSM_IOC_CLEAR_MAPS_RULES:
	case KSM_IOC_GET_FEATURES:
	case KSM_IOC_SET_MOUNT_HIDE:
	case KSM_IOC_SET_MAPS_SPOOF:
	case KSM_IOC_SET_STATFS_SPOOF:
	case KSM_IOC_SELINUX_FIX:
	case KSM_IOC_ADD_SPOOF_KSTAT:
	case KSM_IOC_UPDATE_SPOOF_KSTAT:
		ret = kasumi_dispatch_cmd(cmd, (void __user *)arg);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	atomic_long_set(&kasumi_ioctl_tgid, 0);
	return ret;
}

/* ======================================================================
 * Part 17: Anonymous fd (no device node; syscall returns this fd)
 * ====================================================================== */

static const struct file_operations kasumi_anon_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = kasumi_dev_ioctl,
	.compat_ioctl   = kasumi_dev_ioctl,
	.llseek         = noop_llseek,
};

/**
 * kasumi_get_anon_fd - Create and return anonymous fd for Kasumi.
 * Returns fd on success, negative errno on failure.
 */
int kasumi_get_anon_fd(void)
{
	int fd;
	pid_t pid;

	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return -EPERM;
	fd = anon_inode_getfd("kasumi", &kasumi_anon_fops, NULL, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fd;
	pid = task_tgid_vnr(current);
	WRITE_ONCE(kasumi_daemon_pid, pid);
	kasumi_log("Daemon PID auto-registered: %d\n", pid);
	return fd;
}
EXPORT_SYMBOL_GPL(kasumi_get_anon_fd);
