/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - proc, mountinfo, maps, and read-path hooks layered over syscall flow.
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
#include "kasumi_proc_hooks.h"
#include "kasumi_syscall_redirect.h"
#include "kasumi_uname.h"
#include "kasumi_fake_mountinfo.h"
/* override_fd/override_active and cmdline_ctx now in kasumi_percpu_base */

static int kasumi_ni_syscall_pre(struct kprobe *p, struct pt_regs *regs)
{
#if defined(__aarch64__)
	unsigned long nr = regs->regs[8];
	unsigned long a0 = regs->regs[0];
	unsigned long a1 = regs->regs[1];
	unsigned long a2 = regs->regs[2];
#elif defined(__x86_64__)
	unsigned long nr = regs->orig_ax;
	unsigned long a0 = regs->di;
	unsigned long a1 = regs->si;
	unsigned long a2 = regs->dx;
#else
	unsigned long nr = 0, a0 = 0, a1 = 0, a2 = 0;
#endif
	if (nr != (unsigned long)kasumi_syscall_nr_param)
		return 0;
	if (a0 != KSM_MAGIC1 || a1 != KSM_MAGIC2 || a2 != (unsigned long)KSM_CMD_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;
	{
		int fd = kasumi_get_anon_fd();
		if (fd < 0)
			return 0;
		kasumi_this_cpu()->override_fd = fd;
		kasumi_this_cpu()->override_active = 1;
	}
	return 0;
}

/*
 * kretprobe handler: replace function return value (x0) with our fd.
 *
 * On aarch64 >= 4.16 the call chain is:
 *   invoke_syscall() {
 *       ret = __arm64_sys_reboot(regs);  // <-- kretprobe fires here
 *       regs->regs[0] = ret;             // stores ret into user pt_regs
 *   }
 * So we MUST modify the kretprobe's own regs->regs[0] (= function return value x0).
 * invoke_syscall will then copy our fd into the user's pt_regs.
 * Writing to real_regs directly would be overwritten by invoke_syscall.
 */
static int kasumi_ni_syscall_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!kasumi_this_cpu()->override_active)
		return 0;
#if defined(__aarch64__)
	regs->regs[0] = kasumi_this_cpu()->override_fd;
#elif defined(__x86_64__)
	regs->ax = kasumi_this_cpu()->override_fd;
#endif
	kasumi_this_cpu()->override_active = 0;
	return 0;
}

static struct kprobe kasumi_kp_ni = {
	.pre_handler = kasumi_ni_syscall_pre,
};
static struct kretprobe kasumi_krp_ni = {
	.handler = kasumi_ni_syscall_ret,
};

/*
 * GET_FD via kprobe on __arm64_sys_reboot (same as susfs/KernelSU old kprobes).
 * When userspace calls SYS_reboot(142) with our magic, we intercept and return fd in kretprobe.
 * Real reboot sees invalid magic and returns -EINVAL; we overwrite return value with fd.
 * Compatible with 5.10+; use this when ni_syscall path is not available.
 */
static int kasumi_reboot_pre(struct kprobe *p, struct pt_regs *regs)
{
	/*
	 * On aarch64 4.16+, __arm64_sys_reboot is a wrapper: first arg (regs->regs[0])
	 * is the pointer to the real syscall pt_regs. Read magic from there.
	 *
	 * We use the KernelSU approach: write fd to userspace via put_user on the
	 * 4th syscall argument (a user pointer). This avoids kretprobe return value
	 * issues entirely — invoke_syscall would overwrite any kretprobe changes.
	 *
	 * Userspace: int fd = -1; syscall(SYS_reboot, M1, M2, CMD, &fd);
	 */
#if defined(__aarch64__)
	struct pt_regs *real_regs;
	unsigned long a0, a1, a2;
	int __user *fd_ptr;
	int fd;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
	real_regs = (struct pt_regs *)regs->regs[0];
#else
	real_regs = regs;
#endif
	a0 = real_regs->regs[0];
	a1 = real_regs->regs[1];
	a2 = real_regs->regs[2];

	if (a0 != KSM_MAGIC1 || a1 != KSM_MAGIC2 || a2 != (unsigned long)KSM_CMD_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;

	fd = kasumi_get_anon_fd();
	if (fd < 0)
		return 0;

	/* Write fd to userspace via 4th arg pointer (like KernelSU) */
	fd_ptr = (int __user *)(unsigned long)real_regs->regs[3];
	if (fd_ptr)
		put_user(fd, fd_ptr);
#elif defined(__x86_64__)
	unsigned long a0 = regs->di;
	unsigned long a1 = regs->si;
	unsigned long a2 = regs->dx;

	if (a0 != KSM_MAGIC1 || a1 != KSM_MAGIC2 || a2 != (unsigned long)KSM_CMD_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;
	{
		int fd = kasumi_get_anon_fd();
		if (fd < 0)
			return 0;
		kasumi_this_cpu()->override_fd = fd;
		kasumi_this_cpu()->override_active = 1;
	}
#endif
	return 0;
}

static struct kprobe kasumi_kp_reboot = {
	.pre_handler = kasumi_reboot_pre,
};
static struct kretprobe kasumi_krp_reboot = {
	.handler = kasumi_ni_syscall_ret, /* same: replace return with fd */
};

/*
 * GET_FD via prctl (SECCOMP-safe). option=KSM_PRCTL_GET_FD, arg2=(int *) for fd.
 * No kretprobe: we put_user(fd, arg2) in pre_handler; syscall return value ignored.
 */
static int kasumi_prctl_pre(struct kprobe *p, struct pt_regs *regs)
{
#if defined(__aarch64__)
	struct pt_regs *real_regs;
	unsigned long option;
	unsigned long arg2;
	int __user *fd_ptr;
	int fd;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
	real_regs = (struct pt_regs *)regs->regs[0];
#else
	real_regs = regs;
#endif
	option = real_regs->regs[0];
	arg2 = real_regs->regs[1];

	if (option != (unsigned long)KSM_PRCTL_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;

	fd = kasumi_get_anon_fd();
	if (fd < 0)
		return 0;

	fd_ptr = (int __user *)(unsigned long)arg2;
	if (fd_ptr && put_user(fd, fd_ptr) != 0)
		pr_err("Kasumi: prctl GET_FD put_user failed\n");
#elif defined(__x86_64__)
	unsigned long option = regs->di;
	unsigned long arg2 = regs->si;

	if (option != (unsigned long)KSM_PRCTL_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;
	{
		int fd = kasumi_get_anon_fd();
		int __user *fd_ptr;

		if (fd < 0)
			return 0;
		fd_ptr = (int __user *)(unsigned long)arg2;
		if (fd_ptr && put_user(fd, fd_ptr) != 0)
			pr_err("Kasumi: prctl GET_FD put_user failed\n");
	}
#endif
	return 0;
}

static struct kprobe kasumi_kp_prctl = {
	.pre_handler = kasumi_prctl_pre,
};
static int kasumi_prctl_kprobe_registered;

/* ======================================================================
 * cmdline spoofing: kprobe pre_handler on cmdline_proc_show
 * When spoof active, write fake cmdline to seq_file and skip original.
 * ====================================================================== */

static int kasumi_cmdline_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct seq_file *m;
	bool did_spoof = false;
	pid_t pid;

	if (!READ_ONCE(kasumi_cmdline_spoof_active))
		return 0;
	if (!kasumi_should_apply_hide_rules())
		return 0;
	pid = task_tgid_vnr(current);
	if (READ_ONCE(kasumi_daemon_pid) > 0 && pid == READ_ONCE(kasumi_daemon_pid))
		return 0;

#if defined(__aarch64__)
	m = (struct seq_file *)regs->regs[0];
#elif defined(__x86_64__)
	m = (struct seq_file *)regs->di;
#else
	return 0;
#endif

	rcu_read_lock();
	{
		struct kasumi_cmdline_rcu *c = rcu_dereference(kasumi_spoof_cmdline_ptr);
		if (c && c->cmdline[0]) {
			seq_puts(m, c->cmdline);
			seq_putc(m, '\n');
			did_spoof = true;
		}
	}
	rcu_read_unlock();

	if (!did_spoof)
		return 0;

	/* Skip original: set PC to return address, return value 0 */
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

static struct kprobe kasumi_kp_cmdline = {
	.pre_handler = kasumi_cmdline_pre,
};

/* kretprobe fallback for cmdline when TSR read hook is unavailable */
static int kasumi_cmdline_read_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	kasumi_handle_sys_enter_cmdline(regs, __NR_read);
	return 0;
}

static int kasumi_cmdline_read_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long ret;
#if defined(__aarch64__)
	ret = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret = (long)regs->ax;
#else
	ret = 0;
#endif
	kasumi_handle_sys_exit_cmdline(regs, ret);
	return 0;
}

static struct kretprobe kasumi_krp_cmdline_read = {
	.entry_handler = kasumi_cmdline_read_entry,
	.handler = kasumi_cmdline_read_ret,
	.maxactive = 64,
};

int kasumi_proc_hooks_init(bool skip_getfd, bool no_tracepoint, bool skip_extra_kprobes)
{
	(void)no_tracepoint;
	if (skip_getfd)
		pr_alert("Kasumi: skipping GET_FD kprobes (kasumi_skip_getfd=1)\n");

	if (kasumi_syscall_nr_param <= 0) {
		pr_err("Kasumi: kasumi_syscall_nr must be positive (got %d)\n", kasumi_syscall_nr_param);
		return -EINVAL;
	}

	if (!skip_getfd && kasumi_syscall_dispatcher_nr < 0) {
		const char *ni_names[] = { "__arm64_sys_ni_syscall", "sys_ni_syscall",
					   "__x64_sys_ni_syscall", NULL };
		unsigned long ni_addr = 0;
		int i, ret;

		for (i = 0; ni_names[i]; i++) {
			ni_addr = kasumi_lookup_name(ni_names[i]);
			if (ni_addr)
				break;
		}
		if (!ni_addr) {
			pr_err("Kasumi: ni_syscall not found\n");
			return -ENOENT;
		}
		kasumi_kp_ni.addr = (kprobe_opcode_t *)ni_addr;
		kasumi_krp_ni.kp.addr = (kprobe_opcode_t *)ni_addr;
		ret = register_kprobe(&kasumi_kp_ni);
		if (ret) {
			pr_err("Kasumi: register_kprobe(ni_syscall) failed: %d\n", ret);
			return ret;
		}
		ret = register_kretprobe(&kasumi_krp_ni);
		if (ret) {
			unregister_kprobe(&kasumi_kp_ni);
			return ret;
		}
		kasumi_ni_kprobe_registered = 1;
		pr_info("Kasumi: GET_FD via kprobe on ni_syscall (nr=%d)\n", kasumi_syscall_nr_param);
	} else if (skip_getfd) {
		pr_alert("Kasumi: skipping GET_FD kprobes (kasumi_skip_getfd=1)\n");
	}

	if (!skip_extra_kprobes && kasumi_syscall_dispatcher_nr < 0) {
		static const char *reboot_symbols[] = {
#if defined(__aarch64__)
			"__arm64_sys_reboot", "sys_reboot", NULL
#elif defined(__x86_64__)
			"__x64_sys_reboot", "sys_reboot", NULL
#else
			NULL
#endif
		};
		void *reboot_addr = NULL;
		int i, ret;

		for (i = 0; reboot_symbols[i]; i++) {
			reboot_addr = (void *)kasumi_lookup_name(reboot_symbols[i]);
			if (reboot_addr)
				break;
		}
		if (reboot_addr) {
			kasumi_kp_reboot.addr = (kprobe_opcode_t *)reboot_addr;
			kasumi_krp_reboot.kp.addr = (kprobe_opcode_t *)reboot_addr;
			kasumi_krp_reboot.maxactive = 16;
			ret = register_kprobe(&kasumi_kp_reboot);
			if (ret == 0) {
				ret = register_kretprobe(&kasumi_krp_reboot);
				if (ret)
					unregister_kprobe(&kasumi_kp_reboot);
				else
					kasumi_reboot_kprobe_registered = 1;
			}
		}
	}

	if (!skip_extra_kprobes && kasumi_syscall_dispatcher_nr < 0) {
		static const char *prctl_symbols[] = {
#if defined(__aarch64__)
			"__arm64_sys_prctl", "sys_prctl", NULL
#elif defined(__x86_64__)
			"__x64_sys_prctl", "sys_prctl", NULL
#else
			NULL
#endif
		};
		void *prctl_addr = NULL;
		int i, ret;

		for (i = 0; prctl_symbols[i]; i++) {
			prctl_addr = (void *)kasumi_lookup_name(prctl_symbols[i]);
			if (prctl_addr)
				break;
		}
		if (prctl_addr) {
			kasumi_kp_prctl.addr = (kprobe_opcode_t *)prctl_addr;
			ret = register_kprobe(&kasumi_kp_prctl);
			if (ret == 0)
				kasumi_prctl_kprobe_registered = 1;
		}
	} else if (skip_extra_kprobes) {
		pr_alert("Kasumi: skipping extra kprobes (reboot,prctl,uname,cmdline)\n");
	}

	if (kasumi_uname_init() != 0)
		pr_warn("Kasumi: uname spoofing unavailable (init_uts_ns/uts_sem not resolvable)\n");

	if (!skip_extra_kprobes) {
		int ret;

		if (kasumi_syscall_dispatcher_nr < 0 ||
		    !kasumi_has_syscall_hook(__NR_read)) {
			const char *read_sym =
#if defined(__aarch64__)
				"__arm64_sys_read";
#elif defined(__x86_64__)
				"__x64_sys_read";
#else
				NULL;
#endif
			unsigned long read_addr = read_sym ? kasumi_lookup_name(read_sym) : 0;

			if (read_addr) {
				kasumi_krp_cmdline_read.kp.addr = (kprobe_opcode_t *)read_addr;
				ret = register_kretprobe(&kasumi_krp_cmdline_read);
				if (ret == 0) {
					pr_info("Kasumi: cmdline spoofing via kretprobe on %s\n", read_sym);
					kasumi_cmdline_kretprobe_registered = 1;
				}
			}
			if (!kasumi_cmdline_kretprobe_registered) {
				unsigned long cmdline_addr = kasumi_lookup_name("cmdline_proc_show");

				if (cmdline_addr) {
					kasumi_kp_cmdline.addr = (kprobe_opcode_t *)cmdline_addr;
					ret = register_kprobe(&kasumi_kp_cmdline);
					if (ret == 0) {
						pr_info("Kasumi: cmdline spoofing via kprobe on cmdline_proc_show\n");
						kasumi_cmdline_kprobe_registered = 1;
					} else {
						pr_warn("Kasumi: register_kprobe(cmdline_proc_show) failed: %d\n",
							ret);
					}
				} else {
					pr_warn("Kasumi: cmdline_proc_show not found, cmdline spoofing disabled\n");
				}
			}
		} else {
			pr_info("Kasumi: cmdline spoofing via syscall-table read hook\n");
		}
	}

	kasumi_proc_read_hooks_init();

	return 0;
}

void kasumi_proc_hooks_exit(void)
{
	/*
	 * Note: syscall table restoration is intentionally NOT performed here.
	 * kasumi_bootstrap_exit() drives that as PHASE 1 (before any
	 * handler-reachable resource is freed) so that proc-fd proxies, fake
	 * mountinfo, and other state cleaned up below cannot be raced against
	 * by a high-frequency syscall (read/openat) still being dispatched into
	 * our redirect.
	 */
	kasumi_proc_read_hooks_exit();
	if (kasumi_cmdline_kretprobe_registered)
		unregister_kretprobe(&kasumi_krp_cmdline_read);
	if (kasumi_cmdline_kprobe_registered)
		unregister_kprobe(&kasumi_kp_cmdline);
	if (kasumi_prctl_kprobe_registered)
		unregister_kprobe(&kasumi_kp_prctl);
	if (kasumi_reboot_kprobe_registered) {
		unregister_kretprobe(&kasumi_krp_reboot);
		unregister_kprobe(&kasumi_kp_reboot);
	}
	if (kasumi_ni_kprobe_registered) {
		unregister_kretprobe(&kasumi_krp_ni);
		unregister_kprobe(&kasumi_kp_ni);
	}
}
