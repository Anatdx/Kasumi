/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - proc producer hooks and the reboot GET_FD entry.
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
#include <linux/task_work.h>
#include <linux/vmalloc.h>
#include <linux/jhash.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/rcupdate.h>
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
#include "kasumi_store.h"
#include "kasumi_entrypoints.h"
#include "kasumi_path_policy.h"
#include "kasumi_proc_hooks.h"
#include "kasumi_syscall_redirect.h"
#include "kasumi_fake_mountinfo.h"

/*
 * GET_FD uses a narrow reboot kprobe. The probe only validates scalar
 * arguments and queues task_work; fd allocation and user access run later in
 * normal task context before returning to userspace.
 */
struct kasumi_getfd_task_work {
	struct callback_head cb;
	struct rcu_head rcu;
	int __user *outp;
};

static atomic_t kasumi_getfd_pending = ATOMIC_INIT(0);
static atomic_t kasumi_getfd_accepting = ATOMIC_INIT(0);

static void kasumi_getfd_task_work_release_rcu(struct rcu_head *rcu)
{
	struct kasumi_getfd_task_work *tw =
		container_of(rcu, struct kasumi_getfd_task_work, rcu);

	kfree(tw);
	atomic_dec(&kasumi_getfd_pending);
	/* kasumi_bootstrap_exit() ends with rcu_barrier(), which covers this
	 * callback's epilogue if this is the last module reference.
	 */
	module_put(THIS_MODULE);
}

static void kasumi_getfd_task_work_func(struct callback_head *cb)
{
	struct kasumi_getfd_task_work *tw =
		container_of(cb, struct kasumi_getfd_task_work, cb);
	int fd = atomic_read(&kasumi_getfd_accepting) ?
		kasumi_install_anon_fd(tw->outp) : -ESHUTDOWN;

	if (fd < 0)
		(void)put_user(fd, tw->outp);
	/* Do not drop the last module reference from module text directly. */
	call_rcu(&tw->rcu, kasumi_getfd_task_work_release_rcu);
}

static int kasumi_queue_getfd_task_work(int __user *outp)
{
	struct kasumi_getfd_task_work *tw;

	if (!outp || !access_ok(outp, sizeof(*outp)))
		return -EFAULT;
	if (!atomic_read(&kasumi_getfd_accepting))
		return -ESHUTDOWN;

	tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return -ENOMEM;
	if (!try_module_get(THIS_MODULE)) {
		kfree(tw);
		return -ENODEV;
	}
	atomic_inc(&kasumi_getfd_pending);

	tw->outp = outp;
	tw->cb.func = kasumi_getfd_task_work_func;
	if (!kasumi_task_work_add_ptr ||
	    kasumi_task_work_add_ptr(current, &tw->cb, TWA_RESUME)) {
		call_rcu(&tw->rcu, kasumi_getfd_task_work_release_rcu);
		return -ESRCH;
	}

	return 0;
}

static int kasumi_reboot_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs;
	unsigned long a0, a1, a2;
	int __user *outp;

	(void)p;
#if defined(__aarch64__)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
	real_regs = (struct pt_regs *)regs->regs[0];
#else
	real_regs = regs;
#endif
	if (!real_regs)
		return 0;
	a0 = real_regs->regs[0];
	a1 = real_regs->regs[1];
	a2 = real_regs->regs[2];
	outp = (int __user *)(unsigned long)real_regs->regs[3];
#elif defined(__x86_64__)
	real_regs = (struct pt_regs *)regs->di;
	if (!real_regs)
		return 0;
	a0 = real_regs->di;
	a1 = real_regs->si;
	a2 = real_regs->dx;
	outp = (int __user *)(unsigned long)real_regs->r10;
#else
	return 0;
#endif

	if (a0 != KSM_MAGIC1 || a1 != KSM_MAGIC2 ||
	    a2 != (unsigned long)KSM_CMD_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;

	(void)kasumi_queue_getfd_task_work(outp);
	return 0;
}

static struct kprobe kasumi_kp_reboot = {
	.pre_handler = kasumi_reboot_pre,
};

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
	if (!kasumi_policy_current_is_spoof_target())
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

int kasumi_proc_hooks_init(bool skip_getfd, bool no_tracepoint, bool skip_extra_kprobes)
{
	(void)no_tracepoint;
	atomic_set(&kasumi_getfd_pending, 0);
	atomic_set(&kasumi_getfd_accepting, !skip_getfd);
	if (!skip_getfd) {
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
		if (!reboot_addr) {
			pr_err("Kasumi: reboot syscall symbol not found\n");
			return -ENOENT;
		}

		kasumi_kp_reboot.addr = (kprobe_opcode_t *)reboot_addr;
		ret = register_kprobe(&kasumi_kp_reboot);
		if (ret) {
			pr_err("Kasumi: register_kprobe(reboot) failed: %d\n", ret);
			return ret;
		}
		kasumi_reboot_kprobe_registered = 1;
		pr_info("Kasumi: GET_FD via reboot kprobe\n");
	} else {
		pr_alert("Kasumi: skipping GET_FD reboot kprobe\n");
	}

	if (!skip_extra_kprobes) {
		int ret;
		unsigned long cmdline_addr = kasumi_lookup_name("cmdline_proc_show");

		if (cmdline_addr) {
			kasumi_kp_cmdline.addr = (kprobe_opcode_t *)cmdline_addr;
			ret = register_kprobe(&kasumi_kp_cmdline);
			if (ret == 0) {
				pr_info("Kasumi: cmdline spoofing via cmdline_proc_show\n");
				kasumi_cmdline_kprobe_registered = 1;
			} else {
				pr_warn("Kasumi: register_kprobe(cmdline_proc_show) failed: %d\n",
					ret);
			}
		} else {
			pr_warn("Kasumi: cmdline_proc_show not found, cmdline spoofing disabled\n");
		}
	}

	kasumi_proc_read_hooks_init();

	return 0;
}

unsigned int kasumi_proc_getfd_pending(void)
{
	return (unsigned int)atomic_read(&kasumi_getfd_pending);
}

void kasumi_proc_hooks_stop_new(void)
{
	/*
	 * Note: TSR teardown is intentionally NOT performed here.
	 * kasumi_bootstrap_exit() unregisters the tracepoint and restores the
	 * dispatcher slot in PHASE 1 (before any
	 * handler-reachable resource is freed) so that proc-fd proxies, fake
	 * mountinfo, and other state cleaned up below cannot be raced against
	 * by openat still being dispatched into
	 * our redirect.
	 */
	atomic_set(&kasumi_getfd_accepting, 0);
	kasumi_proc_read_hooks_stop_new();
	if (kasumi_cmdline_kprobe_registered) {
		unregister_kprobe(&kasumi_kp_cmdline);
		kasumi_cmdline_kprobe_registered = 0;
	}
	if (kasumi_reboot_kprobe_registered) {
		unregister_kprobe(&kasumi_kp_reboot);
		kasumi_reboot_kprobe_registered = 0;
	}
}

void kasumi_proc_hooks_exit(void)
{
	kasumi_proc_hooks_stop_new();
	kasumi_proc_read_hooks_exit();
}
