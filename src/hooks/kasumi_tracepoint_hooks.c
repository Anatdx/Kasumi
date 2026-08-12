/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - tracepoint syscall redirect entry.
 *
 * The tracepoint callback only redirects pt_regs to the shared dispatcher.
 * Hook handlers run later in normal syscall context.
 */
#include <asm/syscall.h>
#include <linux/compat.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/tracepoint.h>

#include "kasumi_syscall_redirect.h"
#include "kasumi_tracepoint_hooks.h"

static struct tracepoint *kasumi_sys_enter_tp;
static bool kasumi_sys_enter_registered;

static void kasumi_find_sys_enter(struct tracepoint *tp, void *priv)
{
	struct tracepoint **result = priv;

	if (!*result && tp->name && !strcmp(tp->name, "sys_enter"))
		*result = tp;
}

static void kasumi_sys_enter_redirect(void *data, struct pt_regs *regs, long id)
{
	struct pt_regs *current_regs;

	(void)data;
	(void)regs;

#ifdef CONFIG_COMPAT
	if (unlikely(is_compat_task()))
		return;
#endif
	if (unlikely(id < 0 || !current || current->pid == 0))
		return;
	if (READ_ONCE(kasumi_syscall_dispatcher_nr) < 0 ||
	    !kasumi_has_syscall_hook((int)id))
		return;

	current_regs = task_pt_regs(current);
	if (unlikely(!current_regs))
		return;

	/*
	 * Do not overwrite a redirect installed by KernelSU or another TSR
	 * consumer. If Kasumi runs first, a later consumer can still replace our
	 * dispatcher number, so the existing root implementation always wins an
	 * overlapping route regardless of tracepoint registration order.
	 */
	if (READ_ONCE(current_regs->syscallno) != id)
		return;

	PT_REGS_ORIG_SYSCALL(current_regs) = id;
	WRITE_ONCE(current_regs->syscallno,
		   READ_ONCE(kasumi_syscall_dispatcher_nr));
}

int kasumi_tracepoint_hooks_init(void)
{
	int ret;

	if (READ_ONCE(kasumi_syscall_dispatcher_nr) < 0)
		return -ENODEV;
	if (kasumi_sys_enter_registered)
		return 0;

	for_each_kernel_tracepoint(kasumi_find_sys_enter,
				   &kasumi_sys_enter_tp);
	if (!kasumi_sys_enter_tp) {
		pr_warn("Kasumi: sys_enter tracepoint unavailable\n");
		return -ENOENT;
	}

	ret = tracepoint_probe_register(kasumi_sys_enter_tp,
					kasumi_sys_enter_redirect, NULL);
	if (ret) {
		pr_warn("Kasumi: sys_enter tracepoint registration failed: %d\n",
			ret);
		kasumi_sys_enter_tp = NULL;
		return ret;
	}

	WRITE_ONCE(kasumi_sys_enter_registered, true);
	pr_info("Kasumi: TSR sys_enter redirect registered\n");
	return 0;
}

void kasumi_tracepoint_hooks_exit(void)
{
	if (!kasumi_sys_enter_registered || !kasumi_sys_enter_tp)
		return;

	WRITE_ONCE(kasumi_sys_enter_registered, false);
	tracepoint_probe_unregister(kasumi_sys_enter_tp,
				    kasumi_sys_enter_redirect, NULL);
	tracepoint_synchronize_unregister();
	kasumi_sys_enter_tp = NULL;
	pr_info("Kasumi: TSR sys_enter redirect unregistered\n");
}
