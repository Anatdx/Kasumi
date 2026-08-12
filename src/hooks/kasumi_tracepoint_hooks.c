/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - tracepoint syscall redirect entry.
 *
 * The tracepoint callback only redirects pt_regs to the shared dispatcher.
 * Hook handlers run later in normal syscall context.
 */
#include <asm/syscall.h>
#include <linux/compat.h>
#include <linux/llist.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <linux/tracepoint.h>

#include "kasumi_syscall_redirect.h"
#include "kasumi_path_policy.h"
#include "kasumi_tracepoint_hooks.h"

static struct tracepoint *kasumi_sys_enter_tp;
static bool kasumi_sys_enter_registered;

/*
 * Keep enough allocation-free guards for ordinary syscall concurrency.  If
 * an RCU grace period temporarily retains all reserve entries, GFP_ATOMIC is
 * a safe overflow path from the sys_enter tracepoint callback.
 */
#define KASUMI_REDIRECT_GUARD_RESERVE 64

struct kasumi_redirect_guard {
	struct callback_head work;
	struct rcu_head rcu;
	struct llist_node free_node;
	bool from_reserve;
};

static struct llist_head kasumi_redirect_guard_freelist;
static struct kasumi_redirect_guard
	kasumi_redirect_guard_reserve[KASUMI_REDIRECT_GUARD_RESERVE];

static void kasumi_redirect_guard_free(struct kasumi_redirect_guard *guard)
{
	if (guard->from_reserve)
		llist_add(&guard->free_node, &kasumi_redirect_guard_freelist);
	else
		kfree(guard);
}

static struct kasumi_redirect_guard *kasumi_redirect_guard_alloc(void)
{
	struct kasumi_redirect_guard *guard;
	struct llist_node *node;

	node = llist_del_first(&kasumi_redirect_guard_freelist);
	if (node) {
		guard = container_of(node, struct kasumi_redirect_guard,
				     free_node);
		memset(guard, 0, sizeof(*guard));
		guard->from_reserve = true;
		return guard;
	}

	return kzalloc(sizeof(*guard), GFP_ATOMIC);
}

static void kasumi_redirect_guard_release_rcu(struct rcu_head *rcu)
{
	struct kasumi_redirect_guard *guard =
		container_of(rcu, struct kasumi_redirect_guard, rcu);

	kasumi_redirect_guard_free(guard);
	/* kasumi_bootstrap_exit() ends with rcu_barrier(), which covers this
	 * callback's epilogue if this is the last module reference.
	 */
	module_put(THIS_MODULE);
}

static void kasumi_redirect_guard_task_work(struct callback_head *work)
{
	struct kasumi_redirect_guard *guard =
		container_of(work, struct kasumi_redirect_guard, work);

	/* Do not drop the last module reference from module text directly. */
	call_rcu(&guard->rcu, kasumi_redirect_guard_release_rcu);
}

static bool kasumi_redirect_guard_current(void)
{
	struct kasumi_redirect_guard *guard;
	int ret;

	guard = kasumi_redirect_guard_alloc();
	if (unlikely(!guard)) {
		pr_warn_ratelimited("Kasumi: redirect guard allocation failed\n");
		return false;
	}
	if (unlikely(!try_module_get(THIS_MODULE))) {
		kasumi_redirect_guard_free(guard);
		return false;
	}

	init_task_work(&guard->work, kasumi_redirect_guard_task_work);
	ret = task_work_add(current, &guard->work, TWA_RESUME);
	if (unlikely(ret)) {
		/* Keep the callback and module text alive through an RCU grace
		 * period instead of dropping the reference inside sys_enter.
		 */
		call_rcu(&guard->rcu, kasumi_redirect_guard_release_rcu);
		pr_warn_ratelimited("Kasumi: redirect guard queue failed: %d\n",
				    ret);
		return false;
	}
	return true;
}

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
	if (!kasumi_should_apply_hide_rules())
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
	if (unlikely(!kasumi_redirect_guard_current()))
		return;

	PT_REGS_ORIG_SYSCALL(current_regs) = id;
	WRITE_ONCE(current_regs->syscallno,
		   READ_ONCE(kasumi_syscall_dispatcher_nr));
}

int kasumi_tracepoint_hooks_init(void)
{
	unsigned int i;
	int ret;

	if (READ_ONCE(kasumi_syscall_dispatcher_nr) < 0)
		return -ENODEV;
	if (kasumi_sys_enter_registered)
		return 0;

	init_llist_head(&kasumi_redirect_guard_freelist);
	for (i = 0; i < ARRAY_SIZE(kasumi_redirect_guard_reserve); i++) {
		memset(&kasumi_redirect_guard_reserve[i], 0,
		       sizeof(kasumi_redirect_guard_reserve[i]));
		kasumi_redirect_guard_reserve[i].from_reserve = true;
		llist_add(&kasumi_redirect_guard_reserve[i].free_node,
			  &kasumi_redirect_guard_freelist);
	}

	for_each_kernel_tracepoint(kasumi_find_sys_enter,
				   &kasumi_sys_enter_tp);
	if (!kasumi_sys_enter_tp) {
		pr_warn("Kasumi: sys_enter tracepoint unavailable\n");
		kasumi_sys_enter_tp = NULL;
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

bool kasumi_tracepoint_hooks_active(void)
{
	return READ_ONCE(kasumi_sys_enter_registered);
}
