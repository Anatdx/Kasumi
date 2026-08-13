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
#include <linux/limits.h>
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
#include "kasumi_root_detection.h"
#include "kasumi_runtime.h"
#include "kasumi_task_marker.h"
#include "kasumi_tracepoint_hooks.h"

static struct tracepoint *kasumi_sys_enter_tp;
static bool kasumi_sys_enter_registered;
static bool kasumi_sys_enter_ready;
static bool kasumi_sys_enter_exclusive;
static bool kasumi_sys_enter_ksu_shared;
static void *kasumi_ksu_sys_enter_handler;
static void *kasumi_ksu_sys_enter_handler_cfi;
static void (*kasumi_ksu_mark_running_process)(void);

/*
 * Keep enough allocation-free guards for ordinary syscall concurrency.  If
 * an RCU grace period temporarily retains all reserve entries, GFP_ATOMIC is
 * a safe overflow path from the sys_enter tracepoint callback.
 */
#define KASUMI_REDIRECT_GUARD_RESERVE 64
/* Upstream KernelSU uses INT_MIN. Equal-priority probes retain registration
 * order, so a later-loaded Kasumi runs afterwards and can preserve the
 * KernelSU dispatcher as the next link for overlapping routes.
 */
#define KASUMI_SYS_ENTER_PRIO INT_MIN

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
	ret = kasumi_task_work_add_ptr(current, &guard->work, TWA_RESUME);
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
	if (!READ_ONCE(kasumi_sys_enter_registered))
		return;

#ifdef CONFIG_COMPAT
	if (unlikely(is_compat_task()))
		return;
#endif
	if (unlikely(id < 0 || !current || current->pid == 0))
		return;
	if (READ_ONCE(kasumi_syscall_dispatcher_nr) < 0 ||
	    !kasumi_has_syscall_hook((int)id))
		return;
	if (!kasumi_policy_current_is_view_target() ||
	    !kasumi_policy_view_tsr_demand()) {
		kasumi_task_marker_reconcile_current();
		return;
	}

	current_regs = task_pt_regs(current);
	if (unlikely(!current_regs))
		return;

	if (!kasumi_syscall_redirect_claimable(
		(int)id, READ_ONCE(current_regs->syscallno)))
		return;
	if (unlikely(!kasumi_redirect_guard_current()))
		return;

	PT_REGS_ORIG_SYSCALL(current_regs) = id;
	WRITE_ONCE(current_regs->syscallno,
		   READ_ONCE(kasumi_syscall_dispatcher_nr));
}

enum kasumi_sys_enter_consumers {
	KASUMI_SYS_ENTER_OTHER = 0,
	KASUMI_SYS_ENTER_EMPTY,
	KASUMI_SYS_ENTER_KSU_ONLY,
	KASUMI_SYS_ENTER_KASUMI_ONLY,
	KASUMI_SYS_ENTER_KSU_AND_KASUMI,
};

static bool kasumi_is_ksu_sys_enter_func(void *func)
{
	return func && (func == READ_ONCE(kasumi_ksu_sys_enter_handler) ||
			func == READ_ONCE(kasumi_ksu_sys_enter_handler_cfi));
}

static enum kasumi_sys_enter_consumers kasumi_sys_enter_consumers(void)
{
	struct tracepoint_func *funcs;
	bool seen_kasumi = false;
	bool seen_ksu = false;
	bool other = false;
	unsigned int i;

	if (!kasumi_sys_enter_tp)
		return KASUMI_SYS_ENTER_OTHER;
	rcu_read_lock();
	funcs = rcu_dereference(kasumi_sys_enter_tp->funcs);
	if (funcs) {
		for (i = 0; READ_ONCE(funcs[i].func); i++) {
			void *func = READ_ONCE(funcs[i].func);

			if (func == kasumi_sys_enter_redirect && !seen_kasumi)
				seen_kasumi = true;
			else if (kasumi_is_ksu_sys_enter_func(func) && !seen_ksu)
				seen_ksu = true;
			else
				other = true;
		}
	}
	rcu_read_unlock();
	if (other)
		return KASUMI_SYS_ENTER_OTHER;
	if (seen_kasumi && seen_ksu)
		return KASUMI_SYS_ENTER_KSU_AND_KASUMI;
	if (seen_kasumi)
		return KASUMI_SYS_ENTER_KASUMI_ONLY;
	if (seen_ksu)
		return KASUMI_SYS_ENTER_KSU_ONLY;
	return KASUMI_SYS_ENTER_EMPTY;
}

bool kasumi_tracepoint_hooks_owned_mark_clear_safe(void)
{
	enum kasumi_sys_enter_consumers state = kasumi_sys_enter_consumers();

	return READ_ONCE(kasumi_sys_enter_registered) &&
	       (state == KASUMI_SYS_ENTER_KASUMI_ONLY ||
		state == KASUMI_SYS_ENTER_KSU_AND_KASUMI);
}

bool kasumi_tracepoint_hooks_exclusive_owner(void)
{
	return READ_ONCE(kasumi_sys_enter_exclusive) &&
	       kasumi_sys_enter_consumers() == KASUMI_SYS_ENTER_KASUMI_ONLY;
}

bool kasumi_tracepoint_hooks_ksu_shared(void)
{
	return READ_ONCE(kasumi_sys_enter_ksu_shared) &&
	       kasumi_sys_enter_consumers() ==
		KASUMI_SYS_ENTER_KSU_AND_KASUMI;
}

int kasumi_tracepoint_hooks_init(void)
{
	unsigned int i;

	if (READ_ONCE(kasumi_syscall_dispatcher_nr) < 0)
		return -ENODEV;
	if (READ_ONCE(kasumi_sys_enter_ready))
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
	if (READ_ONCE(kasumi_root_mask) & KASUMI_ROOT_KSU_RDR) {
		kasumi_ksu_sys_enter_handler =
			(void *)kasumi_lookup_name_quiet("ksu_sys_enter_handler");
		kasumi_ksu_sys_enter_handler_cfi =
			(void *)kasumi_lookup_callable_quiet("ksu_sys_enter_handler");
		kasumi_ksu_mark_running_process =
			(void *)kasumi_lookup_callable_quiet(
				"ksu_mark_running_process");
	}

	WRITE_ONCE(kasumi_sys_enter_ready, true);
	pr_info("Kasumi: TSR sys_enter redirect prepared\n");
	return 0;
}

int kasumi_tracepoint_hooks_set_enabled(bool enabled)
{
	enum kasumi_sys_enter_consumers before;
	enum kasumi_sys_enter_consumers after;
	int ret;

	if (!READ_ONCE(kasumi_sys_enter_ready) || !kasumi_sys_enter_tp)
		return enabled ? -ENODEV : 0;
	if (enabled == READ_ONCE(kasumi_sys_enter_registered))
		return 0;

	if (enabled) {
		before = kasumi_sys_enter_consumers();
		if (before != KASUMI_SYS_ENTER_EMPTY &&
		    before != KASUMI_SYS_ENTER_KSU_ONLY)
			return -EBUSY;
		if (before == KASUMI_SYS_ENTER_KSU_ONLY &&
		    !READ_ONCE(kasumi_ksu_mark_running_process))
			return -EOPNOTSUPP;
		ret = tracepoint_probe_register_prio(kasumi_sys_enter_tp,
						     kasumi_sys_enter_redirect, NULL,
						     KASUMI_SYS_ENTER_PRIO);
		if (ret) {
			pr_warn("Kasumi: sys_enter registration failed: %d\n", ret);
			return ret;
		}
		WRITE_ONCE(kasumi_sys_enter_registered, true);
		after = kasumi_sys_enter_consumers();
		if ((before == KASUMI_SYS_ENTER_EMPTY &&
		     after != KASUMI_SYS_ENTER_KASUMI_ONLY) ||
		    (before == KASUMI_SYS_ENTER_KSU_ONLY &&
		     after != KASUMI_SYS_ENTER_KSU_AND_KASUMI)) {
			WRITE_ONCE(kasumi_sys_enter_registered, false);
			tracepoint_probe_unregister(kasumi_sys_enter_tp,
						    kasumi_sys_enter_redirect, NULL);
			tracepoint_synchronize_unregister();
			pr_warn("Kasumi: sys_enter consumers changed during registration\n");
			return -EBUSY;
		}
		WRITE_ONCE(kasumi_sys_enter_exclusive,
			   after == KASUMI_SYS_ENTER_KASUMI_ONLY);
		WRITE_ONCE(kasumi_sys_enter_ksu_shared,
			   after == KASUMI_SYS_ENTER_KSU_AND_KASUMI);
		/* syscall_regfunc marks every task for the first sys_enter
		 * subscriber. As the exclusive owner, immediately narrow delivery
		 * back to tasks that actually have VIEW routes.
		 */
		if (after == KASUMI_SYS_ENTER_KASUMI_ONLY)
			kasumi_task_marker_restrict_exclusive();
		pr_info("Kasumi: VIEW TSR sys_enter redirect registered\n");
		return 0;
	}

	/* Disable the callback before detaching it. Owned marks are reconciled
	 * only after tracepoint delivery can no longer enter Kasumi.
	 */
	WRITE_ONCE(kasumi_sys_enter_exclusive, false);
	WRITE_ONCE(kasumi_sys_enter_ksu_shared, false);
	WRITE_ONCE(kasumi_sys_enter_registered, false);
	tracepoint_probe_unregister(kasumi_sys_enter_tp,
				    kasumi_sys_enter_redirect, NULL);
	tracepoint_synchronize_unregister();
	if (READ_ONCE(kasumi_ksu_mark_running_process) &&
	    kasumi_sys_enter_consumers() == KASUMI_SYS_ENTER_KSU_ONLY)
		kasumi_ksu_mark_running_process();
	kasumi_task_marker_reconcile_owned(true);
	pr_info("Kasumi: VIEW TSR sys_enter redirect unregistered\n");
	return 0;
}

void kasumi_tracepoint_hooks_exit(void)
{
	if (!READ_ONCE(kasumi_sys_enter_ready))
		return;

	(void)kasumi_tracepoint_hooks_set_enabled(false);
	WRITE_ONCE(kasumi_sys_enter_ready, false);
	WRITE_ONCE(kasumi_ksu_sys_enter_handler, NULL);
	WRITE_ONCE(kasumi_ksu_sys_enter_handler_cfi, NULL);
	WRITE_ONCE(kasumi_ksu_mark_running_process, NULL);
	kasumi_sys_enter_tp = NULL;
	pr_info("Kasumi: TSR sys_enter redirect stopped\n");
}

bool kasumi_tracepoint_hooks_active(void)
{
	return READ_ONCE(kasumi_sys_enter_registered);
}

bool kasumi_tracepoint_hooks_available(void)
{
	return READ_ONCE(kasumi_sys_enter_ready);
}
