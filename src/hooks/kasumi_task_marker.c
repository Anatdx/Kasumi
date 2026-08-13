/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - syscall tracepoint task marker lifecycle.
 *
 * UID-changing syscall probes do not depend on SYSCALL_TRACEPOINT. Their
 * pre-handlers queue TWA_RESUME work which runs after the syscall and every
 * root-framework specialization hook, but before the task returns to userspace.
 */
#include <linux/cred.h>
#include <linux/kprobes.h>
#include <linux/llist.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/tracepoint.h>
#include <linux/version.h>
#include <linux/xarray.h>

#include "kasumi_path_policy.h"
#include "kasumi_root_detection.h"
#include "kasumi_runtime.h"
#include "kasumi_task_marker.h"
#include "kasumi_tracepoint_hooks.h"

#define KASUMI_MARKER_WORK_RESERVE 32
#define KASUMI_ANDROID_PER_USER_RANGE 100000

#if defined(CONFIG_ARM64)
#define KASUMI_UID_SYSCALL_NAME(_name) "__arm64_sys_" #_name
#elif defined(CONFIG_X86_64)
#define KASUMI_UID_SYSCALL_NAME(_name) "__x64_sys_" #_name
#else
#define KASUMI_UID_SYSCALL_NAME(_name) "__se_sys_" #_name
#endif

struct kasumi_marker_task_work {
	struct callback_head cb;
	struct rcu_head rcu;
	struct llist_node free_node;
	bool from_reserve;
};

struct kasumi_marker_probe {
	struct kprobe kp;
	bool registered;
};

static int kasumi_marker_uid_syscall_pre(struct kprobe *probe,
					 struct pt_regs *regs);
static bool kasumi_marker_uid_selected(uid_t uid);
static KASUMI_NOCFI bool
kasumi_marker_ksu_needs_task(struct task_struct *task);

static struct kasumi_marker_probe kasumi_marker_probes[] = {
	{
		.kp = {
			.symbol_name = KASUMI_UID_SYSCALL_NAME(setresuid),
			.pre_handler = kasumi_marker_uid_syscall_pre,
		},
	},
	{
		.kp = {
			.symbol_name = KASUMI_UID_SYSCALL_NAME(setuid),
			.pre_handler = kasumi_marker_uid_syscall_pre,
		},
	},
	{
		.kp = {
			.symbol_name = KASUMI_UID_SYSCALL_NAME(setreuid),
			.pre_handler = kasumi_marker_uid_syscall_pre,
		},
	},
};

static struct tracepoint *kasumi_sched_process_fork_tp;
static struct tracepoint *kasumi_sched_process_exit_tp;
static struct llist_head kasumi_marker_work_freelist;
static struct kasumi_marker_task_work
	kasumi_marker_work_reserve[KASUMI_MARKER_WORK_RESERVE];
static kasumi_task_marker_uid_predicate_fn kasumi_marker_uid_predicate;
static bool kasumi_marker_ready_state;
static bool kasumi_marker_operational_state;
static bool kasumi_marker_active_state;
static DEFINE_XARRAY(kasumi_marker_owned_marks);
static bool (*kasumi_ksu_is_allow_uid)(uid_t uid);

static inline void kasumi_set_task_tracepoint_flag(struct task_struct *task)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	set_task_syscall_work(task, SYSCALL_TRACEPOINT);
#else
	set_tsk_thread_flag(task, TIF_SYSCALL_TRACEPOINT);
#endif
}

static inline void kasumi_clear_task_tracepoint_flag(struct task_struct *task)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	clear_task_syscall_work(task, SYSCALL_TRACEPOINT);
#else
	clear_tsk_thread_flag(task, TIF_SYSCALL_TRACEPOINT);
#endif
}

static inline bool
kasumi_test_and_set_task_tracepoint_flag(struct task_struct *task)
{
	return test_and_set_tsk_thread_flag(task, TIF_SYSCALL_TRACEPOINT);
}

static void kasumi_mark_task_tracepoint_owned(struct task_struct *task)
{
	unsigned long index = (unsigned long)task;
	void *old;

	if (!task)
		return;
	xa_lock(&kasumi_marker_owned_marks);
	old = xa_load(&kasumi_marker_owned_marks, index);
	if (old == task) {
		kasumi_set_task_tracepoint_flag(task);
		goto out_unlock;
	}
	/* A pre-existing mark belongs to KernelSU or another consumer. Do not
	 * record ownership merely because Kasumi also needs delivery.
	 */
	if (old || kasumi_test_and_set_task_tracepoint_flag(task))
		goto out_unlock;
	get_task_struct(task);
	old = __xa_store(&kasumi_marker_owned_marks, index, task, GFP_NOWAIT);
	if (xa_is_err(old)) {
		put_task_struct(task);
		if (kasumi_tracepoint_hooks_owned_mark_clear_safe())
			kasumi_clear_task_tracepoint_flag(task);
	}
out_unlock:
	xa_unlock(&kasumi_marker_owned_marks);
}

static bool kasumi_adopt_inherited_mark(struct task_struct *parent,
					struct task_struct *child)
{
	unsigned long parent_index = (unsigned long)parent;
	unsigned long child_index = (unsigned long)child;
	void *old;
	bool adopted = false;

	if (!parent || !child)
		return false;
	xa_lock(&kasumi_marker_owned_marks);
	if (xa_load(&kasumi_marker_owned_marks, parent_index) != parent ||
	    xa_load(&kasumi_marker_owned_marks, child_index))
		goto out_unlock;
	get_task_struct(child);
	old = __xa_store(&kasumi_marker_owned_marks, child_index, child,
			 GFP_NOWAIT);
	if (xa_is_err(old))
		put_task_struct(child);
	else
		adopted = true;
out_unlock:
	xa_unlock(&kasumi_marker_owned_marks);
	return adopted;
}

static void kasumi_reconcile_task_owned(struct task_struct *task)
{
	unsigned long index = (unsigned long)task;
	void *old;

	if (!task)
		return;
	xa_lock(&kasumi_marker_owned_marks);
	old = xa_load(&kasumi_marker_owned_marks, index);
	xa_unlock(&kasumi_marker_owned_marks);
	if (old != task) {
		if (kasumi_tracepoint_hooks_exclusive_owner())
			kasumi_clear_task_tracepoint_flag(task);
		return;
	}
	if (kasumi_marker_ksu_needs_task(task) ||
	    !kasumi_tracepoint_hooks_owned_mark_clear_safe())
		return;
	old = xa_cmpxchg(&kasumi_marker_owned_marks, index, task, NULL,
			 GFP_ATOMIC);
	if (old == task) {
		kasumi_clear_task_tracepoint_flag(task);
		put_task_struct(task);
	}
}

static KASUMI_NOCFI bool
kasumi_marker_ksu_needs_task(struct task_struct *task)
{
	bool (*provider)(uid_t uid);
	uid_t uid = __kuid_val(task_uid(task));
	uid_t appid = uid % KASUMI_ANDROID_PER_USER_RANGE;

	if (!(READ_ONCE(kasumi_root_mask) & KASUMI_ROOT_KSU_RDR))
		return false;
	/* Upstream KernelSU also marks init, shell, zygote and KSU-domain root.
	 * Kasumi owns marks only for ordinary VIEW apps, so preserve any mark
	 * after such a task changes into a non-app identity.
	 */
	if (!((appid >= 10000 && appid <= 19999) ||
	      (appid >= 90000 && appid <= 99999)))
		return true;
	provider = READ_ONCE(kasumi_ksu_is_allow_uid);
	/* Unknown KernelSU variants are preserved rather than unmarked. */
	if (!provider)
		return true;
	return provider(uid);
}

void kasumi_task_marker_reconcile_owned(bool release_all)
{
	unsigned long index = 0;
	bool clear_safe = kasumi_tracepoint_hooks_owned_mark_clear_safe();

	for (;;) {
		struct task_struct *task;
		unsigned long found = index;
		bool wanted;
		void *old;

		xa_lock(&kasumi_marker_owned_marks);
		task = xa_find(&kasumi_marker_owned_marks, &found, ULONG_MAX,
			       XA_PRESENT);
		if (task)
			get_task_struct(task);
		xa_unlock(&kasumi_marker_owned_marks);
		if (!task)
			break;

		wanted = !release_all &&
			smp_load_acquire(&kasumi_marker_active_state) &&
			kasumi_marker_uid_selected(__kuid_val(task_uid(task)));
		if (release_all) {
			old = xa_cmpxchg(&kasumi_marker_owned_marks, found, task,
					 NULL, GFP_ATOMIC);
			if (old == task)
				put_task_struct(task);
		} else if (!wanted && kasumi_marker_ksu_needs_task(task)) {
			old = xa_cmpxchg(&kasumi_marker_owned_marks, found, task,
					 NULL, GFP_ATOMIC);
			if (old == task)
				put_task_struct(task);
		} else if (!wanted && clear_safe) {
			old = xa_cmpxchg(&kasumi_marker_owned_marks, found, task,
					 NULL, GFP_ATOMIC);
			if (old == task) {
				kasumi_clear_task_tracepoint_flag(task);
				put_task_struct(task);
			}
		}

		put_task_struct(task);
		if (found == ULONG_MAX)
			break;
		index = found + 1;
	}
}

void kasumi_task_marker_reconcile_current(void)
{
	unsigned long index = (unsigned long)current;
	struct task_struct *owned;
	bool wanted;

	rcu_read_lock();
	owned = xa_load(&kasumi_marker_owned_marks, index);
	rcu_read_unlock();
	wanted = smp_load_acquire(&kasumi_marker_active_state) &&
		kasumi_marker_uid_selected(__kuid_val(task_uid(current)));
	if (wanted)
		return;
	if (owned != current) {
		if (kasumi_tracepoint_hooks_exclusive_owner())
			kasumi_clear_task_tracepoint_flag(current);
		return;
	}
	if (kasumi_marker_ksu_needs_task(current)) {
		if (xa_cmpxchg(&kasumi_marker_owned_marks, index, current, NULL,
			       GFP_ATOMIC) == current)
			put_task_struct(current);
		return;
	}
	if (!kasumi_tracepoint_hooks_owned_mark_clear_safe())
		return;
	if (xa_cmpxchg(&kasumi_marker_owned_marks, index, current, NULL,
		       GFP_ATOMIC) == current) {
		kasumi_clear_task_tracepoint_flag(current);
		put_task_struct(current);
	}
}

static bool kasumi_marker_uid_selected(uid_t uid)
{
	kasumi_task_marker_uid_predicate_fn predicate;

	predicate = READ_ONCE(kasumi_marker_uid_predicate);
	return predicate && predicate(uid);
}

static void kasumi_marker_work_free(struct kasumi_marker_task_work *work)
{
	if (work->from_reserve)
		llist_add(&work->free_node, &kasumi_marker_work_freelist);
	else
		kfree(work);
}

static struct kasumi_marker_task_work *kasumi_marker_work_alloc(void)
{
	struct kasumi_marker_task_work *work;
	struct llist_node *node;

	node = kasumi_llist_del_first(&kasumi_marker_work_freelist);
	if (node) {
		work = container_of(node, struct kasumi_marker_task_work,
				    free_node);
		memset(work, 0, sizeof(*work));
		work->from_reserve = true;
		return work;
	}

	return kzalloc(sizeof(*work), GFP_ATOMIC);
}

static void kasumi_marker_work_release_rcu(struct rcu_head *rcu)
{
	struct kasumi_marker_task_work *work =
		container_of(rcu, struct kasumi_marker_task_work, rcu);

	kasumi_marker_work_free(work);
	/* kasumi_bootstrap_exit() ends with rcu_barrier(), which covers this
	 * callback's epilogue if this is the last module reference.
	 */
	module_put(THIS_MODULE);
}

static void kasumi_marker_task_work_func(struct callback_head *cb)
{
	struct kasumi_marker_task_work *work =
		container_of(cb, struct kasumi_marker_task_work, cb);
	uid_t uid = __kuid_val(task_uid(current));

	/* Pairs with marker activation after the provider has been pinned. */
	if (smp_load_acquire(&kasumi_marker_active_state)) {
		if (kasumi_policy_uid_is_spoof_target(uid)) {
			kasumi_task_marker_reconcile_current();
		} else if (kasumi_marker_uid_selected(uid)) {
			kasumi_mark_task_tracepoint_owned(current);
		} else {
			kasumi_task_marker_reconcile_current();
		}
	}

	/* Do not drop the last module reference from module text directly. */
	call_rcu(&work->rcu, kasumi_marker_work_release_rcu);
}

static void kasumi_marker_queue_task(struct task_struct *task)
{
	struct kasumi_marker_task_work *work;

	/*
	 * Queue while the lifecycle hook is ready, even if policy arming has not
	 * published active yet. This closes the race where a UID syscall begins
	 * before enable's task scan and completes as a selected UID afterwards.
	 * The callback rechecks active before marking.
	 */
	if (!smp_load_acquire(&kasumi_marker_operational_state))
		return;
	if (!task || unlikely((task->flags & PF_KTHREAD) ||
			    !READ_ONCE(task->mm)))
		return;

	work = kasumi_marker_work_alloc();
	if (unlikely(!work)) {
		pr_warn_ratelimited("Kasumi: task marker work reserve exhausted\n");
		return;
	}
	if (unlikely(!try_module_get(THIS_MODULE))) {
		kasumi_marker_work_free(work);
		return;
	}

	work->cb.func = kasumi_marker_task_work_func;
	if (unlikely(kasumi_task_work_add_ptr(task, &work->cb, TWA_RESUME))) {
		/* Keep this function and the release callback alive through a grace
		 * period instead of dropping the reference in the kprobe handler.
		 */
		call_rcu(&work->rcu, kasumi_marker_work_release_rcu);
		pr_warn_ratelimited("Kasumi: task marker task_work rejected\n");
	}
}

static void kasumi_marker_queue_current(void)
{
	kasumi_marker_queue_task(current);
}

static int kasumi_marker_uid_syscall_pre(struct kprobe *probe,
					 struct pt_regs *regs)
{
	(void)probe;
	(void)regs;
	kasumi_marker_queue_current();
	return 0;
}

static void kasumi_marker_find_fork_tracepoint(struct tracepoint *tp, void *priv)
{
	struct tracepoint **result = priv;

	if (!*result && tp->name && !strcmp(tp->name, "sched_process_fork"))
		*result = tp;
}

static void kasumi_marker_find_exit_tracepoint(struct tracepoint *tp, void *priv)
{
	struct tracepoint **result = priv;

	if (!*result && tp->name && !strcmp(tp->name, "sched_process_exit"))
		*result = tp;
}

static void kasumi_marker_process_fork(void *data, struct task_struct *parent,
				       struct task_struct *child)
{
	uid_t uid;
	bool inherited;

	(void)data;
	/* Pairs with marker activation after the provider has been pinned. */
	if (!smp_load_acquire(&kasumi_marker_active_state) || unlikely(!child))
		return;

	uid = __kuid_val(task_uid(child));
	/* A child inherits the delivery bit. If the parent mark is Kasumi-owned,
	 * preserve that provenance so a child outside VIEW can be reconciled.
	 */
	inherited = kasumi_adopt_inherited_mark(parent, child);
	if (kasumi_policy_uid_is_spoof_target(uid)) {
		if (inherited || kasumi_tracepoint_hooks_exclusive_owner())
			kasumi_reconcile_task_owned(child);
		kasumi_marker_queue_task(child);
	} else if (kasumi_marker_uid_selected(uid)) {
		kasumi_mark_task_tracepoint_owned(child);
	} else if (inherited || kasumi_tracepoint_hooks_exclusive_owner()) {
		kasumi_reconcile_task_owned(child);
	}
}

static void kasumi_marker_process_exit(void *data, struct task_struct *task)
{
	void *old;

	(void)data;
	if (!task)
		return;
	old = xa_erase(&kasumi_marker_owned_marks, (unsigned long)task);
	if (old == task)
		put_task_struct(task);
}

static unsigned int kasumi_marker_scan_targets(bool apply_spoof)
{
	struct task_struct *group;
	struct task_struct *task;
	unsigned int marked = 0;

	rcu_read_lock();
	for_each_process_thread(group, task) {
		uid_t uid;

		if (unlikely(!READ_ONCE(kasumi_marker_active_state)))
			break;
		if (task->flags & PF_KTHREAD)
			continue;

		uid = __kuid_val(task_uid(task));
		if (apply_spoof && kasumi_policy_uid_is_spoof_target(uid)) {
			/* A KernelSU umount target or isolated task has no VIEW routes.
			 * When the only consumers are KernelSU and Kasumi, neither needs
			 * a delivery mark for this task; clearing also heals marks left by
			 * an older Kasumi activation.
			 */
			kasumi_marker_queue_task(task);
		} else if (kasumi_marker_uid_selected(uid)) {
			kasumi_mark_task_tracepoint_owned(task);
			marked++;
		}
	}
	rcu_read_unlock();
	return marked;
}

void kasumi_task_marker_refresh(void)
{
	unsigned int marked;

	if (!READ_ONCE(kasumi_marker_ready_state) ||
	    !READ_ONCE(kasumi_marker_operational_state) ||
	    !READ_ONCE(kasumi_marker_active_state))
		return;

	marked = kasumi_marker_scan_targets(false);
	pr_info("Kasumi: task marker refreshed (selected=%u)\n", marked);
}

void kasumi_task_marker_refresh_scopes(void)
{
	unsigned int marked;

	if (!READ_ONCE(kasumi_marker_ready_state) ||
	    !READ_ONCE(kasumi_marker_operational_state) ||
	    !READ_ONCE(kasumi_marker_active_state))
		return;
	kasumi_task_marker_reconcile_owned(false);
	if (kasumi_tracepoint_hooks_exclusive_owner())
		kasumi_task_marker_restrict_exclusive();
	marked = kasumi_marker_scan_targets(true);
	pr_info("Kasumi: task scopes refreshed (view=%u)\n", marked);
}

void kasumi_task_marker_restrict_exclusive(void)
{
	struct task_struct *group;
	struct task_struct *task;
	unsigned int marked = 0;
	unsigned int cleared = 0;

	if (!READ_ONCE(kasumi_marker_ready_state) ||
	    !READ_ONCE(kasumi_marker_operational_state))
		return;

	rcu_read_lock();
	for_each_process_thread(group, task) {
		uid_t uid;

		if (task->flags & PF_KTHREAD)
			continue;
		uid = __kuid_val(task_uid(task));
		if (kasumi_marker_uid_selected(uid)) {
			kasumi_set_task_tracepoint_flag(task);
			marked++;
		} else {
			kasumi_clear_task_tracepoint_flag(task);
			cleared++;
		}
	}
	rcu_read_unlock();
	pr_info("Kasumi: exclusive syscall marker restricted (view=%u clear=%u)\n",
		marked, cleared);
}

void kasumi_task_marker_set_enabled(bool enabled)
{
	if (!READ_ONCE(kasumi_marker_ready_state) ||
	    !READ_ONCE(kasumi_marker_operational_state))
		return;

	/* Publish the pinned policy provider before lifecycle callbacks use it. */
	smp_store_release(&kasumi_marker_active_state, enabled);
	if (enabled)
		kasumi_task_marker_refresh_scopes();
	/* SYSCALL_TRACEPOINT is shared; never clear another consumer's bit. */
}

bool kasumi_task_marker_available(void)
{
	return READ_ONCE(kasumi_marker_ready_state);
}

bool kasumi_task_marker_ready(void)
{
	return READ_ONCE(kasumi_marker_ready_state) &&
	       smp_load_acquire(&kasumi_marker_operational_state);
}

bool kasumi_task_marker_active(void)
{
	return READ_ONCE(kasumi_marker_active_state);
}

static void kasumi_marker_unregister_probes(void)
{
	int i;

	for (i = ARRAY_SIZE(kasumi_marker_probes) - 1; i >= 0; i--) {
		if (!kasumi_marker_probes[i].registered)
			continue;
		unregister_kprobe(&kasumi_marker_probes[i].kp);
		kasumi_marker_probes[i].registered = false;
	}
}

static int kasumi_marker_register_probes(void)
{
	unsigned int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(kasumi_marker_probes); i++) {
		ret = register_kprobe(&kasumi_marker_probes[i].kp);
		if (!ret) {
			kasumi_marker_probes[i].registered = true;
			continue;
		}
		pr_err("Kasumi: uid syscall probe %s failed: %d\n",
		       kasumi_marker_probes[i].kp.symbol_name, ret);
		kasumi_marker_unregister_probes();
		return ret;
	}
	return 0;
}

int kasumi_task_marker_init(kasumi_task_marker_uid_predicate_fn predicate)
{
	unsigned int i;
	int ret;

	if (!predicate)
		return -EINVAL;
	if (READ_ONCE(kasumi_marker_ready_state))
		return 0;

	init_llist_head(&kasumi_marker_work_freelist);
	for (i = 0; i < ARRAY_SIZE(kasumi_marker_work_reserve); i++) {
		memset(&kasumi_marker_work_reserve[i], 0,
		       sizeof(kasumi_marker_work_reserve[i]));
		kasumi_marker_work_reserve[i].from_reserve = true;
		llist_add(&kasumi_marker_work_reserve[i].free_node,
			  &kasumi_marker_work_freelist);
	}

	WRITE_ONCE(kasumi_marker_uid_predicate, predicate);
	ret = kasumi_marker_register_probes();
	if (ret)
		goto err_predicate;

	for_each_kernel_tracepoint(kasumi_marker_find_fork_tracepoint,
				   &kasumi_sched_process_fork_tp);
	if (!kasumi_sched_process_fork_tp) {
		ret = -ENOENT;
		goto err_probes;
	}
	ret = tracepoint_probe_register(kasumi_sched_process_fork_tp,
					kasumi_marker_process_fork, NULL);
	if (ret)
		goto err_fork;

	for_each_kernel_tracepoint(kasumi_marker_find_exit_tracepoint,
				   &kasumi_sched_process_exit_tp);
	if (!kasumi_sched_process_exit_tp) {
		ret = -ENOENT;
		goto err_exit_tp;
	}
	ret = tracepoint_probe_register(kasumi_sched_process_exit_tp,
					kasumi_marker_process_exit, NULL);
	if (ret)
		goto err_exit_register;

	kasumi_ksu_is_allow_uid = (void *)kasumi_lookup_callable_quiet(
		"__ksu_is_allow_uid");

	WRITE_ONCE(kasumi_marker_ready_state, true);
	pr_info("Kasumi: task marker lifecycle initialized\n");
	return 0;

err_exit_register:
	kasumi_sched_process_exit_tp = NULL;
err_exit_tp:
	tracepoint_probe_unregister(kasumi_sched_process_fork_tp,
				    kasumi_marker_process_fork, NULL);
	tracepoint_synchronize_unregister();
err_fork:
	kasumi_sched_process_fork_tp = NULL;
err_probes:
	kasumi_marker_unregister_probes();
err_predicate:
	WRITE_ONCE(kasumi_marker_uid_predicate, NULL);
	return ret;
}

void kasumi_task_marker_start(void)
{
	if (READ_ONCE(kasumi_marker_ready_state))
		smp_store_release(&kasumi_marker_operational_state, true);
}

void kasumi_task_marker_exit(void)
{
	unsigned long index;
	struct task_struct *task;

	smp_store_release(&kasumi_marker_operational_state, false);
	WRITE_ONCE(kasumi_marker_active_state, false);
	WRITE_ONCE(kasumi_marker_ready_state, false);
	kasumi_marker_unregister_probes();
	if (kasumi_sched_process_fork_tp) {
		tracepoint_probe_unregister(kasumi_sched_process_fork_tp,
					    kasumi_marker_process_fork, NULL);
		tracepoint_synchronize_unregister();
		kasumi_sched_process_fork_tp = NULL;
	}
	if (kasumi_sched_process_exit_tp) {
		tracepoint_probe_unregister(kasumi_sched_process_exit_tp,
					    kasumi_marker_process_exit, NULL);
		tracepoint_synchronize_unregister();
		kasumi_sched_process_exit_tp = NULL;
	}
	/* Any marks that could not be cleared safely belong to a still-active
	 * unknown consumer now. Drop only Kasumi's bookkeeping references.
	 */
	index = 0;
	for (;;) {
		xa_lock(&kasumi_marker_owned_marks);
		task = xa_find(&kasumi_marker_owned_marks, &index, ULONG_MAX,
			       XA_PRESENT);
		if (task)
			__xa_erase(&kasumi_marker_owned_marks, index);
		xa_unlock(&kasumi_marker_owned_marks);
		if (!task)
			break;
		put_task_struct(task);
		if (index == ULONG_MAX)
			break;
		index++;
	}
	xa_destroy(&kasumi_marker_owned_marks);
	WRITE_ONCE(kasumi_ksu_is_allow_uid, NULL);
	/* Queued task_work and its deferred RCU release hold THIS_MODULE, so
	 * module exit cannot reach this point while either callback is pending.
	 */
	WRITE_ONCE(kasumi_marker_uid_predicate, NULL);
	pr_info("Kasumi: task marker lifecycle stopped\n");
}
