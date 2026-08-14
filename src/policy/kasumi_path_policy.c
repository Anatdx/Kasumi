/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - path redirect, hide-policy, and allowlist decision logic.
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
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/xarray.h>
#include <uapi/linux/magic.h>
#ifndef EROFS_SUPER_MAGIC
#define EROFS_SUPER_MAGIC 0xe0f5e1e2
#endif
#include <asm/unistd.h>
#include "kasumi_root_detection.h"
#include "kasumi_runtime.h"
#include "kasumi_store.h"
#include "kasumi_path_policy.h"
/* ======================================================================
 * Part 11: Core Logic - Privileged Check / Allowlist
 * ====================================================================== */

bool kasumi_is_privileged_process(void)
{
	pid_t pid = task_tgid_vnr(current);

	if (unlikely(uid_eq(current_uid(), GLOBAL_ROOT_UID)))
		return true;
	if (READ_ONCE(kasumi_daemon_pid) > 0 && pid == READ_ONCE(kasumi_daemon_pid))
		return true;
	return false;
}

/*
 * KernelSU's kernel_umount caller gates ksu_uid_should_umount() with these
 * Android app/isolated ranges. The scalar provider alone can return its
 * default profile for shell or system UIDs, which are not policy targets.
 * Keep the same outer boundary for every Kasumi policy owner.
 */
#define KASUMI_ANDROID_PER_USER_RANGE      100000
#define KASUMI_ANDROID_FIRST_APP_UID        10000
#define KASUMI_ANDROID_LAST_APP_UID         19999
#define KASUMI_ANDROID_FIRST_ISOLATED_UID   90000
#define KASUMI_ANDROID_LAST_ISOLATED_UID    99999

static inline bool kasumi_uid_is_app(uid_t uid)
{
	uid_t appid = uid % KASUMI_ANDROID_PER_USER_RANGE;

	return appid >= KASUMI_ANDROID_FIRST_APP_UID &&
	       appid <= KASUMI_ANDROID_LAST_APP_UID;
}

static inline bool kasumi_uid_is_isolated(uid_t uid)
{
	uid_t appid = uid % KASUMI_ANDROID_PER_USER_RANGE;

	return appid >= KASUMI_ANDROID_FIRST_ISOLATED_UID &&
	       appid <= KASUMI_ANDROID_LAST_ISOLATED_UID;
}

struct kasumi_policy_snapshot {
	struct rcu_head rcu;
	u64 generation;
	u32 owner;
	u32 flags;
	u32 allow_count;
	u32 deny_count;
	struct xarray allow_uids;
	struct xarray deny_uids;
	u32 *allow_uid_list;
	u32 *deny_uid_list;
};

static struct kasumi_policy_snapshot __rcu *kasumi_policy_current;
static atomic64_t kasumi_policy_generation = ATOMIC64_INIT(0);
static struct module *kasumi_ksu_provider_module;
static struct module *kasumi_apatch_provider_module;
static struct module *(*kasumi_module_address_ptr)(unsigned long addr);
static int (*kasumi_core_kernel_text_ptr)(unsigned long addr);

static KASUMI_NOCFI bool kasumi_policy_resolve_module_address(void)
{
	if (!kasumi_module_address_ptr)
		kasumi_module_address_ptr =
			(void *)kasumi_lookup_callable_quiet("__module_address");
	return kasumi_module_address_ptr != NULL;
}

static KASUMI_NOCFI bool kasumi_policy_pin_stable_provider(unsigned long addr,
							    struct module **owner)
{
	struct module *provider;
	bool module_address;

	if (!addr)
		return false;
	if (*owner)
		return true;
	if (!kasumi_policy_resolve_module_address())
		return false;
	if (!kasumi_core_kernel_text_ptr)
		kasumi_core_kernel_text_ptr =
			(void *)kasumi_lookup_callable_quiet("core_kernel_text");
	preempt_disable();
	provider = kasumi_module_address_ptr(addr);
	module_address = provider != NULL;
	if (provider && !try_module_get(provider))
		provider = NULL;
	preempt_enable();
	if (provider)
		*owner = provider;
	if (module_address)
		return provider != NULL;
	/* Reject unpinnable vmalloc/KPM text; only built-in core text is stable. */
	return kasumi_core_kernel_text_ptr && kasumi_core_kernel_text_ptr(addr);
}

static KASUMI_NOCFI bool kasumi_policy_pin_linux_module(unsigned long addr,
						 struct module **owner,
						 bool *is_module)
{
	struct module *provider;

	if (!addr)
		return false;
	if (*owner) {
		*is_module = true;
		return true;
	}
	if (!kasumi_policy_resolve_module_address())
		return false;
	preempt_disable();
	provider = kasumi_module_address_ptr(addr);
	*is_module = provider != NULL;
	if (provider && !try_module_get(provider))
		provider = NULL;
	preempt_enable();
	if (provider)
		*owner = provider;
	return provider != NULL;
}

static void kasumi_policy_unpin_provider(void)
{
	if (kasumi_ksu_provider_module) {
		module_put(kasumi_ksu_provider_module);
		kasumi_ksu_provider_module = NULL;
	}
	if (kasumi_apatch_provider_module) {
		module_put(kasumi_apatch_provider_module);
		kasumi_apatch_provider_module = NULL;
	}
}

static int kasumi_policy_owner_valid(u32 owner)
{
	switch (owner) {
	case KSM_POLICY_OWNER_AUTO:
	case KSM_POLICY_OWNER_KERNELSU:
	case KSM_POLICY_OWNER_APATCH:
	case KSM_POLICY_OWNER_MANUAL:
	case KSM_POLICY_OWNER_DISABLED:
		return 0;
	case KSM_POLICY_OWNER_MAGISK:
		return -EOPNOTSUPP;
	default:
		return -EINVAL;
	}
}

static int kasumi_policy_values_valid(u32 owner, u32 flags,
				      const u32 *allow_uids, u32 allow_count,
				      const u32 *deny_uids, u32 deny_count)
{
	u32 supported = KSM_POLICY_FLAG_USE_ALLOW_UIDS |
			KSM_POLICY_FLAG_USE_DENY_UIDS |
			KSM_POLICY_FLAG_INCLUDE_ISOLATED_UIDS;
	u32 i;
	int ret;

	ret = kasumi_policy_owner_valid(owner);
	if (ret)
		return ret;
	if (flags & ~supported)
		return -EINVAL;
	if ((flags & KSM_POLICY_FLAG_INCLUDE_ISOLATED_UIDS) &&
	    !(flags & KSM_POLICY_FLAG_USE_ALLOW_UIDS))
		return -EINVAL;
	if (owner == KSM_POLICY_OWNER_MANUAL &&
	    !(flags & KSM_POLICY_FLAG_USE_ALLOW_UIDS))
		return -EINVAL;
	if (allow_count > KASUMI_ALLOWLIST_UID_MAX ||
	    deny_count > KASUMI_ALLOWLIST_UID_MAX)
		return -E2BIG;
	if ((allow_count && !allow_uids) || (deny_count && !deny_uids))
		return -EINVAL;
	if (allow_count && !(flags & KSM_POLICY_FLAG_USE_ALLOW_UIDS))
		return -EINVAL;
	if (deny_count && !(flags & KSM_POLICY_FLAG_USE_DENY_UIDS))
		return -EINVAL;
	for (i = 0; i < allow_count; i++)
		if (allow_uids[i] == 0)
			return -EINVAL;
	for (i = 0; i < deny_count; i++)
		if (deny_uids[i] == 0)
			return -EINVAL;
	return 0;
}

static void kasumi_policy_snapshot_destroy(struct kasumi_policy_snapshot *policy)
{
	if (!policy)
		return;
	xa_destroy(&policy->allow_uids);
	xa_destroy(&policy->deny_uids);
	kfree(policy->allow_uid_list);
	kfree(policy->deny_uid_list);
	kfree(policy);
}

static void kasumi_policy_snapshot_free_rcu(struct rcu_head *head)
{
	struct kasumi_policy_snapshot *policy =
		container_of(head, struct kasumi_policy_snapshot, rcu);

	kasumi_policy_snapshot_destroy(policy);
}

static int kasumi_policy_build_uid_list(struct xarray *xa, u32 **snapshot,
					u32 *snapshot_count, const u32 *uids,
					u32 count)
{
	u32 *dense = NULL;
	u32 i;
	u32 j;
	u32 out = 0;
	u32 value;
	int ret;

	if (count) {
		dense = kmalloc_array(count, sizeof(*dense), GFP_KERNEL);
		if (!dense)
			return -ENOMEM;
	}
	for (i = 0; i < count; i++) {
		if (xa_load(xa, uids[i]))
			continue;
		ret = xa_err(xa_store(xa, uids[i], KASUMI_UID_ALLOW_MARKER,
				      GFP_KERNEL));
		if (ret) {
			kfree(dense);
			return ret;
		}
		dense[out++] = uids[i];
	}
	/* Canonical snapshots make GET results stable across input ordering. */
	for (i = 1; i < out; i++) {
		value = dense[i];
		j = i;
		while (j > 0 && dense[j - 1] > value) {
			dense[j] = dense[j - 1];
			j--;
		}
		dense[j] = value;
	}
	*snapshot = dense;
	*snapshot_count = out;
	return 0;
}

static struct kasumi_policy_snapshot *
kasumi_policy_snapshot_create(u32 owner, u32 flags,
			      const u32 *allow_uids, u32 allow_count,
			      const u32 *deny_uids, u32 deny_count)
{
	struct kasumi_policy_snapshot *policy;
	int ret;

	ret = kasumi_policy_values_valid(owner, flags, allow_uids, allow_count,
					 deny_uids, deny_count);
	if (ret)
		return ERR_PTR(ret);
	policy = kzalloc(sizeof(*policy), GFP_KERNEL);
	if (!policy)
		return ERR_PTR(-ENOMEM);
	xa_init(&policy->allow_uids);
	xa_init(&policy->deny_uids);
	policy->owner = owner;
	policy->flags = flags;

	ret = kasumi_policy_build_uid_list(&policy->allow_uids,
					   &policy->allow_uid_list,
					   &policy->allow_count,
					   allow_uids, allow_count);
	if (ret)
		goto err;
	ret = kasumi_policy_build_uid_list(&policy->deny_uids,
					   &policy->deny_uid_list,
					   &policy->deny_count,
					   deny_uids, deny_count);
	if (ret)
		goto err;
	return policy;

err:
	kasumi_policy_snapshot_destroy(policy);
	return ERR_PTR(ret);
}

static void kasumi_policy_publish_locked(struct kasumi_policy_snapshot *policy)
{
	struct kasumi_policy_snapshot *old;

	lockdep_assert_held(&kasumi_config_mutex);
	old = rcu_dereference_protected(kasumi_policy_current,
					lockdep_is_held(&kasumi_config_mutex));
	policy->generation = atomic64_inc_return(&kasumi_policy_generation);
	rcu_assign_pointer(kasumi_policy_current, policy);
	if (old)
		call_rcu(&old->rcu, kasumi_policy_snapshot_free_rcu);
}

static int kasumi_policy_publish_values_locked(u32 owner, u32 flags,
					       const u32 *allow_uids,
					       u32 allow_count,
					       const u32 *deny_uids,
					       u32 deny_count)
{
	struct kasumi_policy_snapshot *policy;

	lockdep_assert_held(&kasumi_config_mutex);
	policy = kasumi_policy_snapshot_create(owner, flags, allow_uids,
					       allow_count, deny_uids,
					       deny_count);
	if (IS_ERR(policy))
		return PTR_ERR(policy);
	kasumi_policy_publish_locked(policy);
	return 0;
}

u32 kasumi_policy_configured_owner(void)
{
	const struct kasumi_policy_snapshot *policy;
	u32 owner = KSM_POLICY_OWNER_AUTO;

	rcu_read_lock();
	policy = rcu_dereference(kasumi_policy_current);
	if (policy)
		owner = policy->owner;
	rcu_read_unlock();
	return owner;
}

static u32 kasumi_policy_validate_effective_owner(u32 owner)
{
	if (owner == KSM_POLICY_OWNER_AUTO)
		owner = READ_ONCE(kasumi_root_policy_owner);
	if (owner == KSM_POLICY_OWNER_KERNELSU &&
	    (!(READ_ONCE(kasumi_root_mask) & KASUMI_ROOT_KSU) ||
	     !READ_ONCE(kasumi_ksu_policy_available)))
		return KSM_POLICY_OWNER_DISABLED;
	if (owner == KSM_POLICY_OWNER_APATCH &&
	    (!(READ_ONCE(kasumi_root_mask) & KASUMI_ROOT_APATCH) ||
	     !kasumi_ap_get_mod_exclude))
		return KSM_POLICY_OWNER_DISABLED;
	if (owner == KSM_POLICY_OWNER_MAGISK || owner == KSM_POLICY_OWNER_AUTO)
		return KSM_POLICY_OWNER_DISABLED;
	return owner;
}

u32 kasumi_policy_effective_owner(void)
{
	return kasumi_policy_validate_effective_owner(
		kasumi_policy_configured_owner());
}

int kasumi_policy_replace(u32 owner, u32 flags,
			  const u32 *allow_uids, u32 allow_count,
			  const u32 *deny_uids, u32 deny_count)
{
	int ret;

	mutex_lock(&kasumi_config_mutex);
	if (READ_ONCE(kasumi_enabled))
		ret = -EBUSY;
	else
		ret = kasumi_policy_publish_values_locked(owner, flags,
							  allow_uids, allow_count,
							  deny_uids, deny_count);
	mutex_unlock(&kasumi_config_mutex);
	return ret;
}

int kasumi_set_policy_owner(u32 owner, u32 flags)
{
	const struct kasumi_policy_snapshot *old;
	const u32 *allow_uids = NULL;
	const u32 *deny_uids = NULL;
	u32 allow_count = 0;
	u32 deny_count = 0;
	int ret;

	mutex_lock(&kasumi_config_mutex);
	if (READ_ONCE(kasumi_enabled)) {
		mutex_unlock(&kasumi_config_mutex);
		return -EBUSY;
	}
	old = rcu_dereference_protected(kasumi_policy_current,
					lockdep_is_held(&kasumi_config_mutex));
	if (old) {
		allow_uids = old->allow_uid_list;
		allow_count = old->allow_count;
		deny_uids = old->deny_uid_list;
		deny_count = old->deny_count;
	}
	if (!(flags & KSM_POLICY_FLAG_USE_ALLOW_UIDS)) {
		allow_uids = NULL;
		allow_count = 0;
	}
	if (!(flags & KSM_POLICY_FLAG_USE_DENY_UIDS)) {
		deny_uids = NULL;
		deny_count = 0;
	}
	ret = kasumi_policy_publish_values_locked(owner, flags, allow_uids,
						  allow_count, deny_uids,
						  deny_count);
	mutex_unlock(&kasumi_config_mutex);
	return ret;
}

int kasumi_replace_policy_uid_list(u32 list, const u32 *uids, u32 count)
{
	const struct kasumi_policy_snapshot *old;
	const u32 *allow_uids = NULL;
	const u32 *deny_uids = NULL;
	u32 owner = KSM_POLICY_OWNER_AUTO;
	u32 flags = 0;
	u32 allow_count = 0;
	u32 deny_count = 0;
	int ret;

	if (list != KSM_POLICY_UID_LIST_ALLOW &&
	    list != KSM_POLICY_UID_LIST_DENY)
		return -EINVAL;
	if (count > KASUMI_ALLOWLIST_UID_MAX)
		return -E2BIG;
	if (count && !uids)
		return -EINVAL;

	mutex_lock(&kasumi_config_mutex);
	if (READ_ONCE(kasumi_enabled)) {
		mutex_unlock(&kasumi_config_mutex);
		return -EBUSY;
	}
	old = rcu_dereference_protected(kasumi_policy_current,
					lockdep_is_held(&kasumi_config_mutex));
	if (old) {
		owner = old->owner;
		flags = old->flags;
		allow_uids = old->allow_uid_list;
		allow_count = old->allow_count;
		deny_uids = old->deny_uid_list;
		deny_count = old->deny_count;
	}
	if (list == KSM_POLICY_UID_LIST_ALLOW) {
		allow_uids = uids;
		allow_count = count;
		flags |= KSM_POLICY_FLAG_USE_ALLOW_UIDS;
	} else {
		deny_uids = uids;
		deny_count = count;
		flags |= KSM_POLICY_FLAG_USE_DENY_UIDS;
	}
	ret = kasumi_policy_publish_values_locked(owner, flags, allow_uids,
						  allow_count, deny_uids,
						  deny_count);
	mutex_unlock(&kasumi_config_mutex);
	return ret;
}

int kasumi_clear_policy_uid_list(u32 list)
{
	const struct kasumi_policy_snapshot *old;
	const u32 *allow_uids = NULL;
	const u32 *deny_uids = NULL;
	u32 owner = KSM_POLICY_OWNER_AUTO;
	u32 flags = 0;
	u32 allow_count = 0;
	u32 deny_count = 0;
	int ret;

	if (list != KSM_POLICY_UID_LIST_ALLOW &&
	    list != KSM_POLICY_UID_LIST_DENY &&
	    list != KSM_POLICY_UID_LIST_ALL)
		return -EINVAL;

	mutex_lock(&kasumi_config_mutex);
	if (READ_ONCE(kasumi_enabled)) {
		mutex_unlock(&kasumi_config_mutex);
		return -EBUSY;
	}
	old = rcu_dereference_protected(kasumi_policy_current,
					lockdep_is_held(&kasumi_config_mutex));
	if (old) {
		owner = old->owner;
		flags = old->flags;
		allow_uids = old->allow_uid_list;
		allow_count = old->allow_count;
		deny_uids = old->deny_uid_list;
		deny_count = old->deny_count;
	}
	if (list == KSM_POLICY_UID_LIST_ALLOW ||
	    list == KSM_POLICY_UID_LIST_ALL) {
		allow_uids = NULL;
		allow_count = 0;
		flags &= ~KSM_POLICY_FLAG_INCLUDE_ISOLATED_UIDS;
		/* MANUAL with an empty allow set is a valid fail-closed policy. */
		if (owner != KSM_POLICY_OWNER_MANUAL)
			flags &= ~KSM_POLICY_FLAG_USE_ALLOW_UIDS;
	}
	if (list == KSM_POLICY_UID_LIST_DENY ||
	    list == KSM_POLICY_UID_LIST_ALL) {
		deny_uids = NULL;
		deny_count = 0;
		flags &= ~KSM_POLICY_FLAG_USE_DENY_UIDS;
	}
	ret = kasumi_policy_publish_values_locked(owner, flags, allow_uids,
						  allow_count, deny_uids,
						  deny_count);
	mutex_unlock(&kasumi_config_mutex);
	return ret;
}

void kasumi_policy_get_state(struct kasumi_policy_state_arg *state)
{
	const struct kasumi_policy_snapshot *policy;

	if (!state)
		return;
	rcu_read_lock();
	policy = rcu_dereference(kasumi_policy_current);
	if (policy) {
		state->generation = policy->generation;
		state->owner = policy->owner;
		state->flags = policy->flags;
		state->allow_count = policy->allow_count;
		state->deny_count = policy->deny_count;
	} else {
		state->generation = 0;
		state->owner = KSM_POLICY_OWNER_AUTO;
		state->flags = 0;
		state->allow_count = 0;
		state->deny_count = 0;
	}
	state->effective_owner =
		kasumi_policy_validate_effective_owner(state->owner);
	state->detected_roots = READ_ONCE(kasumi_root_mask);
	state->max_uid_count = KASUMI_ALLOWLIST_UID_MAX;
	state->enabled = READ_ONCE(kasumi_enabled);
	rcu_read_unlock();
}

int kasumi_policy_copy_uids(u32 list, u32 *uids, u32 capacity,
			    u32 *copied, u32 *total, u64 *generation)
{
	const struct kasumi_policy_snapshot *policy;
	const u32 *source = NULL;
	u32 count = 0;
	u32 nr;
	u64 gen = 0;

	if (list != KSM_POLICY_UID_LIST_ALLOW &&
	    list != KSM_POLICY_UID_LIST_DENY)
		return -EINVAL;
	if (capacity && !uids)
		return -EINVAL;

	rcu_read_lock();
	policy = rcu_dereference(kasumi_policy_current);
	if (policy) {
		gen = policy->generation;
		if (list == KSM_POLICY_UID_LIST_ALLOW) {
			source = policy->allow_uid_list;
			count = policy->allow_count;
		} else {
			source = policy->deny_uid_list;
			count = policy->deny_count;
		}
	}
	nr = min(capacity, count);
	if (nr)
		memcpy(uids, source, nr * sizeof(*uids));
	rcu_read_unlock();

	if (copied)
		*copied = nr;
	if (total)
		*total = count;
	if (generation)
		*generation = gen;
	return 0;
}

int kasumi_policy_reset(void)
{
	return kasumi_policy_replace(KSM_POLICY_OWNER_AUTO, 0, NULL, 0, NULL, 0);
}

void kasumi_policy_shutdown_locked(void)
{
	struct kasumi_policy_snapshot *old;

	lockdep_assert_held(&kasumi_config_mutex);
	old = rcu_dereference_protected(kasumi_policy_current,
					lockdep_is_held(&kasumi_config_mutex));
	RCU_INIT_POINTER(kasumi_policy_current, NULL);
	if (old)
		call_rcu(&old->rcu, kasumi_policy_snapshot_free_rcu);
	kasumi_policy_unpin_provider();
}

static bool kasumi_current_is_app_zygote(void)
{
	const char suffix[] = "_zygote";
	size_t comm_len = strnlen(current->comm, TASK_COMM_LEN);
	size_t suffix_len = sizeof(suffix) - 1;

	if (strncmp(current->comm, "app_zygote", TASK_COMM_LEN) == 0)
		return true;
	if (comm_len < suffix_len)
		return false;
	return memcmp(current->comm + comm_len - suffix_len,
		      suffix, suffix_len) == 0;
}

static KASUMI_NOCFI enum kasumi_policy_scope
kasumi_policy_scope_for_uid(uid_t uid, bool require_enabled)
{
	struct kasumi_policy_snapshot *policy;
	u32 configured_owner;
	u32 owner;
	u32 flags;
	enum kasumi_policy_scope scope = KASUMI_POLICY_SCOPE_NONE;
	bool allow_gate = true;
	bool denied = false;

	/* Acquire the provider/list state published by SET_ENABLED. */
	if (unlikely((!kasumi_uid_is_app(uid) &&
		       !kasumi_uid_is_isolated(uid)) ||
	    (require_enabled && !smp_load_acquire(&kasumi_enabled))))
		return KASUMI_POLICY_SCOPE_NONE;
	/* Isolated app processes always receive concealment, independently of
	 * their transient UID and of any host-app allow/deny list.
	 */
	if (kasumi_uid_is_isolated(uid))
		return KASUMI_POLICY_SCOPE_SPOOF;

	rcu_read_lock();
	policy = rcu_dereference(kasumi_policy_current);
	configured_owner = policy ? policy->owner : KSM_POLICY_OWNER_AUTO;
	flags = policy ? policy->flags : 0;
	owner = configured_owner == KSM_POLICY_OWNER_AUTO ?
		READ_ONCE(kasumi_root_policy_owner) : configured_owner;

	/* AUTO is valid only when root detection selected one supported provider. */
	if (configured_owner == KSM_POLICY_OWNER_AUTO &&
	    !READ_ONCE(kasumi_root_spoof_allowed))
		goto out;

	switch (owner) {
	case KSM_POLICY_OWNER_KERNELSU: {
		kasumi_ksu_uid_should_umount_fn provider;

		if (!(READ_ONCE(kasumi_root_mask) & KASUMI_ROOT_KSU))
			break;
		provider = READ_ONCE(kasumi_ksu_uid_should_umount_ptr);
		if (!provider)
			break;
		scope = provider(uid) ? KASUMI_POLICY_SCOPE_SPOOF :
			KASUMI_POLICY_SCOPE_VIEW;
		break;
	}
	case KSM_POLICY_OWNER_APATCH: {
		int (*provider)(uid_t uid) = READ_ONCE(kasumi_ap_get_mod_exclude);

		if ((READ_ONCE(kasumi_root_mask) & KASUMI_ROOT_APATCH) &&
		    provider)
			scope = provider(uid) != 0 ?
				KASUMI_POLICY_SCOPE_SPOOF : KASUMI_POLICY_SCOPE_VIEW;
		break;
	}
	case KSM_POLICY_OWNER_MANUAL:
		/* Manual policy has no inverse provider set. Its explicit allow
		 * list therefore names spoof targets and never implicitly grants a
		 * virtual view to every other application.
		 */
		if (flags & KSM_POLICY_FLAG_USE_ALLOW_UIDS)
			scope = KASUMI_POLICY_SCOPE_SPOOF;
		break;
	case KSM_POLICY_OWNER_DISABLED:
	case KSM_POLICY_OWNER_MAGISK:
	case KSM_POLICY_OWNER_AUTO:
	default:
		break;
	}

	/* MANUAL is fail-closed without an explicit allow policy. */
	if (owner == KSM_POLICY_OWNER_MANUAL &&
	    !(flags & KSM_POLICY_FLAG_USE_ALLOW_UIDS))
		allow_gate = false;
	else if (flags & KSM_POLICY_FLAG_USE_ALLOW_UIDS)
		allow_gate = policy && xa_load(&policy->allow_uids, uid) != NULL;

	/* A deny entry is the final decision and wins over every other source. */
	if ((flags & KSM_POLICY_FLAG_USE_DENY_UIDS) && policy)
		denied = xa_load(&policy->deny_uids, uid) != NULL;

out:
	rcu_read_unlock();
	return allow_gate && !denied ? scope : KASUMI_POLICY_SCOPE_NONE;
}

KASUMI_NOCFI enum kasumi_policy_scope kasumi_policy_current_scope(void)
{
	return kasumi_policy_scope_for_uid(__kuid_val(task_uid(current)), true);
}

bool kasumi_policy_current_is_view_target(void)
{
	return kasumi_policy_current_scope() == KASUMI_POLICY_SCOPE_VIEW;
}

bool kasumi_policy_current_is_spoof_target(void)
{
	return kasumi_policy_current_scope() == KASUMI_POLICY_SCOPE_SPOOF;
}

bool kasumi_policy_current_is_isolated(void)
{
	return kasumi_uid_is_isolated(__kuid_val(task_uid(current)));
}

KASUMI_NOCFI bool kasumi_policy_uid_is_view_target(uid_t uid)
{
	return kasumi_policy_scope_for_uid(uid, false) ==
		KASUMI_POLICY_SCOPE_VIEW;
}

KASUMI_NOCFI bool kasumi_policy_uid_is_spoof_target(uid_t uid)
{
	return kasumi_policy_scope_for_uid(uid, false) ==
		KASUMI_POLICY_SCOPE_SPOOF;
}

bool kasumi_policy_view_tsr_demand(void)
{
	return atomic_read(&kasumi_tsr_path_count) > 0 ||
	       atomic_read(&kasumi_hide_count) > 0;
}

bool kasumi_policy_uid_needs_view_tsr(uid_t uid)
{
	return kasumi_policy_view_tsr_demand() &&
	       kasumi_policy_uid_is_view_target(uid);
}

bool kasumi_current_is_selinux_guard_target(void)
{
	uid_t uid = __kuid_val(task_uid(current));

	/*
	 * Ordinary hidden apps retain the narrow app-zygote oracle guard. Android
	 * isolated UIDs follow the all-isolated SPOOF boundary.
	 */
	return kasumi_policy_current_is_spoof_target() &&
	       (kasumi_uid_is_isolated(uid) || kasumi_current_is_app_zygote());
}

static void kasumi_policy_mark_ksu_available(void)
{
	u32 root_mask = READ_ONCE(kasumi_root_mask);
	bool ambiguous;

	root_mask |= KASUMI_ROOT_KSU;
	root_mask &= ~KASUMI_ROOT_NON_ROOT;
	ambiguous = root_mask &
		(KASUMI_ROOT_APATCH | KASUMI_ROOT_MAGISK | KASUMI_ROOT_MULTI);
	/* A newly available second provider makes AUTO ambiguous and fail-closed. */
	if (ambiguous) {
		WRITE_ONCE(kasumi_root_spoof_allowed, false);
		root_mask |= KASUMI_ROOT_MULTI;
		WRITE_ONCE(kasumi_root_policy_owner, KSM_POLICY_OWNER_DISABLED);
	} else {
		WRITE_ONCE(kasumi_root_policy_owner, KSM_POLICY_OWNER_KERNELSU);
	}
	WRITE_ONCE(kasumi_root_mask, root_mask);
	WRITE_ONCE(kasumi_ksu_policy_available, true);
	if (!ambiguous)
		WRITE_ONCE(kasumi_root_spoof_allowed, true);
}

static void kasumi_policy_mark_ksu_unavailable(void)
{
	WRITE_ONCE(kasumi_ksu_policy_available, false);
	if (READ_ONCE(kasumi_root_policy_owner) == KSM_POLICY_OWNER_KERNELSU) {
		WRITE_ONCE(kasumi_root_policy_owner, KSM_POLICY_OWNER_DISABLED);
		WRITE_ONCE(kasumi_root_spoof_allowed, false);
	}
}

/*
 * GKI kernels protect many VFS symbols behind namespaces or don't export
 * them at all. We resolve ALL problematic VFS symbols via kprobe at init
 * time, so the module has zero direct VFS symbol dependencies.
 */
/*
 * Reload the KernelSU provider. Only ksu_uid_should_umount is authoritative:
 * bulk and on-disk profiles omit live default-profile semantics, so using
 * either as a substitute could select the wrong apps.
 */
static bool kasumi_policy_prepare_ksu_locked(void)
{
	unsigned long addr;

	lockdep_assert_held(&kasumi_config_mutex);
	if (!kasumi_ksu_uid_should_umount_ptr) {
		addr = kasumi_lookup_callable_quiet("ksu_uid_should_umount");
		if (addr && kasumi_valid_kernel_addr(addr) &&
		    kasumi_policy_pin_stable_provider(addr,
					       &kasumi_ksu_provider_module))
			WRITE_ONCE(kasumi_ksu_uid_should_umount_ptr,
				   (kasumi_ksu_uid_should_umount_fn)addr);
	}
	if (kasumi_ksu_uid_should_umount_ptr) {
		if (!kasumi_policy_pin_stable_provider(
			(unsigned long)kasumi_ksu_uid_should_umount_ptr,
			&kasumi_ksu_provider_module)) {
			WRITE_ONCE(kasumi_ksu_uid_should_umount_ptr, NULL);
			kasumi_policy_mark_ksu_unavailable();
			return false;
		}
		kasumi_policy_mark_ksu_available();
		return true;
	}

	/*
	 * Bulk/file fallbacks cannot reproduce ksu_uid_should_umount(): they omit
	 * the live default non-root profile or have version-specific layouts. An
	 * approximate cache risks selecting the wrong apps, so fail closed.
	 */
	kasumi_policy_mark_ksu_unavailable();
	return false;
}

static bool kasumi_policy_prepare_apatch_addr_locked(unsigned long addr,
						      bool lifetime_stable)
{
	bool is_module = false;

	lockdep_assert_held(&kasumi_config_mutex);
	if (!addr)
		return false;
	if (kasumi_policy_pin_linux_module(addr,
					   &kasumi_apatch_provider_module,
					   &is_module))
		return true;
	if (is_module)
		goto unavailable;
	if (lifetime_stable)
		return true;
	if (kasumi_policy_pin_stable_provider(addr, &kasumi_apatch_provider_module))
		return true;
unavailable:
	WRITE_ONCE(kasumi_ap_get_mod_exclude, NULL);
	WRITE_ONCE(kasumi_root_spoof_allowed, false);
	WRITE_ONCE(kasumi_root_policy_owner, KSM_POLICY_OWNER_DISABLED);
	return false;
}

bool kasumi_policy_prepare_enable_locked(void)
{
	unsigned long apatch_addr = 0;
	unsigned long ksu_addr;
	bool apatch_stable = false;
	bool apatch_available;
	bool ksu_available;
	u32 configured_owner;
	u32 provider_owner;
	u32 root_mask;
	bool ready = true;

	lockdep_assert_held(&kasumi_config_mutex);
	configured_owner = kasumi_policy_configured_owner();
	provider_owner = configured_owner;
	root_mask = READ_ONCE(kasumi_root_mask) &
		(KASUMI_ROOT_KSU_RDR | KASUMI_ROOT_MAGISK);
	/* AUTO is the default and must notice providers loaded after Kasumi. */
	if (provider_owner == KSM_POLICY_OWNER_AUTO) {
		ksu_addr = kasumi_lookup_callable_quiet("ksu_uid_should_umount");
		ksu_available = ksu_addr && kasumi_valid_kernel_addr(ksu_addr);
		apatch_available = kasumi_probe_apatch_policy(&apatch_addr,
							 &apatch_stable);
		if (ksu_available)
			root_mask |= KASUMI_ROOT_KSU;
		if (apatch_available)
			root_mask |= KASUMI_ROOT_APATCH;
		if (root_mask & (KASUMI_ROOT_KSU | KASUMI_ROOT_APATCH |
				 KASUMI_ROOT_MAGISK))
			root_mask &= ~KASUMI_ROOT_NON_ROOT;
		else
			root_mask |= KASUMI_ROOT_NON_ROOT;
		if ((root_mask & KASUMI_ROOT_KSU) &&
		    (root_mask & (KASUMI_ROOT_APATCH | KASUMI_ROOT_MAGISK)))
			root_mask |= KASUMI_ROOT_MULTI;
		WRITE_ONCE(kasumi_root_mask, root_mask);
	}
	if (provider_owner == KSM_POLICY_OWNER_AUTO) {
		if (root_mask & KASUMI_ROOT_MULTI) {
			provider_owner = KSM_POLICY_OWNER_DISABLED;
			WRITE_ONCE(kasumi_root_policy_owner,
				   KSM_POLICY_OWNER_DISABLED);
			WRITE_ONCE(kasumi_root_spoof_allowed, false);
			ready = false;
		} else if ((root_mask & KASUMI_ROOT_KSU) &&
			 !(root_mask & (KASUMI_ROOT_APATCH | KASUMI_ROOT_MAGISK)))
			provider_owner = KSM_POLICY_OWNER_KERNELSU;
		else if ((root_mask & KASUMI_ROOT_APATCH) &&
			 !(root_mask & (KASUMI_ROOT_KSU | KASUMI_ROOT_MAGISK)))
			provider_owner = KSM_POLICY_OWNER_APATCH;
		else {
			provider_owner = KSM_POLICY_OWNER_DISABLED;
			ready = false;
		}
	}
	if (provider_owner == KSM_POLICY_OWNER_KERNELSU)
		ready = kasumi_policy_prepare_ksu_locked();
	else if (provider_owner == KSM_POLICY_OWNER_APATCH) {
		if (!apatch_addr)
			apatch_available = kasumi_probe_apatch_policy(
				&apatch_addr, &apatch_stable);
		ready = apatch_available &&
			kasumi_policy_prepare_apatch_addr_locked(apatch_addr,
								 apatch_stable);
		if (ready)
			WRITE_ONCE(kasumi_ap_get_mod_exclude,
				   (int (*)(uid_t))apatch_addr);
		if (ready) {
			root_mask = READ_ONCE(kasumi_root_mask) |
				KASUMI_ROOT_APATCH;
			root_mask &= ~KASUMI_ROOT_NON_ROOT;
			WRITE_ONCE(kasumi_root_mask, root_mask);
		}
	}
	if (configured_owner == KSM_POLICY_OWNER_AUTO) {
		if (ready && provider_owner != KSM_POLICY_OWNER_DISABLED) {
			WRITE_ONCE(kasumi_root_policy_owner, provider_owner);
			WRITE_ONCE(kasumi_root_spoof_allowed, true);
		} else {
			WRITE_ONCE(kasumi_root_policy_owner,
				   KSM_POLICY_OWNER_DISABLED);
			WRITE_ONCE(kasumi_root_spoof_allowed, false);
		}
	}
	return ready;
}

void kasumi_policy_disable_provider_locked(void)
{
	lockdep_assert_held(&kasumi_config_mutex);
	WRITE_ONCE(kasumi_ksu_uid_should_umount_ptr, NULL);
	WRITE_ONCE(kasumi_ap_get_mod_exclude, NULL);
	kasumi_apatch_policy_lifetime_stable = false;
	kasumi_policy_mark_ksu_unavailable();
	/* Readers hold rcu_read_lock() while calling the provider. */
	synchronize_rcu();
	kasumi_policy_unpin_provider();
}

/* ======================================================================
 * Part 12: Forward Redirect (resolve_target)
 * ====================================================================== */

char *kasumi_resolve_target(const char *pathname)
{
	struct kasumi_entry *entry;
	u32 hash;
	char *target = NULL;
	size_t path_len;
	pid_t pid;

	if (unlikely(!kasumi_enabled || !pathname ||
		     !kasumi_policy_current_is_view_target()))
		return NULL;

	pid = task_tgid_vnr(current);
	if (READ_ONCE(kasumi_daemon_pid) > 0 && pid == READ_ONCE(kasumi_daemon_pid))
		return NULL;
	path_len = strlen(pathname);
	hash = full_name_hash(NULL, pathname, path_len);

	/* Fast path: atomic + bloom before rcu_read_lock */
	if (atomic_read(&kasumi_rule_count) == 0)
		return NULL;
	{
		unsigned long bh1 = jhash(pathname, (u32)path_len, 0) & (KASUMI_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)path_len, 1) & (KASUMI_BLOOM_SIZE - 1);
		if (!test_bit(bh1, kasumi_path_bloom) || !test_bit(bh2, kasumi_path_bloom))
			return NULL;
	}

	rcu_read_lock();
	hlist_for_each_entry_rcu(entry,
		&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
		if (entry->src_hash == hash &&
		    strcmp(entry->src, pathname) == 0) {
			target = kstrdup(entry->target, GFP_ATOMIC);
			rcu_read_unlock();
			return target;
		}
	}
	/*
	 * Merge trie is NOT consulted here for path redirect. Merge rules
	 * only affect directory listing (inject via iterate_dir). Individual
	 * file redirects are materialized into kasumi_paths at ADD_MERGE_RULE
	 * time, so the bloom+hash exact match above handles them.
	 *
	 * The KPM version validated merge targets with kern_path() before
	 * redirecting. In LKM kprobe context we cannot sleep, so blind
	 * merge-trie redirect would send EVERY path under the merge prefix
	 * to the module dir — including original system files that don't
	 * exist there — breaking PMS and causing bootloop.
	 */

	rcu_read_unlock();
	return target;
}

KASUMI_NOCFI char *kasumi_resolve_target_slow(const char *pathname)
{
	struct kasumi_merge_entry *me;
	char *src = NULL;
	char *target_dir = NULL;
	char *target = NULL;
	size_t path_len;
	int bkt;
	pid_t pid;

	target = kasumi_resolve_target(pathname);
	if (target)
		return target;

	if (unlikely(!kasumi_enabled || !pathname || !*pathname ||
		     !kasumi_policy_current_is_view_target()))
		return NULL;
	pid = task_tgid_vnr(current);
	if (READ_ONCE(kasumi_daemon_pid) > 0 && pid == READ_ONCE(kasumi_daemon_pid))
		return NULL;
	if (!kasumi_kern_path)
		return NULL;

	path_len = strlen(pathname);
	rcu_read_lock();
	hash_for_each_rcu(kasumi_merge_dirs, bkt, me, node) {
		size_t src_len;

		if (!me->src || !me->target)
			continue;
		src_len = strlen(me->src);
		if (path_len <= src_len || pathname[src_len] != '/')
			continue;
		if (strncmp(pathname, me->src, src_len) != 0)
			continue;
		src = kstrdup(me->src, GFP_ATOMIC);
		target_dir = kstrdup(me->target, GFP_ATOMIC);
		break;
	}
	rcu_read_unlock();

	if (src && target_dir) {
		struct path p;
		const char *suffix = pathname + strlen(src);

		target = kasprintf(GFP_KERNEL, "%s%s", target_dir, suffix);
		if (target && kasumi_kern_path(target, LOOKUP_FOLLOW, &p) == 0) {
			if (p.dentry && d_inode(p.dentry) &&
			    S_ISDIR(d_inode(p.dentry)->i_mode)) {
				kasumi_path_put(&p);
				kfree(target);
				target = NULL;
			} else {
				kasumi_path_put(&p);
			}
		} else {
			kfree(target);
			target = NULL;
		}
	}
	kfree(src);
	kfree(target_dir);
	return target;
}

struct kasumi_entry *kasumi_reverse_lookup_target(const char *path_str)
{
	struct kasumi_entry *entry;
	u32 hash;

	if (!path_str || !*path_str)
		return NULL;

	hash = full_name_hash(NULL, path_str, strlen(path_str));
	hlist_for_each_entry_rcu(entry,
		&kasumi_targets[hash_min(hash, KASUMI_HASH_BITS)], target_node) {
		if (strcmp(entry->target, path_str) == 0)
			return entry;
	}
	return NULL;
}

/* ======================================================================
 * Part 14: Hide Logic
 * ====================================================================== */

static bool kasumi_hide_rule_matches(const char *pathname)
{
	struct kasumi_hide_entry *he;
	u32 hash;
	size_t len;

	if (!pathname || !*pathname)
		return false;
	if (atomic_read(&kasumi_hide_count) == 0)
		return false;

	len = strlen(pathname);
	{
		unsigned long bh1 = jhash(pathname, (u32)len, 0) & (KASUMI_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)len, 1) & (KASUMI_BLOOM_SIZE - 1);

		if (!test_bit(bh1, kasumi_hide_bloom) || !test_bit(bh2, kasumi_hide_bloom))
			return false;
	}

	hash = full_name_hash(NULL, pathname, len);
	rcu_read_lock();
	hlist_for_each_entry_rcu(he,
		&kasumi_hide_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
		if (he->path_hash == hash && strcmp(he->path, pathname) == 0) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

bool kasumi_should_hide(const char *pathname)
{
	pid_t pid;

	if (unlikely(!kasumi_enabled || !pathname || !*pathname))
		return false;
	pid = task_tgid_vnr(current);
	if (READ_ONCE(kasumi_daemon_pid) > 0 && pid == READ_ONCE(kasumi_daemon_pid))
		return false;
	if (unlikely(kasumi_is_privileged_process()))
		return false;
	if (!kasumi_policy_current_is_view_target())
		return false;
	return kasumi_hide_rule_matches(pathname);
}

static bool __maybe_unused kasumi_should_replace(const char *pathname)
{
	struct kasumi_entry *entry;
	u32 hash;
	size_t path_len;
	pid_t pid;

	if (unlikely(!kasumi_enabled || !pathname))
		return false;

	pid = task_tgid_vnr(current);
	if (READ_ONCE(kasumi_daemon_pid) > 0 && pid == READ_ONCE(kasumi_daemon_pid))
		return false;
	if (atomic_read(&kasumi_rule_count) == 0)
		return false;

	path_len = strlen(pathname);
	{
		unsigned long bh1 = jhash(pathname, (u32)path_len, 0) & (KASUMI_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)path_len, 1) & (KASUMI_BLOOM_SIZE - 1);

		if (!test_bit(bh1, kasumi_path_bloom) || !test_bit(bh2, kasumi_path_bloom))
			return false;
	}

	hash = full_name_hash(NULL, pathname, path_len);
	rcu_read_lock();
	hlist_for_each_entry_rcu(entry,
		&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
		if (entry->src_hash == hash && strcmp(entry->src, pathname) == 0) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}
