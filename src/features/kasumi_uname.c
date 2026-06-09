/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - global and scoped uname spoofing support.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/nsproxy.h>
#include <linux/utsname.h>
#include <linux/fs_struct.h>
#include <linux/init_task.h>
#include <linux/rwsem.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/user_namespace.h>
#include <linux/version.h>

#include "kasumi_entrypoints.h"
#include "kasumi_uname.h"

/* ------------------------------------------------------------------
 * Resolved kernel symbols (none of these are EXPORT_SYMBOL)
 * ------------------------------------------------------------------ */
static struct rw_semaphore *kasumi_uts_sem;
static struct uts_namespace *kasumi_init_uts_ns_ptr;
static struct nsproxy *(*kasumi_create_new_namespaces_fn)(unsigned long,
							struct task_struct *,
							struct user_namespace *,
							struct fs_struct *);
static int (*kasumi_unshare_nsproxy_namespaces_fn)(unsigned long,
						 struct nsproxy **,
						 struct cred *,
						 struct fs_struct *);
static void (*kasumi_switch_task_namespaces_fn)(struct task_struct *,
					      struct nsproxy *);
static const struct cred *(*kasumi_override_creds_fn)(const struct cred *);
static void (*kasumi_revert_creds_fn)(const struct cred *);
static struct task_struct *kasumi_init_task_ptr;
static struct cred *kasumi_scoped_kcred;

/* ------------------------------------------------------------------
 * Config state
 * ------------------------------------------------------------------ */
static DEFINE_MUTEX(kasumi_uname_cfg_mutex);

struct kasumi_uname_cfg_rcu {
	struct kasumi_spoof_uname data;
	struct rcu_head rcu;
};

/* Scoped-mode spoof config (RCU-protected). */
static struct kasumi_uname_cfg_rcu __rcu *kasumi_uname_scoped_cfg;
static bool kasumi_uname_scoped_on;

/* Global-mode state */
static bool kasumi_uname_global_on;
static struct new_utsname kasumi_uname_global_saved; /* originals captured on first apply */
static bool kasumi_uname_global_saved_valid;

/* ------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------ */

static inline bool field_set(const char *s)
{
	return s && s[0] != '\0';
}

/* Overwrite dst fields in-place with any non-empty src fields. Caller holds uts_sem. */
static void kasumi_merge_uts(struct new_utsname *dst, const struct kasumi_spoof_uname *src)
{
	if (field_set(src->sysname))
		strscpy(dst->sysname, src->sysname, sizeof(dst->sysname));
	if (field_set(src->nodename))
		strscpy(dst->nodename, src->nodename, sizeof(dst->nodename));
	if (field_set(src->release))
		strscpy(dst->release, src->release, sizeof(dst->release));
	if (field_set(src->version))
		strscpy(dst->version, src->version, sizeof(dst->version));
	if (field_set(src->machine))
		strscpy(dst->machine, src->machine, sizeof(dst->machine));
	if (field_set(src->domainname))
		strscpy(dst->domainname, src->domainname, sizeof(dst->domainname));
}

static bool spoof_has_any(const struct kasumi_spoof_uname *u)
{
	return field_set(u->sysname) || field_set(u->nodename) ||
	       field_set(u->release) || field_set(u->version) ||
	       field_set(u->machine) || field_set(u->domainname);
}

static const char *kasumi_errno_name(int err)
{
	switch (err) {
	case 0:
		return "OK";
	case -EPERM:
		return "EPERM";
	case -EINVAL:
		return "EINVAL";
	case -ENOMEM:
		return "ENOMEM";
	case -ENOSPC:
		return "ENOSPC";
	case -EUSERS:
		return "EUSERS";
	default:
		return "UNKNOWN";
	}
}

/*
 * kCFI rejects indirect calls through dynamically resolved pointers unless the
 * callsite is explicitly exempted. Keep the exemption narrowly scoped to this
 * wrapper so the rest of the uname path still benefits from normal checking.
 */
static KASUMI_NOCFI struct nsproxy *kasumi_create_new_uts_ns_nocfi(struct task_struct *task)
{
	if (!kasumi_create_new_namespaces_fn || !task || !task->fs)
		return ERR_PTR(-ENOSYS);
	return kasumi_create_new_namespaces_fn(CLONE_NEWUTS, task,
					     current_user_ns(), task->fs);
}

/* ------------------------------------------------------------------
 * Init / exit
 * ------------------------------------------------------------------ */

int kasumi_uname_init(void)
{
	kasumi_uts_sem = (struct rw_semaphore *)kasumi_lookup_name("uts_sem");
	kasumi_init_uts_ns_ptr = (struct uts_namespace *)kasumi_lookup_name("init_uts_ns");
	kasumi_create_new_namespaces_fn = (void *)kasumi_lookup_name("create_new_namespaces");
	kasumi_unshare_nsproxy_namespaces_fn = (void *)kasumi_lookup_name("unshare_nsproxy_namespaces");
	kasumi_switch_task_namespaces_fn = (void *)kasumi_lookup_name("switch_task_namespaces");
	kasumi_override_creds_fn = (void *)kasumi_lookup_name("override_creds");
	kasumi_revert_creds_fn = (void *)kasumi_lookup_name("revert_creds");
	kasumi_init_task_ptr = (struct task_struct *)kasumi_lookup_name("init_task");

	if (!kasumi_uts_sem || !kasumi_init_uts_ns_ptr) {
		pr_warn("Kasumi: uname: uts_sem/init_uts_ns not resolvable — uname spoof disabled\n");
		return -ENOENT;
	}
	if (kasumi_unshare_nsproxy_namespaces_fn && kasumi_switch_task_namespaces_fn &&
	    kasumi_override_creds_fn && kasumi_revert_creds_fn && kasumi_init_task_ptr)
		kasumi_scoped_kcred = prepare_kernel_cred(kasumi_init_task_ptr);
	if ((!kasumi_create_new_namespaces_fn &&
	     (!kasumi_unshare_nsproxy_namespaces_fn || !kasumi_override_creds_fn ||
	      !kasumi_revert_creds_fn || !kasumi_init_task_ptr || !kasumi_scoped_kcred)) ||
	    !kasumi_switch_task_namespaces_fn) {
		pr_info("Kasumi: uname: scoped mode unavailable (ns/cred helpers missing), global mode only\n");
	}
	return 0;
}

void kasumi_uname_exit(void)
{
	struct kasumi_uname_cfg_rcu *old;

	if (kasumi_uname_global_on)
		kasumi_uname_restore_global();

	mutex_lock(&kasumi_uname_cfg_mutex);
	old = rcu_dereference_protected(kasumi_uname_scoped_cfg,
					lockdep_is_held(&kasumi_uname_cfg_mutex));
	rcu_assign_pointer(kasumi_uname_scoped_cfg, NULL);
	WRITE_ONCE(kasumi_uname_scoped_on, false);
	mutex_unlock(&kasumi_uname_cfg_mutex);

	if (old) {
		rcu_barrier();
		kfree(old);
	}

	if (kasumi_scoped_kcred) {
		put_cred(kasumi_scoped_kcred);
		kasumi_scoped_kcred = NULL;
	}
}

/* ------------------------------------------------------------------
 * Global mode
 * ------------------------------------------------------------------ */

int kasumi_uname_apply_global(const struct kasumi_spoof_uname *u)
{
	if (!kasumi_uts_sem || !kasumi_init_uts_ns_ptr)
		return -ENOSYS;
	if (!u || !spoof_has_any(u))
		return -EINVAL;

	mutex_lock(&kasumi_uname_cfg_mutex);
	down_write(kasumi_uts_sem);
	if (!kasumi_uname_global_saved_valid) {
		memcpy(&kasumi_uname_global_saved, &kasumi_init_uts_ns_ptr->name,
		       sizeof(kasumi_uname_global_saved));
		kasumi_uname_global_saved_valid = true;
	}
	kasumi_merge_uts(&kasumi_init_uts_ns_ptr->name, u);
	up_write(kasumi_uts_sem);
	kasumi_uname_global_on = true;
	mutex_unlock(&kasumi_uname_cfg_mutex);

	kasumi_log("uname global applied: release='%s' version='%s'\n",
		kasumi_init_uts_ns_ptr->name.release,
		kasumi_init_uts_ns_ptr->name.version);
	return 0;
}

int kasumi_uname_restore_global(void)
{
	if (!kasumi_uts_sem || !kasumi_init_uts_ns_ptr)
		return -ENOSYS;

	mutex_lock(&kasumi_uname_cfg_mutex);
	if (!kasumi_uname_global_saved_valid) {
		mutex_unlock(&kasumi_uname_cfg_mutex);
		return 0;
	}
	down_write(kasumi_uts_sem);
	memcpy(&kasumi_init_uts_ns_ptr->name, &kasumi_uname_global_saved,
	       sizeof(kasumi_init_uts_ns_ptr->name));
	up_write(kasumi_uts_sem);
	kasumi_uname_global_saved_valid = false;
	kasumi_uname_global_on = false;
	mutex_unlock(&kasumi_uname_cfg_mutex);

	kasumi_log("uname global restored\n");
	return 0;
}

bool kasumi_uname_global_active(void)
{
	return READ_ONCE(kasumi_uname_global_on);
}

bool kasumi_uname_capable(void)
{
	return kasumi_uts_sem && kasumi_init_uts_ns_ptr;
}

/* ------------------------------------------------------------------
 * Scoped mode
 * ------------------------------------------------------------------ */

int kasumi_uname_set_scoped_config(const struct kasumi_spoof_uname *u)
{
	struct kasumi_uname_cfg_rcu *new_cfg = NULL;
	struct kasumi_uname_cfg_rcu *old_cfg;
	bool active = u && spoof_has_any(u);

	if (active && !kasumi_switch_task_namespaces_fn)
		return -ENOSYS;
	if (active && !kasumi_create_new_namespaces_fn &&
	    (!kasumi_unshare_nsproxy_namespaces_fn ||
	     !kasumi_override_creds_fn ||
	     !kasumi_revert_creds_fn ||
	     !kasumi_init_task_ptr ||
	     !kasumi_scoped_kcred))
		return -ENOSYS;

	if (active) {
		new_cfg = kzalloc(sizeof(*new_cfg), GFP_KERNEL);
		if (!new_cfg)
			return -ENOMEM;
		memcpy(&new_cfg->data, u, sizeof(new_cfg->data));
	}

	mutex_lock(&kasumi_uname_cfg_mutex);
	old_cfg = rcu_dereference_protected(kasumi_uname_scoped_cfg,
					    lockdep_is_held(&kasumi_uname_cfg_mutex));
	rcu_assign_pointer(kasumi_uname_scoped_cfg, new_cfg);
	WRITE_ONCE(kasumi_uname_scoped_on, active);
	mutex_unlock(&kasumi_uname_cfg_mutex);

	if (old_cfg)
		kfree_rcu(old_cfg, rcu);

	kasumi_log("uname scoped config %s\n", active ? "set" : "cleared");
	return 0;
}

bool kasumi_uname_scoped_active(void)
{
	return READ_ONCE(kasumi_uname_scoped_on);
}

KASUMI_NOCFI void kasumi_uname_apply_scoped_current(void)
{
	struct task_struct *task = current;
	struct nsproxy *new_nsp = NULL;
	struct uts_namespace *cur_uts;
	struct kasumi_uname_cfg_rcu *cfg;
	struct kasumi_spoof_uname spoof;
	const struct cred *old_cred;
	int ret;

	if (!READ_ONCE(kasumi_uname_scoped_on))
		return;
	if (!kasumi_switch_task_namespaces_fn)
		return;
	if (!kasumi_create_new_namespaces_fn &&
	    (!kasumi_unshare_nsproxy_namespaces_fn || !kasumi_override_creds_fn ||
	     !kasumi_revert_creds_fn || !kasumi_init_task_ptr || !kasumi_scoped_kcred))
		return;
	if (!task || (task->flags & PF_KTHREAD))
		return;

	/* task_lock protects nsproxy read; cheap enough for one-shot path. */
	task_lock(task);
	cur_uts = task->nsproxy ? task->nsproxy->uts_ns : NULL;
	task_unlock(task);

	/*
	 * Fast exit: already owns a private uts_ns (either we did it earlier
	 * or the task unshared on its own). We never touch a namespace we
	 * don't own, and we never re-apply.
	 */
	if (!cur_uts || cur_uts != kasumi_init_uts_ns_ptr)
		return;

	if (!task->fs)
		return;

	rcu_read_lock();
	cfg = rcu_dereference(kasumi_uname_scoped_cfg);
	if (!cfg) {
		rcu_read_unlock();
		return;
	}
	memcpy(&spoof, &cfg->data, sizeof(spoof));
	rcu_read_unlock();

	/*
	 * This helper enforces CAP_SYS_ADMIN in the caller's current user_ns.
	 * Normal apps fail that check, so scoped uname would silently never
	 * activate. Temporarily adopt a kernel service cred while creating the
	 * private UTS ns, then immediately revert.
	 */
	if (kasumi_create_new_namespaces_fn) {
		new_nsp = kasumi_create_new_uts_ns_nocfi(task);
		if (IS_ERR(new_nsp)) {
			ret = PTR_ERR(new_nsp);
			kasumi_log("uname scoped: nocfi create_new_namespaces(CLONE_NEWUTS) failed: %d (%s)\n",
				 ret, kasumi_errno_name(ret));
			return;
		}
	} else {
		old_cred = kasumi_override_creds_fn(kasumi_scoped_kcred);
		ret = kasumi_unshare_nsproxy_namespaces_fn(CLONE_NEWUTS, &new_nsp,
							 kasumi_scoped_kcred,
							 task->fs);
		kasumi_revert_creds_fn(old_cred);
		if (ret || !new_nsp) {
			kasumi_log("uname scoped: CLONE_NEWUTS unshare failed: %d (%s)\n",
				 ret, kasumi_errno_name(ret));
			return;
		}
	}

	down_write(kasumi_uts_sem);
	kasumi_merge_uts(&new_nsp->uts_ns->name, &spoof);
	up_write(kasumi_uts_sem);

	kasumi_switch_task_namespaces_fn(task, new_nsp);
}
