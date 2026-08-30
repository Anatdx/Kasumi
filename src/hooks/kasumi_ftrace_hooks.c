/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - ftrace-backed VFS entry hooks and kretprobe bridge support.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifdef CONFIG_DYNAMIC_FTRACE

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/version.h>
/* 6.6+ may call arch_ftrace_get_regs without defining it in ftrace.h. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && !defined(arch_ftrace_get_regs)
#define arch_ftrace_get_regs(fregs) (NULL)
#endif
#include <linux/kprobes.h>
#include <linux/smp.h>
#include <linux/vmalloc.h>
#include <linux/ftrace.h>

#include "kasumi_entrypoints.h"
#include "kasumi_ftrace_hooks.h"

#define KASUMI_FTRACE_SLOT_DEPTH 16

struct kasumi_ftrace_slot {
	int type; /* 0=getattr 1=dpath 2=iter 3=getxattr, -2=skipped */
	union {
		struct kasumi_getattr_ri_data getattr;
		struct kasumi_d_path_ri_data dpath;
		struct kasumi_iterate_ri_data iter;
		struct kasumi_getxattr_ri_data getxattr;
	} u;
};

/* vmalloc-based per-CPU ftrace state (avoids percpu allocator exhaustion on 6.6 Qualcomm) */
struct kasumi_ftrace_percpu {
	struct kasumi_ftrace_slot slots[KASUMI_FTRACE_SLOT_DEPTH];
	int depth;
	int cb_ran;
};
static struct kasumi_ftrace_percpu *kasumi_ftrace_base;

static inline struct kasumi_ftrace_percpu *kasumi_ftrace_this_cpu(void)
{
	return kasumi_ftrace_base ? kasumi_ftrace_base + smp_processor_id() : NULL;
}
static unsigned long kasumi_ft_addr[4];
static struct ftrace_ops kasumi_ftrace_ops;

/* Resolved at runtime: 1) __symbol_get (if exported), 2) kasumi_lookup_name (kallsyms).
 * __symbol_get/__symbol_put are resolved via kallsyms to avoid link-time dependency
 * on kernels that don't export them (e.g. some OEM builds). */
typedef int (*ftrace_register_fn)(struct ftrace_ops *ops);
typedef void (*ftrace_unregister_fn)(struct ftrace_ops *ops);
typedef int (*ftrace_filter_fn)(struct ftrace_ops *ops, unsigned long *ips,
				unsigned int cnt, int remove, int reset);
typedef void *(*symbol_get_fn)(const char *name);
typedef void (*symbol_put_fn)(const char *name);
static ftrace_register_fn kasumi_ftrace_register_fn;
static ftrace_unregister_fn kasumi_ftrace_unregister_fn;
static ftrace_filter_fn kasumi_ftrace_filter_fn;
static symbol_get_fn kasumi_symbol_get;
static symbol_put_fn kasumi_symbol_put;
static bool kasumi_ftrace_used_symbol_get; /* true = need symbol_put on unregister */

/*
 * Build a stack-local kretprobe_instance view for reusing existing handlers
 * from the ftrace path without writing past object bounds.
 */
#define KASUMI_FAKE_RI_DATA_OFF offsetof(struct kretprobe_instance, data)
#define KASUMI_FAKE_RI_SIZE \
	((sizeof(struct kretprobe_instance) > \
	  (KASUMI_FAKE_RI_DATA_OFF + sizeof(void *))) ? \
	 sizeof(struct kretprobe_instance) : \
	 (KASUMI_FAKE_RI_DATA_OFF + sizeof(void *)))

static inline struct kretprobe_instance *kasumi_fake_ri_init(unsigned char *buf, void *ptr)
{
	struct kretprobe_instance *ri = (struct kretprobe_instance *)buf;

	memset(buf, 0, KASUMI_FAKE_RI_SIZE);
	memcpy((char *)ri + KASUMI_FAKE_RI_DATA_OFF, &ptr, sizeof(ptr));
	return ri;
}

static void kasumi_ftrace_callback(unsigned long ip, unsigned long parent_ip,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
				struct ftrace_ops *op, struct pt_regs *regs)
#else
				struct ftrace_ops *op, struct ftrace_regs *fregs)
#endif
{
	struct pt_regs *regs_local;
	struct kasumi_ftrace_percpu *pcpu;
	struct kasumi_ftrace_slot *slot;
	int depth, type = -1;
	static struct kprobe kp_dummy;

	(void)parent_ip;
	(void)op;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	/* Defensive: verify fregs is valid */
	if (!fregs)
		return;

	regs_local = ftrace_get_regs(fregs);
	if (!regs_local)
		return;
#else
	regs_local = regs;
	if (!regs_local)
		return;
#endif

	/* Check if any ftrace addresses are registered */
	if (!kasumi_ft_addr[0] && !kasumi_ft_addr[1] && !kasumi_ft_addr[2] && !kasumi_ft_addr[3])
		return;

	pcpu = kasumi_ftrace_this_cpu();
	if (!pcpu)
		return;

	pcpu->cb_ran = 0;
	depth = pcpu->depth;
	if (depth >= KASUMI_FTRACE_SLOT_DEPTH || depth < 0)
		return;

	if (ip == kasumi_ft_addr[0])
		type = 0;
	else if (ip == kasumi_ft_addr[1])
		type = 1;
	else if (ip == kasumi_ft_addr[2])
		type = 2;
	else if (ip == kasumi_ft_addr[3])
		type = 3;
	else
		return;

	slot = &pcpu->slots[depth];
	pcpu->depth = depth + 1;
	pcpu->cb_ran = 1;
	slot->type = type;

	if (type == 0) {
		unsigned char ri_buf[KASUMI_FAKE_RI_SIZE];
		struct kretprobe_instance *ri = kasumi_fake_ri_init(ri_buf, &slot->u.getattr);

		if (kasumi_krp_vfs_getattr_entry(ri, regs_local) != 0)
			slot->type = -1;
	} else if (type == 1) {
		unsigned char ri_buf[KASUMI_FAKE_RI_SIZE];
		struct kretprobe_instance *ri = kasumi_fake_ri_init(ri_buf, &slot->u.dpath);

		if (kasumi_krp_d_path_entry(ri, regs_local) != 0)
			slot->type = -1;
	} else if (type == 2) {
		struct dir_context *ictx;
		kasumi_kp_iterate_dir_pre(&kp_dummy, regs_local);
		ictx = (struct dir_context *)regs_local->regs[1];
		if (ictx && ictx->actor == kasumi_filldir_filter) {
			slot->u.iter.did_swap = 1;
			slot->u.iter.wrapper = container_of(ictx,
				struct kasumi_filldir_wrapper, wrap_ctx);
		} else {
			slot->u.iter.did_swap = 0;
			slot->u.iter.wrapper = NULL;
		}
	} else if (type == 3) {
		unsigned char ri_buf[KASUMI_FAKE_RI_SIZE];
		struct kretprobe_instance *ri = kasumi_fake_ri_init(ri_buf, &slot->u.getxattr);

		if (kasumi_krp_vfs_getxattr_entry(ri, regs_local) != 0)
			slot->type = -1;
	}
}

int kasumi_ftrace_krp_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kasumi_ftrace_percpu *pcpu;
	int depth;

	(void)regs;
	*(struct kasumi_ftrace_slot **)ri->data = NULL;
	pcpu = kasumi_ftrace_this_cpu();
	if (!pcpu || !pcpu->cb_ran)
		return 0;
	depth = pcpu->depth;
	if (depth > 0 && depth <= KASUMI_FTRACE_SLOT_DEPTH)
		*(struct kasumi_ftrace_slot **)ri->data = &pcpu->slots[depth - 1];
	return 0;
}

int kasumi_ftrace_krp_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kasumi_ftrace_percpu *pcpu;
	struct kasumi_ftrace_slot *slot;

	slot = *(struct kasumi_ftrace_slot **)ri->data;
	if (!slot)
		return 0;
	if (slot->type >= 0) {
		if (slot->type == 0) {
			unsigned char ri_buf[KASUMI_FAKE_RI_SIZE];
			struct kretprobe_instance *r = kasumi_fake_ri_init(ri_buf, &slot->u.getattr);

			kasumi_krp_vfs_getattr_ret(r, regs);
		} else if (slot->type == 1) {
			unsigned char ri_buf[KASUMI_FAKE_RI_SIZE];
			struct kretprobe_instance *r = kasumi_fake_ri_init(ri_buf, &slot->u.dpath);

			kasumi_krp_d_path_ret(r, regs);
		} else if (slot->type == 2) {
			unsigned char ri_buf[KASUMI_FAKE_RI_SIZE];
			struct kretprobe_instance *r = kasumi_fake_ri_init(ri_buf, &slot->u.iter);

			kasumi_krp_iterate_dir_ret(r, regs);
		} else if (slot->type == 3) {
			unsigned char ri_buf[KASUMI_FAKE_RI_SIZE];
			struct kretprobe_instance *r = kasumi_fake_ri_init(ri_buf, &slot->u.getxattr);

			kasumi_krp_vfs_getxattr_ret(r, regs);
		}
	}
	pcpu = kasumi_ftrace_this_cpu();
	if (pcpu && pcpu->depth > 0)
		pcpu->depth--;
	return 0;
}

int kasumi_ftrace_try_register(unsigned long addr[4])
{
	int i, ret;
	static const char *ft_syms[] = {"vfs_getattr", "d_path", "iterate_dir", "vfs_getxattr"};

	/* 1) Resolve __symbol_get/__symbol_put via kallsyms (avoids link dep on unexported kernels) */
	kasumi_ftrace_used_symbol_get = false;
	kasumi_symbol_get = NULL;
	kasumi_symbol_put = NULL;
	kasumi_ftrace_register_fn = NULL;
	kasumi_ftrace_unregister_fn = NULL;
	kasumi_ftrace_filter_fn = NULL;
	{
		unsigned long sg = kasumi_lookup_name("__symbol_get");
		unsigned long sp = kasumi_lookup_name("__symbol_put");
		if (sg && sp && !IS_ERR_VALUE(sg) && !IS_ERR_VALUE(sp)) {
			kasumi_symbol_get = (symbol_get_fn)sg;
			kasumi_symbol_put = (symbol_put_fn)sp;
			kasumi_ftrace_register_fn = (ftrace_register_fn)kasumi_symbol_get("register_ftrace_function");
			kasumi_ftrace_unregister_fn = (ftrace_unregister_fn)kasumi_symbol_get("unregister_ftrace_function");
			kasumi_ftrace_filter_fn = (ftrace_filter_fn)kasumi_symbol_get("ftrace_set_filter_ips");
			if (kasumi_ftrace_register_fn && kasumi_ftrace_unregister_fn && kasumi_ftrace_filter_fn)
				kasumi_ftrace_used_symbol_get = true;
		}
	}
	if (!kasumi_ftrace_register_fn || !kasumi_ftrace_unregister_fn || !kasumi_ftrace_filter_fn) {
		/* Fallback: resolve ftrace symbols via kallsyms (no symbol_put needed) */
		if (kasumi_ftrace_used_symbol_get) {
			if (kasumi_ftrace_register_fn)
				kasumi_symbol_put("register_ftrace_function");
			if (kasumi_ftrace_unregister_fn)
				kasumi_symbol_put("unregister_ftrace_function");
			if (kasumi_ftrace_filter_fn)
				kasumi_symbol_put("ftrace_set_filter_ips");
		}
		{
			unsigned long a1 = kasumi_lookup_name("register_ftrace_function");
			unsigned long a2 = kasumi_lookup_name("unregister_ftrace_function");
			unsigned long a3 = kasumi_lookup_name("ftrace_set_filter_ips");
			if (!a1 || !a2 || !a3 || IS_ERR_VALUE(a1) || IS_ERR_VALUE(a2) || IS_ERR_VALUE(a3)) {
				kasumi_ftrace_register_fn = NULL;
				kasumi_ftrace_unregister_fn = NULL;
				kasumi_ftrace_filter_fn = NULL;
				return -EOPNOTSUPP;
			}
			kasumi_ftrace_register_fn = (ftrace_register_fn)a1;
			kasumi_ftrace_unregister_fn = (ftrace_unregister_fn)a2;
			kasumi_ftrace_filter_fn = (ftrace_filter_fn)a3;
			kasumi_ftrace_used_symbol_get = false;
			pr_info("Kasumi: ftrace resolved via kallsyms (not exported)\n");
		}
	}

	kasumi_ftrace_base = vmalloc(nr_cpu_ids * sizeof(struct kasumi_ftrace_percpu));
	if (!kasumi_ftrace_base) {
		pr_warn("Kasumi: ftrace vmalloc failed\n");
		ret = -ENOMEM;
		goto err_put;
	}
	memset(kasumi_ftrace_base, 0, nr_cpu_ids * sizeof(struct kasumi_ftrace_percpu));

	for (i = 0; i < 4; i++) {
		addr[i] = kasumi_lookup_name(ft_syms[i]);
		/* vfs_getxattr is optional */
		if (!addr[i] && i < 3) {
			pr_warn("Kasumi: ftrace symbol not found: %s\n", ft_syms[i]);
			vfree(kasumi_ftrace_base);
			kasumi_ftrace_base = NULL;
			ret = -ENOENT;
			goto err_put;
		}
		if (addr[i] && IS_ERR_VALUE(addr[i])) {
			pr_warn("Kasumi: ftrace lookup failed for %s: %ld\n", ft_syms[i], (long)addr[i]);
			vfree(kasumi_ftrace_base);
			kasumi_ftrace_base = NULL;
			ret = -EINVAL;
			goto err_put;
		}
	}
	for (i = 0; i < 4; i++)
		kasumi_ft_addr[i] = addr[i];

	memset(&kasumi_ftrace_ops, 0, sizeof(kasumi_ftrace_ops));
	kasumi_ftrace_ops.func = kasumi_ftrace_callback;
	kasumi_ftrace_ops.flags = FTRACE_OPS_FL_SAVE_REGS;
	ret = kasumi_ftrace_register_fn(&kasumi_ftrace_ops);
	if (ret != 0) {
		pr_warn("Kasumi: register_ftrace_function failed: %d\n", ret);
		vfree(kasumi_ftrace_base);
		kasumi_ftrace_base = NULL;
		goto err_put;
	}
	{
		unsigned long filter_ips[4];
		unsigned int filter_cnt = 0;

		for (i = 0; i < 4; i++) {
			if (kasumi_ft_addr[i])
				filter_ips[filter_cnt++] = kasumi_ft_addr[i];
		}
		if (filter_cnt == 0) {
			pr_warn("Kasumi: no valid ftrace symbol addresses\n");
			ret = -ENOENT;
			kasumi_ftrace_unregister_fn(&kasumi_ftrace_ops);
			vfree(kasumi_ftrace_base);
			kasumi_ftrace_base = NULL;
			goto err_put;
		}
		ret = kasumi_ftrace_filter_fn(&kasumi_ftrace_ops, filter_ips, filter_cnt, 0, 0);
		if (ret != 0) {
			pr_warn("Kasumi: ftrace_set_filter_ips failed: %d\n", ret);
			kasumi_ftrace_unregister_fn(&kasumi_ftrace_ops);
			vfree(kasumi_ftrace_base);
			kasumi_ftrace_base = NULL;
			goto err_put;
		}
	}
	return 0;

err_put:
	if (kasumi_ftrace_used_symbol_get && kasumi_symbol_put) {
		kasumi_symbol_put("register_ftrace_function");
		kasumi_symbol_put("unregister_ftrace_function");
		kasumi_symbol_put("ftrace_set_filter_ips");
	}
	kasumi_ftrace_register_fn = NULL;
	kasumi_ftrace_unregister_fn = NULL;
	kasumi_ftrace_filter_fn = NULL;
	kasumi_ftrace_used_symbol_get = false;
	return ret;
}

void kasumi_ftrace_unregister(void)
{
	if (kasumi_ftrace_unregister_fn)
		kasumi_ftrace_unregister_fn(&kasumi_ftrace_ops);
	vfree(kasumi_ftrace_base);
	kasumi_ftrace_base = NULL;
	if (kasumi_ftrace_used_symbol_get && kasumi_symbol_put) {
		kasumi_symbol_put("register_ftrace_function");
		kasumi_symbol_put("unregister_ftrace_function");
		kasumi_symbol_put("ftrace_set_filter_ips");
	}
	kasumi_ftrace_register_fn = NULL;
	kasumi_ftrace_unregister_fn = NULL;
	kasumi_ftrace_filter_fn = NULL;
	kasumi_ftrace_used_symbol_get = false;
}

#endif /* CONFIG_DYNAMIC_FTRACE */
