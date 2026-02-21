/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/tracepoint.h>

#include "hymofs_lkm.h"
#include "hymofs_tracepoint.h"

static int tp_registered;
static struct tracepoint *tp_sys_enter;

static void hymo_sys_enter_handler(void *data, struct pt_regs *regs, long id)
{
	(void)data;
	hymofs_handle_sys_enter_path(regs, id);
}

int hymofs_tracepoint_path_init(void)
{
	int ret;

	tp_sys_enter = (struct tracepoint *)kallsyms_lookup_name("__tracepoint_sys_enter");
	if (!tp_sys_enter) {
		pr_warn("hymofs: __tracepoint_sys_enter not found (kallsyms), falling back to getname_flags kprobe\n");
		return 0;
	}

	ret = tracepoint_probe_register(tp_sys_enter, hymo_sys_enter_handler, NULL);
	if (ret) {
		pr_warn("hymofs: tracepoint_probe_register failed: %d, falling back to getname_flags kprobe\n",
			ret);
		return 0;
	}
	tp_registered = 1;
	pr_info("hymofs: sys_enter tracepoint registered (path redirect)\n");
	return 1;
}

void hymofs_tracepoint_path_exit(void)
{
	if (tp_registered && tp_sys_enter) {
		tracepoint_probe_unregister(tp_sys_enter, hymo_sys_enter_handler, NULL);
		tracepoint_synchronize_unregister();
		pr_info("hymofs: sys_enter tracepoint unregistered\n");
		tp_registered = 0;
		tp_sys_enter = NULL;
	}
}

int hymofs_tracepoint_path_registered(void)
{
	return tp_registered;
}
