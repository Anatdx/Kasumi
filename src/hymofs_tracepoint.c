/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/tracepoint.h>

#include "hymofs_lkm.h"
#include "hymofs_tracepoint.h"

static int tp_path_registered;
static int tp_getfd_registered;
static struct tracepoint *tp_sys_enter;
static struct tracepoint *tp_sys_exit;

static void hymo_sys_enter_handler(void *data, struct pt_regs *regs, long id)
{
	(void)data;
	hymofs_handle_sys_enter_getfd(regs, id);
	hymofs_handle_sys_enter_path(regs, id);
}

static void hymo_sys_exit_handler(void *data, struct pt_regs *regs, long ret)
{
	(void)data;
	hymofs_handle_sys_exit_getfd(regs, ret);
}

int hymofs_tracepoint_path_init(void)
{
	int ret;
	unsigned long addr;

	addr = hymofs_lookup_name("__tracepoint_sys_enter");
	tp_sys_enter = (struct tracepoint *)addr;
	if (!tp_sys_enter) {
		pr_warn("hymofs: __tracepoint_sys_enter not found, falling back to getname_flags kprobe\n");
		return 0;
	}

	ret = tracepoint_probe_register(tp_sys_enter, hymo_sys_enter_handler, NULL);
	if (ret) {
		pr_warn("hymofs: tracepoint_probe_register(sys_enter) failed: %d\n", ret);
		return 0;
	}
	tp_path_registered = 1;

	addr = hymofs_lookup_name("__tracepoint_sys_exit");
	tp_sys_exit = (struct tracepoint *)addr;
	if (tp_sys_exit) {
		ret = tracepoint_probe_register(tp_sys_exit, hymo_sys_exit_handler, NULL);
		if (ret == 0)
			tp_getfd_registered = 1;
	}

	pr_info("hymofs: sys_enter tracepoint (path+GET_FD)%s\n",
		tp_getfd_registered ? ", sys_exit (GET_FD)" : "");
	return 1;
}

void hymofs_tracepoint_path_exit(void)
{
	if (tp_getfd_registered && tp_sys_exit) {
		tracepoint_probe_unregister(tp_sys_exit, hymo_sys_exit_handler, NULL);
		tp_getfd_registered = 0;
		tp_sys_exit = NULL;
	}
	if (tp_path_registered && tp_sys_enter) {
		tracepoint_probe_unregister(tp_sys_enter, hymo_sys_enter_handler, NULL);
		tracepoint_synchronize_unregister();
		tp_path_registered = 0;
		tp_sys_enter = NULL;
	}
}

int hymofs_tracepoint_path_registered(void)
{
	return tp_path_registered;
}

int hymofs_tracepoint_getfd_registered(void)
{
	return tp_getfd_registered;
}
