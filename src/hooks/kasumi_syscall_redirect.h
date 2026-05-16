/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
#ifndef _KASUMI_SYSCALL_REDIRECT_H
#define _KASUMI_SYSCALL_REDIRECT_H
#include <linux/types.h>
#include <asm/ptrace.h>

#if defined(__aarch64__)
#define PT_REGS_ORIG_SYSCALL(_regs) ((_regs)->regs[8])
#elif defined(__x86_64__)
#define PT_REGS_ORIG_SYSCALL(_regs) ((_regs)->orig_ax)
#else
#define PT_REGS_ORIG_SYSCALL(_regs) (0)
#endif

extern void *kasumi_syscall_table;
extern int  kasumi_syscall_dispatcher_nr;
typedef long (*kasumi_syscall_hook_fn)(const struct pt_regs *regs);

int  kasumi_syscall_redirect_init(void);
void kasumi_syscall_redirect_exit(void);
int  kasumi_register_syscall_hook(int nr, kasumi_syscall_hook_fn fn);
void kasumi_unregister_syscall_hook(int nr);
bool kasumi_has_syscall_hook(int nr);
extern kasumi_syscall_hook_fn orig_kernel_openat;
extern kasumi_syscall_hook_fn orig_kernel_openat2;
extern kasumi_syscall_hook_fn orig_kernel_statfs;
extern kasumi_syscall_hook_fn orig_kernel_fstatfs;
#ifdef __NR_statx
extern kasumi_syscall_hook_fn orig_kernel_statx;
#endif
#ifdef __NR_statfs64
extern kasumi_syscall_hook_fn orig_kernel_statfs64;
#endif
#ifdef __NR_fstatfs64
extern kasumi_syscall_hook_fn orig_kernel_fstatfs64;
#endif
#endif
