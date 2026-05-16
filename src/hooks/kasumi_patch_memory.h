/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Kasumi - bmax-style kernel text/table patch helper.
 *
 * Derived from KernelSU hook/patch_memory.h.
 */
#ifndef _KASUMI_PATCH_MEMORY_H
#define _KASUMI_PATCH_MEMORY_H

#include <linux/types.h>
#include <linux/version.h>

#ifdef __aarch64__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#include <asm/patching.h>
#else
#include <asm/insn.h>
#endif
#elif defined(__x86_64__)
#include <asm/text-patching.h>
#else
#error "Unsupported arch"
#endif

#define KASUMI_PATCH_TEXT_FLUSH_DCACHE 1
#define KASUMI_PATCH_TEXT_FLUSH_ICACHE 2

unsigned long kasumi_phys_from_virt(unsigned long addr, int *err);
int kasumi_patch_text(void *dst, void *src, size_t len, int flags);

#endif /* _KASUMI_PATCH_MEMORY_H */
