/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Kasumi - bmax-style arm64 text/table patch helper.
 *
 * Derived from KernelSU hook/arm64/patch_memory.c.
 */
#ifdef __aarch64__

#include "../kasumi_patch_memory.h"

#include <linux/atomic.h>
#include <linux/cpumask.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/stop_machine.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>

#include "kasumi_runtime.h"

typedef void (*kasumi_set_fixmap_fn)(enum fixed_addresses idx,
				     phys_addr_t phys, pgprot_t prot);
typedef void (*kasumi_dcache_range_fn)(unsigned long start, unsigned long end);
typedef void (*kasumi_dcache_area_fn)(void *addr, size_t size);

static struct mm_struct *kasumi_init_mm;
static kasumi_set_fixmap_fn kasumi_set_fixmap;
static kasumi_dcache_range_fn kasumi_dcache_clean_inval_poc;
static kasumi_dcache_range_fn kasumi_caches_clean_inval_pou;
static kasumi_dcache_area_fn kasumi_flush_dcache_area;
static kasumi_dcache_range_fn kasumi_flush_icache_range;

static int kasumi_patch_resolve_symbols(void)
{
	if (!kasumi_init_mm)
		kasumi_init_mm = (void *)kasumi_lookup_name("init_mm");
	if (!kasumi_set_fixmap)
		kasumi_set_fixmap = (void *)kasumi_lookup_name("__set_fixmap");
	if (!kasumi_dcache_clean_inval_poc)
		kasumi_dcache_clean_inval_poc =
			(void *)kasumi_lookup_name_quiet("dcache_clean_inval_poc");
	if (!kasumi_flush_dcache_area)
		kasumi_flush_dcache_area =
			(void *)kasumi_lookup_name_quiet("__flush_dcache_area");
	if (!kasumi_caches_clean_inval_pou)
		kasumi_caches_clean_inval_pou =
			(void *)kasumi_lookup_name_quiet("caches_clean_inval_pou");
	if (!kasumi_flush_icache_range)
		kasumi_flush_icache_range =
			(void *)kasumi_lookup_name_quiet("__flush_icache_range");

	if (!kasumi_init_mm || !kasumi_set_fixmap) {
		pr_err("Kasumi: patch_memory missing init_mm=%px __set_fixmap=%px\n",
		       kasumi_init_mm, kasumi_set_fixmap);
		return -ENOENT;
	}
	return 0;
}

static KASUMI_NOCFI void kasumi_patch_flush_dcache(unsigned long start,
						   size_t size)
{
	if (kasumi_dcache_clean_inval_poc) {
		kasumi_dcache_clean_inval_poc(start, start + size);
		return;
	}
	if (kasumi_flush_dcache_area) {
		kasumi_flush_dcache_area((void *)start, size);
		return;
	}
	if (kasumi_caches_clean_inval_pou)
		kasumi_caches_clean_inval_pou(start, start + size);
}

static KASUMI_NOCFI void kasumi_patch_flush_icache(unsigned long start,
						   size_t size)
{
	if (kasumi_flush_icache_range) {
		kasumi_flush_icache_range(start, start + size);
		return;
	}
	if (kasumi_caches_clean_inval_pou)
		kasumi_caches_clean_inval_pou(start, start + size);
}

unsigned long kasumi_phys_from_virt(unsigned long addr, int *err)
{
	struct mm_struct *mm = kasumi_init_mm;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	*err = 0;
	if (!mm)
		goto fail;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		goto fail;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		goto fail;
#if defined(p4d_leaf)
	if (p4d_leaf(*p4d))
		return __p4d_to_phys(*p4d) + (addr & ~P4D_MASK);
#endif

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		goto fail;
#if defined(pud_leaf)
	if (pud_leaf(*pud))
		return __pud_to_phys(*pud) + (addr & ~PUD_MASK);
#endif

	pmd = pmd_offset(pud, addr);
#if defined(pmd_leaf)
	if (pmd_leaf(*pmd))
		return __pmd_to_phys(*pmd) + (addr & ~PMD_MASK);
#endif
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		goto fail;

	pte = pte_offset_kernel(pmd, addr);
	if (!pte || !pte_present(*pte))
		goto fail;

	return __pte_to_phys(*pte) + (addr & ~PAGE_MASK);

fail:
	*err = -ENOENT;
	return 0;
}

struct kasumi_patch_text_info {
	void *dst;
	void *src;
	size_t len;
	atomic_t cpu_count;
	int flags;
};

static KASUMI_NOCFI int kasumi_patch_text_nosync(void *dst, void *src,
						 size_t len, int flags)
{
	unsigned long p = (unsigned long)dst;
	unsigned long phys;
	void *map;
	int phys_err;

	phys = kasumi_phys_from_virt(p, &phys_err);
	if (phys_err) {
		pr_err("Kasumi: failed to resolve patch target phys addr 0x%lx\n", p);
		return phys_err;
	}

	kasumi_set_fixmap(FIX_TEXT_POKE0, phys, FIXMAP_PAGE_NORMAL);
	map = (void *)(fix_to_virt(FIX_TEXT_POKE0) + (phys & ~PAGE_MASK));
	memcpy(map, src, len);
	kasumi_set_fixmap(FIX_TEXT_POKE0, 0, FIXMAP_PAGE_CLEAR);

	if (flags & KASUMI_PATCH_TEXT_FLUSH_ICACHE)
		kasumi_patch_flush_icache((unsigned long)dst, len);
	if (flags & KASUMI_PATCH_TEXT_FLUSH_DCACHE)
		kasumi_patch_flush_dcache((unsigned long)dst, len);

	return 0;
}

static int kasumi_patch_text_cb(void *arg)
{
	struct kasumi_patch_text_info *info = arg;
	int ret = 0;

	if (atomic_inc_return(&info->cpu_count) == num_online_cpus()) {
		ret = kasumi_patch_text_nosync(info->dst, info->src,
					       info->len, info->flags);
		atomic_inc(&info->cpu_count);
	} else {
		while (atomic_read(&info->cpu_count) <= num_online_cpus())
			cpu_relax();
		isb();
	}

	return ret;
}

int kasumi_patch_text(void *dst, void *src, size_t len, int flags)
{
	struct kasumi_patch_text_info info = {
		.dst = dst,
		.src = src,
		.len = len,
		.cpu_count = ATOMIC_INIT(0),
		.flags = flags,
	};
	int ret;

	ret = kasumi_patch_resolve_symbols();
	if (ret)
		return ret;

	return stop_machine(kasumi_patch_text_cb, &info, cpu_online_mask);
}

#endif /* __aarch64__ */
