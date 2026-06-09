/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - root implementation detection.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/moduleparam.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include "kasumi_root_detection.h"
#include "kasumi_runtime.h"

#define KASUMI_KP_SYMBOL_NAME_LEN 32
#define KASUMI_KP_SYMBOL_SIZE 48
#define KASUMI_KP_SCAN_CHUNK PAGE_SIZE
#define KASUMI_KP_SCAN_OVERLAP KASUMI_KP_SYMBOL_SIZE
#define KASUMI_KP_MAX_SYMBOL_WALK 256
#define KASUMI_KP_MAX_SCAN_RANGE (512UL * 1024 * 1024)
#define KASUMI_KP_MAX_VMAP_RANGE (64UL * 1024 * 1024)
#define KASUMI_KP_MAX_VMAP_AREAS 4096
#define KASUMI_KP_VM_FLAGS 0x44UL
#define KASUMI_KP_SU_NAME "su_get_path"

struct kasumi_kp_symbol {
	u64 addr;
	u64 hash;
	char name[KASUMI_KP_SYMBOL_NAME_LEN];
};

struct kasumi_kp_vmap_area {
	unsigned long va_start;
	unsigned long va_end;
	struct rb_node rb_node;
	struct list_head list;
	union {
		unsigned long subtree_max_size;
		struct vm_struct *vm;
	};
	unsigned long flags;
};

struct kasumi_kp_vmap_pool {
	struct list_head head;
	unsigned long len;
};

struct kasumi_kp_rb_list {
	struct rb_root root;
	struct list_head head;
	spinlock_t lock;
};

struct kasumi_kp_vmap_node {
	struct kasumi_kp_vmap_pool pool[256];
	spinlock_t pool_lock;
	bool skip_populate;
	struct kasumi_kp_rb_list busy;
	struct kasumi_kp_rb_list lazy;
	struct list_head purge_list;
	struct work_struct purge_work;
	unsigned long nr_purged;
};

int kasumi_root_mask;
int kasumi_ksu_dispatcher_nr = -1;
bool kasumi_root_spoof_allowed;
const char *(*kasumi_ap_su_get_path)(void);
int (*kasumi_ap_is_su_allow_uid)(uid_t uid);
int (*kasumi_ap_su_allow_uid_nums)(void);
int (*kasumi_ap_su_allow_uids)(int is_user, uid_t *out_uids, int out_num);
int (*kasumi_ap_su_allow_uid_profile)(int is_user, uid_t uid,
				      struct kasumi_ap_su_profile *profile);
int (*kasumi_ap_get_mod_exclude)(uid_t uid);
int (*kasumi_ap_list_mod_exclude)(uid_t *uids, int len);
int (*kasumi_ap_read_kstorage)(int gid, long did, void *data, int offset,
			       int len, bool data_is_user);
int (*kasumi_ap_list_kstorage_ids)(int gid, long *ids, int idslen,
				   bool data_is_user);

static long (*kasumi_copy_from_kernel_nofault_fn)(void *dst, const void *src,
						  size_t size);
static bool kasumi_copy_from_kernel_nofault_tried;

static KASUMI_NOCFI struct file *kasumi_open_ro(const char *path)
{
	if (!kasumi_filp_open)
		kasumi_filp_open = (void *)kasumi_lookup_callable_quiet("filp_open");
	if (!kasumi_filp_open)
		return ERR_PTR(-ENOENT);
	return kasumi_filp_open(path, O_RDONLY, 0);
}

static KASUMI_NOCFI void kasumi_close_file(struct file *file)
{
	if (!kasumi_filp_close)
		kasumi_filp_close = (void *)kasumi_lookup_callable_quiet("filp_close");
	if (kasumi_filp_close)
		kasumi_filp_close(file, NULL);
	else
		fput(file);
}

static void kasumi_ap_clear_symbols(void)
{
	kasumi_ap_su_get_path = NULL;
	kasumi_ap_is_su_allow_uid = NULL;
	kasumi_ap_su_allow_uid_nums = NULL;
	kasumi_ap_su_allow_uids = NULL;
	kasumi_ap_su_allow_uid_profile = NULL;
	kasumi_ap_get_mod_exclude = NULL;
	kasumi_ap_list_mod_exclude = NULL;
	kasumi_ap_read_kstorage = NULL;
	kasumi_ap_list_kstorage_ids = NULL;
}

static KASUMI_NOCFI bool kasumi_kernel_read_nofault(void *dst, unsigned long src, size_t size)
{
	if (!kasumi_copy_from_kernel_nofault_tried) {
		unsigned long a = kasumi_lookup_callable_quiet("copy_from_kernel_nofault");

		kasumi_copy_from_kernel_nofault_tried = true;
		if (a && kasumi_valid_kernel_addr(a))
			kasumi_copy_from_kernel_nofault_fn = (void *)a;
	}

	return kasumi_copy_from_kernel_nofault_fn &&
	       kasumi_copy_from_kernel_nofault_fn(dst, (const void *)src, size) == 0;
}

static bool kasumi_kp_symbol_name_eq(const struct kasumi_kp_symbol *sym,
				     const char *name)
{
	size_t len = strlen(name);

	if (len >= KASUMI_KP_SYMBOL_NAME_LEN)
		return false;
	if (memcmp(sym->name, name, len) != 0)
		return false;
	return sym->name[len] == '\0';
}

static bool kasumi_kp_read_symbol(unsigned long entry,
				  struct kasumi_kp_symbol *sym)
{
	if (!kasumi_valid_kernel_addr(entry))
		return false;
	return kasumi_kernel_read_nofault(sym, entry, sizeof(*sym));
}

static unsigned long kasumi_kp_lookup_near(unsigned long anchor,
					   const char *name)
{
	struct kasumi_kp_symbol sym;
	int i;

	for (i = -KASUMI_KP_MAX_SYMBOL_WALK; i <= KASUMI_KP_MAX_SYMBOL_WALK; i++) {
		unsigned long entry = anchor + i * KASUMI_KP_SYMBOL_SIZE;

		if (!kasumi_kp_read_symbol(entry, &sym))
			continue;
		if (!kasumi_kp_symbol_name_eq(&sym, name))
			continue;
		if (!kasumi_valid_kernel_addr((unsigned long)sym.addr))
			return 0;
		return (unsigned long)sym.addr;
	}

	return 0;
}

static bool kasumi_kp_parse_table(unsigned long su_name_addr)
{
	unsigned long anchor = su_name_addr - offsetof(struct kasumi_kp_symbol, name);
	struct kasumi_kp_symbol sym;
	unsigned long a;

	if (!kasumi_kp_read_symbol(anchor, &sym) ||
	    !kasumi_kp_symbol_name_eq(&sym, KASUMI_KP_SU_NAME) ||
	    !kasumi_valid_kernel_addr((unsigned long)sym.addr))
		return false;

	a = kasumi_kp_lookup_near(anchor, "su_allow_uid_profile");
	if (!a)
		return false;
	kasumi_ap_su_allow_uid_profile = (void *)a;

	a = kasumi_kp_lookup_near(anchor, "get_ap_mod_exclude");
	if (!a)
		return false;
	kasumi_ap_get_mod_exclude = (void *)a;

	kasumi_ap_su_get_path = (void *)(unsigned long)sym.addr;
	kasumi_ap_is_su_allow_uid =
		(void *)kasumi_kp_lookup_near(anchor, "is_su_allow_uid");
	kasumi_ap_su_allow_uid_nums =
		(void *)kasumi_kp_lookup_near(anchor, "su_allow_uid_nums");
	kasumi_ap_su_allow_uids =
		(void *)kasumi_kp_lookup_near(anchor, "su_allow_uids");
	kasumi_ap_list_mod_exclude =
		(void *)kasumi_kp_lookup_near(anchor, "list_ap_mod_exclude");
	kasumi_ap_read_kstorage =
		(void *)kasumi_kp_lookup_near(anchor, "read_kstorage");
	kasumi_ap_list_kstorage_ids =
		(void *)kasumi_kp_lookup_near(anchor, "list_kstorage_ids");

	pr_info("Kasumi: APatch KP symbols detected: su_get_path=%px profile=%px exclude=%px\n",
		kasumi_ap_su_get_path, kasumi_ap_su_allow_uid_profile,
		kasumi_ap_get_mod_exclude);
	return true;
}

static bool kasumi_kp_scan_chunk(unsigned long base, const char *buf,
				 size_t len)
{
	size_t name_len = strlen(KASUMI_KP_SU_NAME);
	size_t i;

	if (len < name_len)
		return false;

	for (i = 0; i <= len - name_len; i++) {
		if (buf[i] != KASUMI_KP_SU_NAME[0])
			continue;
		if (memcmp(buf + i, KASUMI_KP_SU_NAME, name_len) != 0)
			continue;
		if (kasumi_kp_parse_table(base + i))
			return true;
	}

	return false;
}

static bool kasumi_kp_scan_range(unsigned long start, unsigned long end,
				 const char *tag)
{
	char *buf;
	unsigned long p;

	if (!kasumi_valid_kernel_addr(start) || !kasumi_valid_kernel_addr(end) ||
	    end <= start || end - start > 512UL * 1024 * 1024) {
		pr_warn("Kasumi: skip KP %s scan, bad range [%lx, %lx)\n",
			tag, start, end);
		return false;
	}

	buf = kmalloc(KASUMI_KP_SCAN_CHUNK + KASUMI_KP_SCAN_OVERLAP, GFP_KERNEL);
	if (!buf)
		return false;

	for (p = start; p < end; p += KASUMI_KP_SCAN_CHUNK) {
		size_t len = min_t(unsigned long,
				   KASUMI_KP_SCAN_CHUNK + KASUMI_KP_SCAN_OVERLAP,
				   end - p);

		if (!kasumi_kernel_read_nofault(buf, p, len))
			continue;
		if (kasumi_kp_scan_chunk(p, buf, len)) {
			kfree(buf);
			pr_info("Kasumi: APatch KP symbol table found in %s range [%lx, %lx)\n",
				tag, start, end);
			return true;
		}
	}

	kfree(buf);
	return false;
}

static bool kasumi_kp_scan_kernel_image(void)
{
	unsigned long start = kasumi_lookup_callable_quiet("_text");
	unsigned long end = kasumi_lookup_callable_quiet("_end");

	if (!kasumi_valid_kernel_addr(start))
		start = kasumi_lookup_callable_quiet("_stext");

	if (kasumi_kp_scan_range(start, end, "kernel image"))
		return true;

	return false;
}

static bool kasumi_kp_scan_vmap_list(unsigned long head_addr, const char *tag)
{
	struct kasumi_kp_vmap_area va;
	struct list_head head;
	unsigned long pos;
	int count = 0;

	if (!kasumi_valid_kernel_addr(head_addr) ||
	    !kasumi_kernel_read_nofault(&head, head_addr, sizeof(head)))
		return false;

	pos = (unsigned long)head.next;
	while (kasumi_valid_kernel_addr(pos) && pos != head_addr &&
	       count++ < KASUMI_KP_MAX_VMAP_AREAS) {
		unsigned long va_addr =
			pos - offsetof(struct kasumi_kp_vmap_area, list);
		struct vm_struct vm;
		unsigned long size;

		if (!kasumi_kernel_read_nofault(&va, va_addr, sizeof(va)))
			break;

		if (kasumi_valid_kernel_addr(va.va_start) &&
		    kasumi_valid_kernel_addr(va.va_end) &&
		    va.va_end > va.va_start) {
			size = va.va_end - va.va_start;
			if (size >= KASUMI_KP_SYMBOL_SIZE &&
			    size <= KASUMI_KP_MAX_VMAP_RANGE &&
			    kasumi_valid_kernel_addr((unsigned long)va.vm) &&
			    kasumi_kernel_read_nofault(&vm, (unsigned long)va.vm,
						       sizeof(vm)) &&
			    (unsigned long)vm.addr == va.va_start &&
			    vm.size == size &&
			    vm.flags == KASUMI_KP_VM_FLAGS) {
				pr_info("Kasumi: scanning APatch-like vmap [%lx, %lx) caller=%px\n",
					va.va_start, va.va_end, vm.caller);
				if (kasumi_kp_scan_range(va.va_start, va.va_end, tag))
					return true;
			}
		}

		pos = (unsigned long)va.list.next;
	}

	return false;
}

static bool kasumi_kp_scan_vmap_nodes(void)
{
	unsigned long nodes_sym = kasumi_lookup_callable_quiet("vmap_nodes");
	unsigned long nr_sym = kasumi_lookup_callable_quiet("nr_vmap_nodes");
	struct kasumi_kp_vmap_node *nodes;
	unsigned int nr;
	unsigned int i;

	if (!kasumi_valid_kernel_addr(nodes_sym) ||
	    !kasumi_valid_kernel_addr(nr_sym) ||
	    !kasumi_kernel_read_nofault(&nodes, nodes_sym, sizeof(nodes)) ||
	    !kasumi_kernel_read_nofault(&nr, nr_sym, sizeof(nr)) ||
	    !kasumi_valid_kernel_addr((unsigned long)nodes) ||
	    nr == 0 || nr > 1024)
		return false;

	for (i = 0; i < nr; i++) {
		unsigned long head_addr =
			(unsigned long)&nodes[i].busy.head;

		if (kasumi_kp_scan_vmap_list(head_addr, "vmalloc"))
			return true;
	}

	return false;
}

static bool kasumi_kp_scan_legacy_vmap_list(void)
{
	unsigned long head_addr = kasumi_lookup_callable_quiet("vmap_area_list");

	if (!kasumi_valid_kernel_addr(head_addr))
		return false;

	return kasumi_kp_scan_vmap_list(head_addr, "vmalloc");
}

static bool kasumi_kp_scan_symbols(void)
{
	if (kasumi_kp_scan_kernel_image())
		return true;
	if (kasumi_kp_scan_vmap_nodes())
		return true;
	if (kasumi_kp_scan_legacy_vmap_list())
		return true;

	pr_info("Kasumi: APatch KP symbol table not found in scanned memory\n");
	return false;
}

static bool kasumi_apatch_detect(void)
{
	unsigned long a;

	kasumi_ap_clear_symbols();

	a = kasumi_lookup_callable_quiet("su_get_path");
	if (a && kasumi_valid_kernel_addr(a)) {
		kasumi_ap_su_get_path = (void *)a;
		kasumi_ap_su_allow_uid_profile =
			(void *)kasumi_lookup_callable_quiet("su_allow_uid_profile");
		kasumi_ap_get_mod_exclude =
			(void *)kasumi_lookup_callable_quiet("get_ap_mod_exclude");
		pr_info("Kasumi: APatch sucompat detected via kallsyms\n");
		return true;
	}

	if (kasumi_kp_scan_symbols()) {
		pr_info("Kasumi: APatch sucompat detected via KP symbol scan\n");
		return true;
	}

	return false;
}

static bool kasumi_path_exists(const char *path)
{
	struct file *f;

	if (!path)
		return false;
	f = kasumi_open_ro(path);
	if (IS_ERR(f))
		return false;
	kasumi_close_file(f);
	return true;
}

static bool kasumi_ksu_detect(void)
{
	unsigned long a;
	bool seen = false;
	bool has_policy = false;

	a = kasumi_lookup_callable_quiet("ksu_syscall_table");
	if (a && kasumi_valid_kernel_addr(a)) {
		kasumi_root_mask |= KASUMI_ROOT_KSU;
		seen = true;
		a = kasumi_lookup_callable_quiet("ksu_dispatcher_nr");
		if (a && kasumi_valid_kernel_addr(a)) {
			int nr = -1;

			if (kasumi_kernel_read_nofault(&nr, a, sizeof(nr)) &&
			    nr >= 0) {
				kasumi_ksu_dispatcher_nr = nr;
				kasumi_root_mask |= KASUMI_ROOT_KSU_RDR;
			}
		}
	}

	a = kasumi_lookup_callable_quiet("ksu_uid_should_umount");
	if (a && kasumi_valid_kernel_addr(a)) {
		kasumi_root_mask |= KASUMI_ROOT_KSU;
		kasumi_ksu_uid_should_umount_ptr = (void *)a;
		seen = true;
		has_policy = true;
	}

	a = kasumi_lookup_callable_quiet("ksu_get_allow_list");
	if (a && kasumi_valid_kernel_addr(a)) {
		kasumi_root_mask |= KASUMI_ROOT_KSU;
		kasumi_ksu_get_allow_list_ptr = (void *)a;
		seen = true;
		has_policy = true;
	}

	if (seen) {
		a = kasumi_lookup_callable_quiet("__ksu_is_allow_uid_for_current");
		if (a && kasumi_valid_kernel_addr(a))
			kasumi_ksu_is_allow_uid_ptr = (void *)a;
		if (!kasumi_ksu_is_allow_uid_ptr) {
			a = kasumi_lookup_callable_quiet("__ksu_is_allow_uid");
			if (a && kasumi_valid_kernel_addr(a))
				kasumi_ksu_is_allow_uid_ptr = (void *)a;
		}
	}

	if (kasumi_path_exists(KASUMI_KSU_ALLOWLIST_PATH)) {
		kasumi_root_mask |= KASUMI_ROOT_KSU;
		seen = true;
		has_policy = true;
	}

	if (seen)
		pr_info("Kasumi: KernelSU detected%s%s\n",
			(kasumi_root_mask & KASUMI_ROOT_KSU_RDR) ?
			" (redirect)" : "",
			has_policy ? "" : " (no policy source)");

	return has_policy;
}

static bool kasumi_magisk_detect(void)
{
	static const char * const magisk_paths[] = {
		"/sbin/magisk",
		"/debug_ramdisk/sbin/magisk",
		"/data/adb/magisk/magisk",
		NULL
	};
	int i;

	for (i = 0; magisk_paths[i]; i++) {
		struct file *f = kasumi_open_ro(magisk_paths[i]);

		if (IS_ERR(f))
			continue;
		kasumi_close_file(f);
		kasumi_root_mask |= KASUMI_ROOT_MAGISK;
		pr_info("Kasumi: Magisk detected at %s\n", magisk_paths[i]);
		return true;
	}

	return false;
}

void kasumi_root_detect(void)
{
	bool ksu_active;
	bool apatch_active;
	bool magisk_active;
	int active_roots = 0;

	kasumi_root_mask = KASUMI_ROOT_NONE;
	kasumi_ksu_dispatcher_nr = -1;
	kasumi_root_spoof_allowed = false;

	ksu_active = kasumi_ksu_detect();
	if (!ksu_active && (kasumi_root_mask & KASUMI_ROOT_KSU))
		pr_warn("Kasumi: KernelSU detected without allowlist policy source\n");

	if (kasumi_apatch_detect()) {
		kasumi_root_mask |= KASUMI_ROOT_APATCH;
		apatch_active = true;
	} else {
		apatch_active = false;
	}

	magisk_active = kasumi_magisk_detect();

	if (ksu_active)
		active_roots++;
	if (apatch_active)
		active_roots++;
	if (magisk_active)
		active_roots++;

	if (active_roots > 1) {
		kasumi_root_mask |= KASUMI_ROOT_MULTI;
		pr_warn("Kasumi: multi-root detected (mask=0x%x), spoofing disabled\n",
			kasumi_root_mask);
		return;
	}

	if (ksu_active) {
		kasumi_root_spoof_allowed = true;
		pr_info("Kasumi: root policy owner: KernelSU\n");
		return;
	}

	if (apatch_active) {
		kasumi_root_spoof_allowed = true;
		pr_info("Kasumi: root policy owner: APatch\n");
		return;
	}

	kasumi_root_mask |= KASUMI_ROOT_NON_ROOT;
	pr_warn("Kasumi: no supported root policy owner (mask=0x%x), spoofing disabled\n",
		kasumi_root_mask);
}

bool kasumi_root_allows_spoofing(void)
{
	return READ_ONCE(kasumi_root_spoof_allowed);
}
