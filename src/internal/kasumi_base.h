/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - shared compile-time constants, attributes, and logging helpers.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_BASE_H
#define _KASUMI_BASE_H

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/version.h>

#include "kasumi_uapi.h"

#if defined(__clang__)
#if __clang_major__ >= 17
#define KASUMI_NOCFI __attribute__((no_sanitize("cfi", "kcfi")))
#else
#define KASUMI_NOCFI __attribute__((no_sanitize("cfi")))
#endif
#else
#define KASUMI_NOCFI
#endif

#define KASUMI_HASH_BITS              12
#define KASUMI_BLOOM_BITS             10
#define KASUMI_BLOOM_SIZE             (1 << KASUMI_BLOOM_BITS)
#define KASUMI_BLOOM_MASK             (KASUMI_BLOOM_SIZE - 1)
#define KASUMI_MERGE_HASH_BITS        6
#define KASUMI_MERGE_HASH_SIZE        (1 << KASUMI_MERGE_HASH_BITS)

#define KASUMI_ALLOWLIST_UID_MAX      1024
#define KASUMI_KSU_ALLOWLIST_PATH     "/data/adb/ksu/.allowlist"
#define KASUMI_KSU_ALLOWLIST_MAGIC    0x7f4b5355
#define KASUMI_KSU_ALLOWLIST_VERSION  3
#define KASUMI_KSU_FILE_FORMAT_VERSION 3
#define KASUMI_KSU_APP_PROFILE_VER     2
#define KASUMI_KSU_MAX_PACKAGE_NAME   256
#define KASUMI_KSU_MAX_GROUPS         32
#define KASUMI_KSU_SELINUX_DOMAIN     64

#define KASUMI_PATH_BUF               512
#define KASUMI_ITERATE_PATH_BUF       512

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0))
#define KASUMI_FILLDIR_RET_TYPE int
#define KASUMI_FILLDIR_CONTINUE 0
#define KASUMI_FILLDIR_STOP     1
#else
#define KASUMI_FILLDIR_RET_TYPE bool
#define KASUMI_FILLDIR_CONTINUE true
#define KASUMI_FILLDIR_STOP     false
#endif

#define KASUMI_UID_ALLOW_MARKER ((void *)1)
#define KASUMI_SELINUX_CTX_MAX 96
#define KASUMI_D_PATH_SRC_MAX 256
#define KASUMI_MAX_MERGE_TARGETS 4

extern bool kasumi_debug_enabled;

#define kasumi_log(fmt, ...) (void)(kasumi_debug_enabled && pr_info("Kasumi: " fmt, ##__VA_ARGS__))

#endif /* _KASUMI_BASE_H */
