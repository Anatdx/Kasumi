/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - userspace/kernel shared definitions (ioctl, protocol, constants).
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_UAPI_H
#define _KASUMI_UAPI_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/bits.h>
#else
#include <sys/ioctl.h>
#include <stddef.h>
#include <stdint.h>
#endif // #ifdef __KERNEL__

#define KSM_MAGIC1 0x4B534D31  // "KSM1"
#define KSM_MAGIC2 0x524F4F54  // "ROOT"
#define KSM_PROTOCOL_VERSION 17

#define KSM_MAX_LEN_PATHNAME 256
#define KSM_FAKE_CMDLINE_SIZE 4096

/*
 * Kasumi inode marking bits (stored in inode->i_mapping->flags)
 * Using high bits to avoid conflict with kernel AS_* flags and SUSFS bits
 * SUSFS uses bits 33-39, we use 40+
 */
#ifdef __KERNEL__
#define AS_FLAGS_KASUMI_HIDE 40
#define BIT_KASUMI_HIDE BIT(40)
/* Marks a directory as containing hidden entries (for fast filldir skip) */
#define AS_FLAGS_KASUMI_DIR_HAS_HIDDEN 41
#define BIT_KASUMI_DIR_HAS_HIDDEN BIT(41)
/* Marks an inode for kstat spoofing */
#define AS_FLAGS_KASUMI_SPOOF_KSTAT 42
#define BIT_KASUMI_SPOOF_KSTAT BIT(42)
/* Marks a directory as having inject/merge rules (fast path for iterate_dir) */
#define AS_FLAGS_KASUMI_DIR_HAS_INJECT 43
#define BIT_KASUMI_DIR_HAS_INJECT BIT(43)
/* Marks an inode as having shadow inode_operations installed (lookup-time i_op override) */
#define AS_FLAGS_KASUMI_IOP_INSTALLED 44
#define BIT_KASUMI_IOP_INSTALLED BIT(44)
/* Marks a directory inode as having shadow file_operations installed for readdir */
#define AS_FLAGS_KASUMI_FOP_INSTALLED 45
#define BIT_KASUMI_FOP_INSTALLED BIT(45)
#endif // #ifdef __KERNEL__

/* Syscall number: 142 = SYS_reboot on aarch64; we kprobe __arm64_sys_reboot (5.10 compatible). */
#define KSM_SYSCALL_NR 142

/* Only one syscall command: Get anonymous FD */
#define KSM_CMD_GET_FD 0x48021

struct kasumi_syscall_arg {
    const char *src;
    const char *target;
    int type;
};

struct kasumi_syscall_list_arg {
    char *buf;  // Keep as char* for output buffer
    size_t size;
};

struct kasumi_uid_list_arg {
    __u32 count;
    __u32 reserved;
    __aligned_u64 uids;
};

#define KSM_POLICY_API_VERSION 1

/*
 * AUTO uses the detected root provider. MANUAL is driven only by the explicit
 * UID policy below. MAGISK is reported for diagnostics but is not currently a
 * supported provider; use MANUAL when running on Magisk.
 */
#define KSM_POLICY_OWNER_AUTO       0
#define KSM_POLICY_OWNER_KERNELSU   1
#define KSM_POLICY_OWNER_APATCH     2
#define KSM_POLICY_OWNER_MAGISK     3
#define KSM_POLICY_OWNER_MANUAL     4
#define KSM_POLICY_OWNER_DISABLED   5

/* detected_roots bitmask returned by KSM_IOC_GET_POLICY. */
#define KSM_POLICY_ROOT_KERNELSU          (1U << 0)
#define KSM_POLICY_ROOT_KERNELSU_REDIRECT (1U << 1)
#define KSM_POLICY_ROOT_APATCH            (1U << 2)
#define KSM_POLICY_ROOT_MAGISK            (1U << 3)
#define KSM_POLICY_ROOT_MULTI             (1U << 4)
#define KSM_POLICY_ROOT_NO_PROVIDER       (1U << 5)

/* DENY wins over ALLOW for ordinary app UIDs. Isolated UIDs always receive
 * the concealment scope; INCLUDE_ISOLATED_UIDS is retained for ABI stability.
 */
#define KSM_POLICY_FLAG_USE_ALLOW_UIDS        (1U << 0)
#define KSM_POLICY_FLAG_USE_DENY_UIDS         (1U << 1)
#define KSM_POLICY_FLAG_INCLUDE_ISOLATED_UIDS (1U << 2)

#define KSM_POLICY_UID_LIST_ALLOW 1
#define KSM_POLICY_UID_LIST_DENY  2
#define KSM_POLICY_UID_LIST_ALL   3

struct kasumi_policy_config_arg {
	__u32 version;
	__u32 size;
	__u32 owner;
	__u32 flags;
	__u32 reserved[4];
	__s32 err;
};

struct kasumi_policy_state_arg {
	__u32 version;
	__u32 size;
	__u32 owner;
	__u32 effective_owner;
	__u32 flags;
	__u32 detected_roots;
	__u32 allow_count;
	__u32 deny_count;
	__u32 max_uid_count;
	/* Covers configured owner, flags, and lists; provider detection is live. */
	__aligned_u64 generation;
	__u32 enabled;
	__u32 reserved[3];
	__s32 err;
};

struct kasumi_policy_uid_list_arg {
	__u32 version;
	__u32 size;
	__u32 list;
	__u32 count;
	__u32 total;
	__u32 reserved;
	__aligned_u64 uids;
	__aligned_u64 generation; /* configured-policy snapshot generation */
	__s32 err;
};

/*
 * Atomically replace owner, flags, and both UID lists. Userspace controllers
 * should prefer this over the incremental SET_POLICY/SET_POLICY_UIDS ioctls.
 */
struct kasumi_policy_replace_arg {
	__u32 version;
	__u32 size;
	__u32 owner;
	__u32 flags;
	__u32 allow_count;
	__u32 deny_count;
	__aligned_u64 allow_uids;
	__aligned_u64 deny_uids;
	__u32 reserved[4];
	__s32 err;
};

/*
 * kstat spoofing structure - allows full control over stat() results
 * Similar to susfs sus_kstat but with Kasumi conventions
 */
struct kasumi_spoof_kstat {
    unsigned long target_ino;                           /* Target inode number (after mount/overlay) */
    char target_pathname[KSM_MAX_LEN_PATHNAME];        /* Path to spoof */
    unsigned long spoofed_ino;                          /* Spoofed inode number */
    unsigned long spoofed_dev;                          /* Spoofed device number */
    unsigned int spoofed_nlink;                         /* Spoofed link count */
    long long spoofed_size;                             /* Spoofed file size */
    long spoofed_atime_sec;                             /* Spoofed access time (seconds) */
    long spoofed_atime_nsec;                            /* Spoofed access time (nanoseconds) */
    long spoofed_mtime_sec;                             /* Spoofed modification time (seconds) */
    long spoofed_mtime_nsec;                            /* Spoofed modification time (nanoseconds) */
    long spoofed_ctime_sec;                             /* Spoofed change time (seconds) */
    long spoofed_ctime_nsec;                            /* Spoofed change time (nanoseconds) */
    unsigned long spoofed_blksize;                      /* Spoofed block size */
    unsigned long long spoofed_blocks;                  /* Spoofed block count */
    int is_static;                                      /* If true, ino won't change after remount */
    int err;                                            /* Error code for userspace feedback */
};

/*
 * cmdline spoofing structure - spoof /proc/cmdline
 */
struct kasumi_spoof_cmdline {
    char cmdline[KSM_FAKE_CMDLINE_SIZE];               /* Fake cmdline content */
    int err;
};

/*
 * Feature flags for KSM_CMD_GET_FEATURES
 */
#define KSM_FEATURE_KSTAT_SPOOF    (1 << 0)
/* Bit 1 remains reserved for the removed uname feature. */
#define KSM_FEATURE_CMDLINE_SPOOF  (1 << 2)
#define KSM_FEATURE_SELINUX_BYPASS (1 << 4)
#define KSM_FEATURE_MERGE_DIR      (1 << 5)
#define KSM_FEATURE_MOUNT_HIDE    (1 << 6)  /* hide overlay from /proc/mounts and /proc/pid/mountinfo */
#define KSM_FEATURE_MAPS_SPOOF    (1 << 7)  /* spoof ino/dev/pathname in /proc/pid/maps (read buffer filter) */
#define KSM_FEATURE_STATFS_SPOOF  (1 << 8)  /* spoof statfs f_type so direct matches resolved (INCONSISTENT_MOUNT) */
#define KSM_FEATURE_FAKE_MOUNTINFO (1 << 9) /* serve per-marked-app fake mountinfo (no KSU mounts, renumbered ids) */
#define KSM_FEATURE_SELINUX_FIX (1 << 10) /* hide SELinux oracles from hidden app-zygote and isolated apps */
#define KSM_FEATURE_FAKE_SELINUXFS KSM_FEATURE_SELINUX_FIX /* compatibility alias */

/*
 * Maps spoof rule: when a /proc/pid/maps line has (target_ino[, target_dev]),
 * replace ino/dev/pathname with spoofed values. target_dev 0 = match any dev.
 */
struct kasumi_maps_rule {
	unsigned long target_ino;
	unsigned long target_dev;   /* 0 = match any device */
	unsigned long spoofed_ino;
	unsigned long spoofed_dev;
	char spoofed_pathname[KSM_MAX_LEN_PATHNAME];
	int err;
};

/*
 * Feature config structs - enable + reserved for future custom rules.
 * mount_hide: path_pattern empty = hide all overlay; non-empty = hide only matching (future).
 * maps_spoof: rules via ADD_MAPS_RULE; struct allows future inline rule.
 * statfs_spoof: path empty = auto spoof; non-empty = custom path->f_type (future).
 */
struct kasumi_mount_hide_arg {
	int enable;
	char path_pattern[KSM_MAX_LEN_PATHNAME];  /* reserved: empty = all overlay */
	int err;
};

struct kasumi_maps_spoof_arg {
	int enable;
	/* reserved for future: inline rule, batch config */
	char reserved[sizeof(struct kasumi_maps_rule)];
	int err;
};

struct kasumi_statfs_spoof_arg {
	int enable;
	char path[KSM_MAX_LEN_PATHNAME];  /* reserved: empty = auto */
	unsigned long spoof_f_type;         /* reserved: 0 = use d_real_inode */
	int err;
};

// ioctl definitions (for fd-based mode)
// Must be after struct definitions
#define KSM_IOC_MAGIC 'S'
#define KSM_IOC_ADD_RULE           _IOW(KSM_IOC_MAGIC, 1, struct kasumi_syscall_arg)
#define KSM_IOC_DEL_RULE           _IOW(KSM_IOC_MAGIC, 2, struct kasumi_syscall_arg)
#define KSM_IOC_HIDE_RULE          _IOW(KSM_IOC_MAGIC, 3, struct kasumi_syscall_arg)
#define KSM_IOC_CLEAR_ALL          _IO(KSM_IOC_MAGIC, 5)
#define KSM_IOC_GET_VERSION        _IOR(KSM_IOC_MAGIC, 6, int)
#define KSM_IOC_LIST_RULES         _IOWR(KSM_IOC_MAGIC, 7, struct kasumi_syscall_list_arg)
#define KSM_IOC_SET_DEBUG          _IOW(KSM_IOC_MAGIC, 8, int)
#define KSM_IOC_REORDER_MNT_ID     _IO(KSM_IOC_MAGIC, 9)
#define KSM_IOC_SET_STEALTH        _IOW(KSM_IOC_MAGIC, 10, int)
#define KSM_IOC_HIDE_OVERLAY_XATTRS _IOW(KSM_IOC_MAGIC, 11, struct kasumi_syscall_arg)
#define KSM_IOC_ADD_MERGE_RULE     _IOW(KSM_IOC_MAGIC, 12, struct kasumi_syscall_arg)
#define KSM_IOC_SET_MIRROR_PATH    _IOW(KSM_IOC_MAGIC, 14, struct kasumi_syscall_arg)
#define KSM_IOC_ADD_SPOOF_KSTAT    _IOW(KSM_IOC_MAGIC, 15, struct kasumi_spoof_kstat)
#define KSM_IOC_UPDATE_SPOOF_KSTAT _IOW(KSM_IOC_MAGIC, 16, struct kasumi_spoof_kstat)
#define KSM_IOC_SET_CMDLINE        _IOW(KSM_IOC_MAGIC, 18, struct kasumi_spoof_cmdline)
#define KSM_IOC_GET_FEATURES       _IOR(KSM_IOC_MAGIC, 19, int)
#define KSM_IOC_SET_ENABLED        _IOW(KSM_IOC_MAGIC, 20, int)
#define KSM_IOC_SET_HIDE_UIDS      _IOW(KSM_IOC_MAGIC, 21, struct kasumi_uid_list_arg)
#define KSM_IOC_GET_HOOKS          _IOWR(KSM_IOC_MAGIC, 22, struct kasumi_syscall_list_arg)
#define KSM_IOC_ADD_MAPS_RULE     _IOW(KSM_IOC_MAGIC, 23, struct kasumi_maps_rule)
#define KSM_IOC_CLEAR_MAPS_RULES   _IO(KSM_IOC_MAGIC, 24)
#define KSM_IOC_SET_MOUNT_HIDE     _IOW(KSM_IOC_MAGIC, 25, struct kasumi_mount_hide_arg)
#define KSM_IOC_SET_MAPS_SPOOF    _IOW(KSM_IOC_MAGIC, 26, struct kasumi_maps_spoof_arg)
#define KSM_IOC_SET_STATFS_SPOOF  _IOW(KSM_IOC_MAGIC, 27, struct kasumi_statfs_spoof_arg)
/* Commands 17 and 28 remain reserved for removed uname operations. */
#define KSM_IOC_SELINUX_FIX       _IOW(KSM_IOC_MAGIC, 29, int)
/* Policy mutations require SET_ENABLED(0) first and return -EBUSY otherwise. */
#define KSM_IOC_SET_POLICY        _IOWR(KSM_IOC_MAGIC, 30, struct kasumi_policy_config_arg)
#define KSM_IOC_SET_POLICY_OWNER  KSM_IOC_SET_POLICY
#define KSM_IOC_SET_POLICY_UIDS   _IOWR(KSM_IOC_MAGIC, 31, struct kasumi_policy_uid_list_arg)
#define KSM_IOC_CLEAR_POLICY_UIDS _IOWR(KSM_IOC_MAGIC, 32, struct kasumi_policy_uid_list_arg)
#define KSM_IOC_GET_POLICY        _IOWR(KSM_IOC_MAGIC, 33, struct kasumi_policy_state_arg)
#define KSM_IOC_GET_POLICY_UIDS   _IOWR(KSM_IOC_MAGIC, 34, struct kasumi_policy_uid_list_arg)
#define KSM_IOC_REPLACE_POLICY    _IOWR(KSM_IOC_MAGIC, 35, struct kasumi_policy_replace_arg)
/* Unlike CLEAR_ALL, RESET_POLICY discards the configured policy. */
#define KSM_IOC_RESET_POLICY      _IOWR(KSM_IOC_MAGIC, 36, struct kasumi_policy_config_arg)

#endif /* _KASUMI_UAPI_H */
