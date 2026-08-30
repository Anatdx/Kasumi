# Kasumi

Kasumi is an out-of-tree Linux kernel module (`kasumi_lkm.ko`) for Android GKI/Linux path control in root/SU environments.

It provides path redirection, hiding, directory merge/injection, and scoped proc/mount presentation through a root-only anonymous-fd + `ioctl` control plane. Kasumi was previously developed as HymoFS; Kasumi/KSM is the current project and ABI name.

中文版本：[README.zh-CN.md](./README.zh-CN.md)

## Status

- Repository type: LKM, not an in-tree kernel patch set
- Implementation: `src/`
- Userspace ABI: `src/include/kasumi_uapi.h`
- Protocol: `KSM_PROTOCOL_VERSION = 17`
- Path view: VFS lookup/vnode based; there is no syscall-table dispatcher or `sys_enter` redirect engine
- Control entry: root-only `reboot` GET_FD command, followed by fd-based ioctls

## Capabilities

- Redirect a visible path to a regular file, symlink, directory, character device, block device, or FIFO source
- Hide paths and merge/inject directory trees, including newly created virtual directory levels
- Preserve visible path, inode/device identity, SELinux context, and exec-time file capabilities where supported
- Forward file and directory mutations to directory-backed sources
- Apply policy by detected root provider or explicit allow/deny UID lists
- Present scoped `/proc/<pid>/maps`, `mountinfo`, `mounts`, mount namespace links, and statfs/statx mount identity
- Configure kstat, maps, mount-hide, statfs, overlay-xattr, and SELinux-oracle filtering features

Socket sources are not supported. Source-less virtual directories are read-only.

## CI KMI Targets

The default DDK release is `20260828`. Current workflows build:

- `android12-5.10`
- `android13-5.10`
- `android13-5.15`
- `android14-5.15`
- `android14-6.1`
- `android15-6.6`
- `android16-6.12`
- `android17-6.18`

See `.github/workflows/build-lkm.yml` and `.github/workflows/ddk-lkm.yml`.

## Build

### DDK

```bash
ddk build
ddk build android14-6.1
ddk build android15-6.6
ddk build android17-6.18
```

### Kernel tree

Run against a prepared kernel tree after `modules_prepare`:

```bash
make -C /path/to/kernel ARCH=arm64 M=$(pwd)/src modules
```

## Load and Module Parameters

```sh
insmod kasumi_lkm.ko
```

If required symbols are not exported and the installed KernelSU implementation supports it:

```sh
ksud insmod kasumi_lkm.ko
```

Useful parameters:

- `kasumi_skip_kallsyms=1`: resolve symbols individually through kprobes
- `kasumi_fscaps=0|1`: disable/enable exec-time source file-capability replay; default `1`
- `kasumi_device_sources=0|1`: disable/enable char/block/FIFO source wrappers; default `1`
- `kasumi_dummy_mode=1`: stop after early initialization for load testing
- `kasumi_dirhijack=0`: debug only; disables the VFS path-view provider and has no TSR fallback
- `kasumi_dirhijack_force=1`: test only; bypasses per-observer visibility policy

`kasumi_no_tracepoint` is retained as a legacy module parameter, but API 17 no longer has a syscall-redirect path engine.

## Userspace API

The shared ABI is defined by [`src/include/kasumi_uapi.h`](./src/include/kasumi_uapi.h). Userspace should include the matching header, zero-initialize all ABI structs, and keep all reserved fields zero.

### 1. Obtain the control fd

GET_FD is available only to UID 0. The fourth syscall argument points to an `int` that receives the new fd:

```c
#include <linux/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "src/include/kasumi_uapi.h"

static int kasumi_get_fd(void)
{
    int fd = -1;

    (void)syscall(SYS_reboot,
                  KSM_MAGIC1, KSM_MAGIC2, KSM_CMD_GET_FD, &fd);
    return fd;
}
```

The underlying `reboot` syscall normally returns an error because these are not Linux reboot magic values. Ignore that syscall return and check the value written to `fd`. The pointer must remain valid until the syscall returns.

### 2. Check protocol and capabilities

Do this before sending configuration commands:

```c
int version = 0;
int features = 0;

if (ioctl(fd, KSM_IOC_GET_VERSION, &version) < 0 ||
    version != KSM_PROTOCOL_VERSION) {
    /* incompatible userspace/kernel ABI */
}

if (ioctl(fd, KSM_IOC_GET_FEATURES, &features) < 0) {
    /* feature query failed */
}
```

Use the feature mask before requesting optional behavior, especially `KSM_FEATURE_QUIESCE` and `KSM_FEATURE_MOUNT_HIDE_AGGRESSIVE`.

### 3. Configure and enable

The recommended controller sequence is:

1. Obtain the fd and verify `KSM_PROTOCOL_VERSION`.
2. Query `KSM_IOC_GET_FEATURES`.
3. Call `KSM_IOC_SET_ENABLED` with `0` before replacing policy. Policy mutations return `-EBUSY` while Kasumi is enabled.
4. Replace policy with `KSM_IOC_REPLACE_POLICY`.
5. Add path/merge/hide rules and configure optional features.
6. Call `KSM_IOC_SET_ENABLED` with `1`.

A minimal redirect looks like this:

```c
int disabled = 0;
int enabled = 1;
struct kasumi_policy_replace_arg policy = {
    .version = KSM_POLICY_API_VERSION,
    .size = sizeof(policy),
    .owner = KSM_POLICY_OWNER_AUTO,
};
struct kasumi_syscall_arg rule = {
    .src = "/system/etc/example.conf",              /* visible path */
    .target = "/data/adb/modules/example/system/etc/example.conf",
    .type = 0,
};

ioctl(fd, KSM_IOC_SET_ENABLED, &disabled);
ioctl(fd, KSM_IOC_REPLACE_POLICY, &policy);
ioctl(fd, KSM_IOC_ADD_RULE, &rule);
ioctl(fd, KSM_IOC_SET_ENABLED, &enabled);
```

For `struct kasumi_syscall_arg`:

- `src` is the visible path controlled by Kasumi.
- `target` is the real backing source path.
- `type` is a legacy/fallback dirent type; controllers normally pass `0` because Kasumi captures the source type.

### Rule ioctls

| ioctl | Argument | Meaning |
| --- | --- | --- |
| `KSM_IOC_ADD_RULE` | `struct kasumi_syscall_arg *` | Redirect visible `src` to backing `target`; replaces an existing rule for the same `src` |
| `KSM_IOC_ADD_MERGE_RULE` | `struct kasumi_syscall_arg *` | Merge backing directory `target` into visible directory `src` |
| `KSM_IOC_HIDE_RULE` | `struct kasumi_syscall_arg *` | Hide `src`; `target` is unused |
| `KSM_IOC_DEL_RULE` | `struct kasumi_syscall_arg *` | Delete the redirect/hide identified by `src` |
| `KSM_IOC_CLEAR_ALL` | no argument | Clear rules and feature state; configured policy is preserved |
| `KSM_IOC_LIST_RULES` | `struct kasumi_syscall_list_arg *` | Write the active rule listing to the caller-provided buffer |

All strings and buffers referenced by an ioctl argument must remain valid until that ioctl returns.

### Policy ioctls

`KSM_IOC_REPLACE_POLICY` is preferred over incremental updates. Set `version = KSM_POLICY_API_VERSION`, `size = sizeof(struct)`, and pass userspace UID arrays through `allow_uids`/`deny_uids` with their counts.

- `AUTO` selects a detected KernelSU or APatch provider.
- `MANUAL` uses explicit UID lists and requires an allow list.
- `MAGISK` is diagnostic-only; use `MANUAL` for Magisk environments.
- Deny entries win over allow entries; isolated UIDs always receive the concealment scope.
- `KSM_IOC_RESET_POLICY` resets policy explicitly. `KSM_IOC_CLEAR_ALL` does not.

To read a consistent snapshot, call `KSM_IOC_GET_POLICY`, then `KSM_IOC_GET_POLICY_UIDS` for the required lists, and retry if the returned `generation` values do not match.

### Feature and status ioctls

| ioctl | Argument |
| --- | --- |
| `KSM_IOC_GET_FEATURES` | `int *` feature mask |
| `KSM_IOC_GET_HOOKS` | `struct kasumi_syscall_list_arg *` output buffer |
| `KSM_IOC_SET_MOUNT_HIDE_MODE` | `int *` containing `KSM_MOUNT_HIDE_MODE_NORMAL` or `KSM_MOUNT_HIDE_MODE_AGGRESSIVE` |
| `KSM_IOC_SET_MOUNT_HIDE` | `struct kasumi_mount_hide_arg *` |
| `KSM_IOC_ADD_MAPS_RULE` / `KSM_IOC_CLEAR_MAPS_RULES` | `struct kasumi_maps_rule *` / no argument |
| `KSM_IOC_SET_MAPS_SPOOF` | `struct kasumi_maps_spoof_arg *` |
| `KSM_IOC_SET_STATFS_SPOOF` | `struct kasumi_statfs_spoof_arg *` |
| `KSM_IOC_ADD_SPOOF_KSTAT` / `KSM_IOC_UPDATE_SPOOF_KSTAT` | `struct kasumi_spoof_kstat *` |
| `KSM_IOC_HIDE_OVERLAY_XATTRS` | `struct kasumi_syscall_arg *`, using `src` |
| `KSM_IOC_SELINUX_FIX` | `int *` enable value |

For ioctls whose argument struct contains `err`, check both the `ioctl()` return value and `arg.err`.

### Unload handshake

If `KSM_FEATURE_QUIESCE` is available, keep exactly one control fd and initialize:

```c
struct kasumi_quiesce_arg q = {
    .version = KSM_QUIESCE_API_VERSION,
    .size = sizeof(q),
};

ioctl(fd, KSM_IOC_PREPARE_UNLOAD, &q);
```

`KSM_IOC_PREPARE_UNLOAD` is an idempotent terminal transition. Repeat it on the same fd while `q.state == KSM_QUIESCE_STATE_DRAINING`. When it reports `READY`, close the fd and invoke `delete_module`; the module-removal result remains the final liveness check. Do not use this command unless the controller is committed to unloading, because new GET_FD requests and ordinary control commands are rejected after draining starts.

### Removed or unsupported ABI slots

- uname and `/proc/cmdline` spoofing have been removed; their old command/feature numbers remain reserved.
- `KSM_IOC_SET_MIRROR_PATH` is retained for ABI numbering and returns `-EOPNOTSUPP`.
- `KSM_IOC_REORDER_MNT_ID` is not supported by the LKM build and returns `-EOPNOTSUPP`.

## Standard Userspace Controller

[Kagami](https://github.com/Rouyashiki/Kagami) is the only standard userspace controller implementation for the current Kasumi ABI. Use its Kasumi client and matching UAPI definitions as the reference when integrating API 17.

## Troubleshooting

- Cannot load: check `vermagic`, module signature policy, symbol availability, and `dmesg`.
- API mismatch: query `KSM_IOC_GET_VERSION` before any configuration command.
- Optional command returns `EOPNOTSUPP`: check `KSM_IOC_GET_FEATURES` and the ABI notes above.
- Inspect active routes and rules with `KSM_IOC_GET_HOOKS` and `KSM_IOC_LIST_RULES`.
- For merge/injection regressions, compare `ls`, `ls -l`, `ls -Z`, and `getfattr -n security.selinux` on canonical and symlinked paths.

## Repository Layout

- `src/`: LKM implementation and shared UAPI
- `scripts/`: automation scripts
- `tools/`: diagnostic tools
- `.github/workflows/`: multi-KMI build/release pipeline

## License

- SPDX: `Apache-2.0 OR GPL-2.0`
- See `LICENSE`, `LICENSE-GPL-2.0`, and `NOTICE`
