> [!CAUTION]
> # ⚠️ 重要警告 / IMPORTANT WARNING ⚠️
>
> **本项目目前存在已知或潜在的检测问题，无法保证能够规避检测。作者近期处于消极维护、低活跃开发状态，相关问题可能无法得到及时修复。继续使用本项目所造成的一切后果均由用户自行承担。在作者恢复积极维护并另行通知前，我不建议任何用户继续使用本项目。**
>
> **This project currently has known or potential detection issues and cannot be assumed to evade detection. The author has recently been maintaining and developing it at a low level of activity, so related problems may not be fixed promptly. You are solely responsible for any consequences resulting from continued use. I do not recommend that anyone continue using this project until the author resumes active maintenance and announces otherwise.**

---

# Kasumi

Kasumi is an out-of-tree Linux kernel module (`kasumi_lkm.ko`) for Android GKI/Linux path control in root/SU environments.

It provides redirection, hiding, merge/injection, and spoofing behavior through an anonymous-fd + `ioctl` control plane.

Kasumi was previously developed as HymoFS. The project name, module name, userspace ABI, and public symbols now use Kasumi/KSM naming; HymoFS should be treated as a historical name.

中文版本: [README.zh-CN.md](./README.zh-CN.md)

## Scope and Status

- Repository type: LKM (not an in-tree kernel patch set)
- Main code: `src/`
- Control protocol: `src/include/kasumi_uapi.h`
- Current protocol version: `KSM_PROTOCOL_VERSION = 16`
- Hook strategy: syscall-table TSR for the hot path, with fop/iop shadows and kprobe/ftrace fallbacks where needed
- 6.6+ compatibility for `arch_ftrace_get_regs` is included in current code

## Core Capabilities

- Path redirect: `src -> target`, including `openat`, `statx`, `newfstatat`, `faccessat`, and xattr path syscalls
- Reverse mapping for path presentation (`d_path` related flow)
- Directory entry hiding (`iterate_dir` filtering)
- Directory merge/injection behavior
- `kstat` spoofing (ino/dev/size/time, etc.)
- Overlay/xattr related filtering and SELinux label presentation for injected files
- `uname` spoofing
- `/proc/cmdline` spoofing
- `/proc/<pid>/maps` spoofing rules (ino/dev/pathname)
- Mount-hide and statfs spoof features

Use in controlled environments only. This module hooks VFS and syscall hot paths.

## Hook Overview

- GET_FD path: syscall-table TSR through `reboot`/`prctl`, with legacy kprobe fallbacks
- Path syscalls: syscall-table TSR covers `openat/openat2`, `statx`, `newfstatat`, `faccessat`, `getxattr/lgetxattr`, and `listxattr/llistxattr`
- VFS path: iop/fop shadow hooks handle `getattr` and `readdir`; ftrace/kretprobe paths remain as fallbacks where enabled
- Symbol resolution: prefer `kallsyms_lookup_name`, fallback to per-symbol kprobe resolution

## CI KMI Targets

Current workflow builds:

- `android12-5.10`
- `android13-5.10`
- `android13-5.15`
- `android14-5.15`
- `android14-6.1`
- `android15-6.6`
- `android16-6.12`

See `.github/workflows/build-lkm.yml` and `.github/workflows/ddk-lkm.yml`.

## Build

### Option A: DDK (recommended)

```bash
ddk build
ddk build android14-6.1
ddk build android15-6.6
```

### Option B: Kernel tree local build

Run against a prepared kernel tree (`modules_prepare` done):

```bash
make -C /path/to/kernel ARCH=arm64 M=$(pwd)/src modules
```

## Load and Debug Parameters

```sh
insmod kasumi_lkm.ko
```

If symbol export limitations prevent loading, and you are using newer KernelSU or its forks, you can also try:

```sh
ksud insmod kasumi_lkm.ko
```

Common module parameters in `src/core/kasumi_bootstrap.c`:

- `kasumi_syscall_nr`
- `kasumi_no_tracepoint=1`
- `kasumi_skip_vfs=1`
- `kasumi_skip_extra_kprobes=1`
- `kasumi_skip_getfd=1`
- `kasumi_skip_kallsyms=1`
- `kasumi_dummy_mode=1`

## Userspace Control Plane

1. Userspace obtains an anonymous fd through GET_FD (root-only).
2. Userspace sends `ioctl` on that fd to manage rules/features.

Main ioctls (see `src/include/kasumi_uapi.h` for full ABI):

- `KSM_IOC_ADD_RULE`, `KSM_IOC_DEL_RULE`, `KSM_IOC_HIDE_RULE`
- `KSM_IOC_ADD_MERGE_RULE`, `KSM_IOC_CLEAR_ALL`, `KSM_IOC_SET_ENABLED`
- `KSM_IOC_GET_FEATURES`, `KSM_IOC_GET_HOOKS`, `KSM_IOC_LIST_RULES`
- `KSM_IOC_ADD_SPOOF_KSTAT`, `KSM_IOC_UPDATE_SPOOF_KSTAT`
- `KSM_IOC_SET_UNAME`, `KSM_IOC_SET_CMDLINE`
- `KSM_IOC_ADD_MAPS_RULE`, `KSM_IOC_CLEAR_MAPS_RULES`
- `KSM_IOC_SET_MOUNT_HIDE`, `KSM_IOC_SET_MAPS_SPOOF`, `KSM_IOC_SET_STATFS_SPOOF`

You can use [YukiSU](https://github.com/Anatdx/YukiSU) (C++) for KernelSU-integrated flows.
In addition, the [hybrid-mount](https://github.com/Hybrid-Mount/meta-hybrid_mount) meta-module includes Kasumi support with a Rust userspace implementation.

> Given mount logic quality and update cadence, hybrid-mount is generally the preferred meta-module choice.

## Quick Troubleshooting

- `Unknown symbol __tracepoint_sys_enter`: try `kasumi_no_tracepoint=1`
- Builds but cannot load: check `vermagic`, module signature policy, and `dmesg`
- Hook/ABI changes: validate with `KSM_IOC_GET_HOOKS` and `KSM_IOC_GET_FEATURES`
- Merge/injection regressions: compare `ls`, `ls -l`, `ls -Z`, and `getfattr -n security.selinux` on both canonical and symlinked paths

## Repository Layout

- `src/`: LKM implementation
- `docs/`: design and notes
- `scripts/`: automation scripts
- `.github/workflows/`: multi-KMI build/release pipeline

## License

- SPDX: `Apache-2.0 OR GPL-2.0`
- See `LICENSE`, `LICENSE-GPL-2.0`, and `NOTICE`
