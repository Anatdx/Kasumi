> [!CAUTION]
> # ⚠️ 重要警告 / IMPORTANT WARNING ⚠️
>
> **本项目目前存在已知或潜在的检测问题，无法保证能够规避检测。作者近期处于消极维护、低活跃开发状态，相关问题可能无法得到及时修复。继续使用本项目所造成的一切后果均由用户自行承担。在作者恢复积极维护并另行通知前，我不建议任何用户继续使用本项目。**
>
> **This project currently has known or potential detection issues and cannot be assumed to evade detection. The author has recently been maintaining and developing it at a low level of activity, so related problems may not be fixed promptly. You are solely responsible for any consequences resulting from continued use. I do not recommend that anyone continue using this project until the author resumes active maintenance and announces otherwise.**

---

# Kasumi

Kasumi 是一个面向 Android GKI/Linux 的外置内核模块（LKM，产物为 `kasumi_lkm.ko`），用于 root/SU 场景下的路径控制。

它通过“匿名 fd + `ioctl`”控制面提供重定向、隐藏、合并/注入与伪装能力。

Kasumi 的前身是 HymoFS。项目名、模块名、用户态 ABI 与公开符号现在统一使用 Kasumi/KSM 命名；HymoFS 仅作为历史名称保留。

English version： [README.md](./README.md)

## 当前状态

- 仓库形态：LKM（不是 in-tree 内核补丁）
- 主代码目录：`src/`
- 协议定义：`src/include/kasumi_uapi.h`
- 当前协议版本：`KSM_PROTOCOL_VERSION = 16`
- Hook 策略：热路径优先使用 syscall-table TSR，必要时配合 fop/iop shadow 与 kprobe/ftrace 回退
- 已包含 `arch_ftrace_get_regs` 在 6.6+ 的兼容处理

## 主要能力

- 路径重定向：`src -> target`，覆盖 `openat`、`statx`、`newfstatat`、`faccessat` 以及 xattr 路径类 syscall
- 路径展示反向映射（`d_path` 相关）
- 目录隐藏（`iterate_dir` 过滤）
- 目录合并/注入
- `kstat` 伪装（ino/dev/size/time 等）
- overlay/xattr 相关过滤，以及注入文件的 SELinux label 展示
- `uname` 伪装
- `/proc/cmdline` 伪装
- `/proc/<pid>/maps` 规则伪装（ino/dev/pathname）
- mount hide、statfs spoof

> 该模块会拦截 VFS 与 syscall 热路径，请仅在可控环境使用。

## Hook 架构

- GET_FD：通过 `reboot`/`prctl` 走 syscall-table TSR，保留旧 kprobe 回退
- 路径 syscall：syscall-table TSR 覆盖 `openat/openat2`、`statx`、`newfstatat`、`faccessat`、`getxattr/lgetxattr` 与 `listxattr/llistxattr`
- VFS：`getattr` 与 `readdir` 使用 iop/fop shadow hook；必要时仍可使用 ftrace/kretprobe 回退路径
- 符号解析：优先 `kallsyms_lookup_name`，失败回退逐符号 kprobe 解析

## CI 覆盖 KMI

- `android12-5.10`
- `android13-5.10`
- `android13-5.15`
- `android14-5.15`
- `android14-6.1`
- `android15-6.6`
- `android16-6.12`

对应工作流：`.github/workflows/build-lkm.yml`、`.github/workflows/ddk-lkm.yml`。

## 构建

### 方式 A：DDK（推荐）

```bash
ddk build
ddk build android14-6.1
ddk build android15-6.6
```

### 方式 B：内核源码树本地构建

先完成目标内核 `modules_prepare`，再执行：

```bash
make -C /path/to/kernel ARCH=arm64 M=$(pwd)/src modules
```

## 加载与调试参数

```sh
insmod kasumi_lkm.ko
```

如遇符号不全无法加载，且使用新版 KernelSU 及其分支,可尝试

```sh
ksud insmod kasumi_lkm.ko
```

常用参数（定义于 `src/core/kasumi_bootstrap.c`）：

- `kasumi_syscall_nr`
- `kasumi_no_tracepoint=1`
- `kasumi_skip_vfs=1`
- `kasumi_skip_extra_kprobes=1`
- `kasumi_skip_getfd=1`
- `kasumi_skip_kallsyms=1`
- `kasumi_dummy_mode=1`

## 用户态控制面

1. 用户态通过 GET_FD 获取匿名 fd（仅 root）。
2. 对该 fd 发送 `ioctl` 管理规则与特性。

常用 ioctl（完整 ABI 见 `src/include/kasumi_uapi.h`）：

- `KSM_IOC_ADD_RULE`、`KSM_IOC_DEL_RULE`、`KSM_IOC_HIDE_RULE`
- `KSM_IOC_ADD_MERGE_RULE`、`KSM_IOC_CLEAR_ALL`、`KSM_IOC_SET_ENABLED`
- `KSM_IOC_GET_FEATURES`、`KSM_IOC_GET_HOOKS`、`KSM_IOC_LIST_RULES`
- `KSM_IOC_ADD_SPOOF_KSTAT`、`KSM_IOC_UPDATE_SPOOF_KSTAT`
- `KSM_IOC_SET_UNAME`、`KSM_IOC_SET_CMDLINE`
- `KSM_IOC_ADD_MAPS_RULE`、`KSM_IOC_CLEAR_MAPS_RULES`
- `KSM_IOC_SET_MOUNT_HIDE`、`KSM_IOC_SET_MAPS_SPOOF`、`KSM_IOC_SET_STATFS_SPOOF`

Anatdx 本人维护的 [YukiSU](https://github.com/Anatdx/YukiSU) 提供与 KernelSU 集成的实现（C++），
以及 Anatdx 参与开发的 [hybrid-mount](https://github.com/Hybrid-Mount/meta-hybrid_mount) 元模块也加入了 Kasumi 支持与用户态实现（Rust）。

> 由于 kasumi 模块挂载逻辑并不优秀且更新频率缓慢，我推荐使用更优秀的 hybrid-mount 作为元模块使用

## 快速排障

- 出现 `Unknown symbol __tracepoint_sys_enter`：尝试 `kasumi_no_tracepoint=1`
- 可编译但无法加载：检查 `vermagic`、模块签名策略和 `dmesg`
- 调整 hook/ABI 后：优先用 `KSM_IOC_GET_HOOKS` 与 `KSM_IOC_GET_FEATURES` 做运行态自检
- 排查合并/注入回归：同时检查 canonical 与 symlink 路径下的 `ls`、`ls -l`、`ls -Z` 和 `getfattr -n security.selinux`

## 许可证

- SPDX：`Apache-2.0 OR GPL-2.0`
- 详见：`LICENSE`、`LICENSE-GPL-2.0`、`NOTICE`
