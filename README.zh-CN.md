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
- 当前协议版本：`KSM_PROTOCOL_VERSION = 17`
- Hook 策略：优先使用 fop/iop/VFS 操作层 hook；TSR 只保留给当前 LKM inode 模型无法表达的虚拟路径查找
- 已包含 `arch_ftrace_get_regs` 在 6.6+ 的兼容处理

## 主要能力

- 路径重定向：`src -> target`，覆盖 `openat`、`statfs`、`statx`、`newfstatat`、`faccessat` 以及 xattr 路径类 syscall
- 路径展示反向映射（`d_path` 相关）
- 目录隐藏（`iterate_dir` 过滤）
- 目录合并/注入
- `kstat` 伪装（ino/dev/size/time 等）
- overlay/xattr 相关过滤，以及注入文件的 SELinux label 展示
- `/proc/cmdline` 伪装
- `/proc/<pid>/maps` 规则伪装（ino/dev/pathname）
- mount hide、statfs spoof

> 该模块会拦截部分 VFS 操作与路径 syscall，请仅在可控环境使用。

## Hook 架构

- TSR：`sys_enter` 将已注册的 syscall number 重定向到一个共享 dispatcher；dispatcher 只占用一个空闲 `ni_syscall` 表项，不再修改目标 syscall 表项
- GET_FD：通过仅 root 可用的 `reboot` kprobe 将 fd 安装排入 task work；`reboot` 与 `prctl` 均不属于 TSR 路由
- 路径 syscall：TSR 覆盖 `openat/openat2`、`statfs`、`statx`、`newfstatat`、`faccessat`、`getxattr/lgetxattr` 与 `listxattr/llistxattr`
- 数据面 syscall：`read`、`write`、`getdents64`、`fstatfs` 不再是 TSR 路由；cmdline、proc attr、目录遍历与 statfs 伪装分别下沉到 producer/VFS 操作层
- KernelSU 共存：Kasumi 选择另一个空闲 dispatcher 槽位，并且不会覆盖已被其他 TSR 使用者重定向的 syscall number
- VFS：`getattr` 与 `readdir` 使用 iop/fop shadow hook；statfs 伪装挂在 `vfs_statfs`，且只作用于当前 fake mountinfo 视图中被隐藏的挂载
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

- `kasumi_no_tracepoint=1`（禁用 TSR；虚拟路径重定向将不可用，独立的操作层功能可继续工作）
- `kasumi_tsr_basic=1`（调试：仅保留 `openat/openat2` TSR 路由）
- `kasumi_skip_kallsyms=1`
- `kasumi_dummy_mode=1`

## 用户态控制面

1. 用户态通过仅 root 可用的 `reboot` GET_FD 命令获取匿名 fd。
2. 对该 fd 发送 `ioctl` 管理规则与特性。

常用 ioctl（完整 ABI 见 `src/include/kasumi_uapi.h`）：

- `KSM_IOC_ADD_RULE`、`KSM_IOC_DEL_RULE`、`KSM_IOC_HIDE_RULE`
- `KSM_IOC_ADD_MERGE_RULE`、`KSM_IOC_CLEAR_ALL`、`KSM_IOC_SET_ENABLED`
- `KSM_IOC_GET_FEATURES`、`KSM_IOC_GET_HOOKS`、`KSM_IOC_LIST_RULES`
- `KSM_IOC_ADD_SPOOF_KSTAT`、`KSM_IOC_UPDATE_SPOOF_KSTAT`
- `KSM_IOC_SET_CMDLINE`
- `KSM_IOC_ADD_MAPS_RULE`、`KSM_IOC_CLEAR_MAPS_RULES`
- `KSM_IOC_SET_MOUNT_HIDE`、`KSM_IOC_SET_MOUNT_HIDE_MODE`、`KSM_IOC_SET_MAPS_SPOOF`、`KSM_IOC_SET_STATFS_SPOOF`
- `KSM_IOC_REPLACE_POLICY`、`KSM_IOC_GET_POLICY`、`KSM_IOC_GET_POLICY_UIDS`
- `KSM_IOC_RESET_POLICY`（policy 必须显式重置；`KSM_IOC_CLEAR_ALL` 保留 policy）

API 17 将 owner、flags 与两张 UID 表作为一个 RCU snapshot 一次发布。热路径不会
观察到重建一半的列表，替换失败也不会破坏旧 policy。`MANUAL` 必须配置显式 allow
列表，deny 始终拥有最终否决权。用户态应优先使用 `KSM_IOC_REPLACE_POLICY`，并在组合
查询 policy state 与 UID 列表时检查返回的 generation。generation 只覆盖配置的
owner、flags 与列表；provider 检测及 `effective_owner` 是实时状态。
policy 只能在 Kasumi disabled 状态修改。用户态必须先调用
`KSM_IOC_SET_ENABLED(0)`，完成 SET/REPLACE/CLEAR/RESET 后再显式启用完整配置。

mount hide 默认为普通模式：只从 proc 挂载视图移除 root 所有的挂载，不改变真实传播
属性与挂载命名空间链接。激进模式还会将 zygote_next 的 shared 根投影为 private slave，
并向选中进程返回合成的 `/proc/*/ns/mnt` 链接。用户态只能在
`KSM_FEATURE_MOUNT_HIDE_AGGRESSIVE` 可用时请求激进模式。

Anatdx 本人维护的 [YukiSU](https://github.com/Anatdx/YukiSU) 提供与 KernelSU 集成的实现（C++），
以及 Anatdx 参与开发的 [hybrid-mount](https://github.com/Hybrid-Mount/meta-hybrid_mount) 元模块也加入了 Kasumi 支持与用户态实现（Rust）。

> 由于 kasumi 模块挂载逻辑并不优秀且更新频率缓慢，我推荐使用更优秀的 hybrid-mount 作为元模块使用

## 快速排障

- TSR 初始化报告 `sys_enter` 不可用：`kasumi_no_tracepoint=1` 只用于操作层诊断，不再提供全局路径 hook 回退
- 可编译但无法加载：检查 `vermagic`、模块签名策略和 `dmesg`
- 调整 hook/ABI 后：优先用 `KSM_IOC_GET_HOOKS` 与 `KSM_IOC_GET_FEATURES` 做运行态自检
- 排查合并/注入回归：同时检查 canonical 与 symlink 路径下的 `ls`、`ls -l`、`ls -Z` 和 `getfattr -n security.selinux`

## 许可证

- SPDX：`Apache-2.0 OR GPL-2.0`
- 详见：`LICENSE`、`LICENSE-GPL-2.0`、`NOTICE`
