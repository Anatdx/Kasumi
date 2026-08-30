# Kasumi

Kasumi 是一个面向 Android GKI/Linux 的外置内核模块（LKM，产物为 `kasumi_lkm.ko`），用于 root/SU 环境下的路径控制。

它通过仅 root 可用的“匿名 fd + `ioctl`”控制面提供路径重定向、隐藏、目录合并/注入，以及按作用域生成的 proc/mount 视图。Kasumi 的前身是 HymoFS；当前项目名与 ABI 名称统一为 Kasumi/KSM。

English version: [README.md](./README.md)

## 当前状态

- 仓库形态：LKM，不是 in-tree 内核补丁
- 内核实现：`src/`
- 用户态 ABI：`src/include/kasumi_uapi.h`
- 当前协议：`KSM_PROTOCOL_VERSION = 17`
- 路径视图：由 VFS lookup/vnode 提供，不再包含 syscall table dispatcher 或 `sys_enter` redirect 引擎
- 控制入口：root-only `reboot` GET_FD 命令，后续操作全部通过 fd ioctl 完成

## 主要能力

- 将可见路径重定向到普通文件、符号链接、目录、字符设备、块设备或 FIFO 源
- 隐藏路径、合并/注入目录树，以及生成不存在的中间虚拟目录
- 在支持的场景中保持可见路径、inode/dev 身份、SELinux context 与 exec file capabilities
- 将文件属性修改及目录 mutation 写穿到目录型真实源
- 按自动检测的 root provider 或显式 allow/deny UID 列表应用策略
- 按作用域生成 `/proc/<pid>/maps`、`mountinfo`、`mounts`、挂载命名空间链接及 statfs/statx mount 身份
- 配置 kstat、maps、mount hide、statfs、overlay xattr 与 SELinux oracle 过滤

不支持 socket 源；无真实源的纯虚拟目录只读。

## CI 覆盖 KMI

默认 DDK release 为 `20260828`，当前工作流构建：

- `android12-5.10`
- `android13-5.10`
- `android13-5.15`
- `android14-5.15`
- `android14-6.1`
- `android15-6.6`
- `android16-6.12`
- `android17-6.18`

对应工作流：`.github/workflows/build-lkm.yml`、`.github/workflows/ddk-lkm.yml`。

## 构建

### DDK

```bash
ddk build
ddk build android14-6.1
ddk build android15-6.6
ddk build android17-6.18
```

### 内核源码树

目标内核完成 `modules_prepare` 后执行：

```bash
make -C /path/to/kernel ARCH=arm64 M=$(pwd)/src modules
```

## 加载与模块参数

```sh
insmod kasumi_lkm.ko
```

如果内核未导出所需符号，且已安装的 KernelSU 实现支持模块加载，也可以使用：

```sh
ksud insmod kasumi_lkm.ko
```

常用参数：

- `kasumi_skip_kallsyms=1`：通过逐符号 kprobe 解析符号
- `kasumi_fscaps=0|1`：关闭/启用 exec 时的源文件 capability 回放，默认 `1`
- `kasumi_device_sources=0|1`：关闭/启用 char/block/FIFO 源 wrapper，默认 `1`
- `kasumi_dummy_mode=1`：用于加载测试，在初始化早期退出
- `kasumi_dirhijack=0`：仅用于调试；关闭 VFS 路径视图，且不存在 TSR fallback
- `kasumi_dirhijack_force=1`：仅用于测试；绕过按观察者生效的可见性 policy

`kasumi_no_tracepoint` 仅作为历史兼容参数保留；API 17 已不存在 syscall redirect 路径引擎。

## 用户态接口

共享 ABI 定义在 [`src/include/kasumi_uapi.h`](./src/include/kasumi_uapi.h)。用户态必须使用匹配的头文件、将 ABI 结构体清零，并保证所有 reserved 字段为 0。

### 1. 获取控制 fd

GET_FD 仅允许 UID 0 调用。syscall 的第四个参数指向接收新 fd 的 `int`：

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

这些参数不是 Linux reboot magic，因此底层 `reboot` syscall 通常会返回错误。不要以 syscall 返回值判断 GET_FD 是否成功，应检查 task_work 写回的 `fd`。`fd` 指针必须保持有效，直到 syscall 返回。

### 2. 检查协议与能力

发送配置命令前先执行：

```c
int version = 0;
int features = 0;

if (ioctl(fd, KSM_IOC_GET_VERSION, &version) < 0 ||
    version != KSM_PROTOCOL_VERSION) {
    /* 用户态与内核 ABI 不兼容 */
}

if (ioctl(fd, KSM_IOC_GET_FEATURES, &features) < 0) {
    /* 能力查询失败 */
}
```

请求可选能力前必须检查 feature mask，尤其是 `KSM_FEATURE_QUIESCE` 与 `KSM_FEATURE_MOUNT_HIDE_AGGRESSIVE`。

### 3. 配置并启用

推荐的控制器调用顺序：

1. 获取 fd，并校验 `KSM_PROTOCOL_VERSION`。
2. 查询 `KSM_IOC_GET_FEATURES`。
3. 在替换 policy 前，通过 `KSM_IOC_SET_ENABLED` 传入 `0`。Kasumi enabled 时修改 policy 会返回 `-EBUSY`。
4. 使用 `KSM_IOC_REPLACE_POLICY` 原子替换 policy。
5. 添加路径/合并/隐藏规则，并配置可选功能。
6. 通过 `KSM_IOC_SET_ENABLED` 传入 `1`。

最小重定向示例：

```c
int disabled = 0;
int enabled = 1;
struct kasumi_policy_replace_arg policy = {
    .version = KSM_POLICY_API_VERSION,
    .size = sizeof(policy),
    .owner = KSM_POLICY_OWNER_AUTO,
};
struct kasumi_syscall_arg rule = {
    .src = "/system/etc/example.conf",              /* 可见路径 */
    .target = "/data/adb/modules/example/system/etc/example.conf",
    .type = 0,
};

ioctl(fd, KSM_IOC_SET_ENABLED, &disabled);
ioctl(fd, KSM_IOC_REPLACE_POLICY, &policy);
ioctl(fd, KSM_IOC_ADD_RULE, &rule);
ioctl(fd, KSM_IOC_SET_ENABLED, &enabled);
```

`struct kasumi_syscall_arg` 字段含义：

- `src`：由 Kasumi 控制的可见路径。
- `target`：真实后端源路径。
- `type`：历史/fallback dirent 类型；Kasumi 会捕获源类型，控制器通常传 `0`。

### 路径规则接口

| ioctl | 参数 | 含义 |
| --- | --- | --- |
| `KSM_IOC_ADD_RULE` | `struct kasumi_syscall_arg *` | 将可见 `src` 重定向到后端 `target`；同一 `src` 已存在时替换旧规则 |
| `KSM_IOC_ADD_MERGE_RULE` | `struct kasumi_syscall_arg *` | 将后端目录 `target` 合并到可见目录 `src` |
| `KSM_IOC_HIDE_RULE` | `struct kasumi_syscall_arg *` | 隐藏 `src`；不使用 `target` |
| `KSM_IOC_DEL_RULE` | `struct kasumi_syscall_arg *` | 按 `src` 删除 redirect/hide 规则 |
| `KSM_IOC_CLEAR_ALL` | 无参数 | 清空规则与 feature 状态；保留已配置的 policy |
| `KSM_IOC_LIST_RULES` | `struct kasumi_syscall_list_arg *` | 将当前规则列表写入调用方提供的 buffer |

ioctl 参数引用的字符串和 buffer 必须保持有效，直到该 ioctl 返回。

### Policy 接口

控制器应优先使用 `KSM_IOC_REPLACE_POLICY`，不要拆成多次增量更新。调用时设置 `version = KSM_POLICY_API_VERSION`、`size = sizeof(struct)`，并通过 `allow_uids`/`deny_uids` 传入用户态 UID 数组及对应 count。

- `AUTO`：使用自动检测到的 KernelSU 或 APatch provider。
- `MANUAL`：完全使用显式 UID 列表，且必须提供 allow list。
- `MAGISK`：只用于诊断报告；Magisk 环境应使用 `MANUAL`。
- deny 的优先级高于 allow；isolated UID 始终进入 concealment scope。
- `KSM_IOC_RESET_POLICY` 显式重置 policy；`KSM_IOC_CLEAR_ALL` 不会重置 policy。

读取一致快照时，先调用 `KSM_IOC_GET_POLICY`，再按需调用 `KSM_IOC_GET_POLICY_UIDS`；如果返回的 `generation` 不一致，则重新读取。

### Feature 与状态接口

| ioctl | 参数 |
| --- | --- |
| `KSM_IOC_GET_FEATURES` | `int *` feature mask |
| `KSM_IOC_GET_HOOKS` | `struct kasumi_syscall_list_arg *` 输出 buffer |
| `KSM_IOC_SET_MOUNT_HIDE_MODE` | 指向 `KSM_MOUNT_HIDE_MODE_NORMAL` 或 `KSM_MOUNT_HIDE_MODE_AGGRESSIVE` 的 `int *` |
| `KSM_IOC_SET_MOUNT_HIDE` | `struct kasumi_mount_hide_arg *` |
| `KSM_IOC_ADD_MAPS_RULE` / `KSM_IOC_CLEAR_MAPS_RULES` | `struct kasumi_maps_rule *` / 无参数 |
| `KSM_IOC_SET_MAPS_SPOOF` | `struct kasumi_maps_spoof_arg *` |
| `KSM_IOC_SET_STATFS_SPOOF` | `struct kasumi_statfs_spoof_arg *` |
| `KSM_IOC_ADD_SPOOF_KSTAT` / `KSM_IOC_UPDATE_SPOOF_KSTAT` | `struct kasumi_spoof_kstat *` |
| `KSM_IOC_HIDE_OVERLAY_XATTRS` | `struct kasumi_syscall_arg *`，使用 `src` 字段 |
| `KSM_IOC_SELINUX_FIX` | 指向 enable 值的 `int *` |

对于参数结构体中带 `err` 字段的 ioctl，应同时检查 `ioctl()` 返回值与 `arg.err`。

### 卸载握手

当 `KSM_FEATURE_QUIESCE` 可用时，只保留一个控制 fd，并初始化：

```c
struct kasumi_quiesce_arg q = {
    .version = KSM_QUIESCE_API_VERSION,
    .size = sizeof(q),
};

ioctl(fd, KSM_IOC_PREPARE_UNLOAD, &q);
```

`KSM_IOC_PREPARE_UNLOAD` 是幂等的终止状态转换。`q.state == KSM_QUIESCE_STATE_DRAINING` 时，在同一 fd 上重复调用；状态变为 `READY` 后关闭 fd，再调用 `delete_module`，模块删除结果仍是最终存活性判断。进入 draining 后，新 GET_FD 与普通控制命令都会被拒绝，因此只有确定要卸载时才应调用该接口。

### 已移除或不支持的 ABI 槽位

- uname 与 `/proc/cmdline` spoof 已移除，旧 command/feature 编号仅保留占位。
- `KSM_IOC_SET_MIRROR_PATH` 只保留 ABI 编号，返回 `-EOPNOTSUPP`。
- LKM 不支持 `KSM_IOC_REORDER_MNT_ID`，调用会返回 `-EOPNOTSUPP`。

## 标准用户态控制器

[Kagami](https://github.com/Rouyashiki/Kagami) 是当前 Kasumi ABI 唯一的标准用户态控制器实现。接入 API 17 时，应以其中的 Kasumi client 与配套 UAPI 定义作为参考。

## 快速排障

- 无法加载：检查 `vermagic`、模块签名策略、符号可用性与 `dmesg`。
- ABI 不匹配：任何配置命令前先查询 `KSM_IOC_GET_VERSION`。
- 可选命令返回 `EOPNOTSUPP`：检查 `KSM_IOC_GET_FEATURES` 及上面的 ABI 说明。
- 使用 `KSM_IOC_GET_HOOKS` 与 `KSM_IOC_LIST_RULES` 检查当前运行状态和规则。
- 排查 merge/injection 时，同时比较 canonical 与 symlink 路径下的 `ls`、`ls -l`、`ls -Z` 和 `getfattr -n security.selinux`。

## 仓库结构

- `src/`：LKM 实现与共享 UAPI
- `scripts/`：自动化脚本
- `tools/`：诊断工具
- `.github/workflows/`：多 KMI 构建与发布流程

## 许可证

- SPDX：`Apache-2.0 OR GPL-2.0`
- 详见 `LICENSE`、`LICENSE-GPL-2.0` 与 `NOTICE`
