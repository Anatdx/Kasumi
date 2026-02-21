# HymoFS

HymoFS is a **kernel-level path manipulation and hiding framework** for Linux (Android GKI). It provides path redirection, directory entry hiding/injection, path reverse lookup, and optional spoofing of stat, xattr, uname, and cmdline — primarily for root/SU environments (e.g. KernelSU) and module overlay use cases.

> **Warning**: This is an experimental kernel modification. Applying it modifies core VFS and namei code. Use only if you understand the risks.

---

## Features

| Feature | Description | Kconfig |
|--------|-------------|--------|
| **Forward redirect** | Virtual path → real path when opening/execing (namei / `getname`) | `CONFIG_HYMOFS_FORWARD_REDIRECT` |
| **Reverse lookup** | Real path → virtual path when userspace asks for path (e.g. `d_path`) | `CONFIG_HYMOFS_REVERSE_LOOKUP` |
| **Hide entries** | Hide files/dirs from directory listing (`readdir` / getdents) | `CONFIG_HYMOFS_HIDE_ENTRIES` |
| **Inject entries** | Inject virtual entries into directory listings (experimental) | `CONFIG_HYMOFS_INJECT_ENTRIES` |
| **Stat spoofing** | Spoof size, timestamps, mode, etc. for specific inodes | `CONFIG_HYMOFS_STAT_SPOOF` |
| **Xattr filter** | Filter or spoof extended attributes (e.g. SELinux context) | `CONFIG_HYMOFS_XATTR_FILTER` |
| **Uname spoof** | Spoof `uname` syscall (kernel version, etc.) | `CONFIG_HYMOFS_UNAME_SPOOF` |
| **Cmdline spoof** | Spoof `/proc/cmdline` and `/proc/bootconfig` | `CONFIG_HYMOFS_CMDLINE_SPOOF` |

Redirect and hide rules are stored in hash tables in kernel; rules can be added/removed at runtime via a privileged fd obtained through a dedicated syscall/ioctl interface (see **Userspace API** below).

---

## Supported kernels

**All mainstream GKI kernel versions are supported.** The patch and `setup.sh` target **Android GKI-style** trees; version is auto-detected from the kernel `Makefile` (VERSION / PATCHLEVEL), and the matching patch or branch is used.

| Kernel | Typical Android |
|--------|------------------|
| **5.10** | Android 12 / 13 |
| **5.15** | Android 13 / 14 |
| **6.1**  | Android 14 |
| **6.6**  | Android 15 |
| **6.12** | Android 16 |

- The script selects the matching patch or branch from the kernel `Makefile` (VERSION / PATCHLEVEL).
- If your tree layout differs (e.g. no `common/`), you can point to the kernel root and defconfig explicitly (see **Installation**).

---

## Installation

### One-line setup (recommended)

From your **kernel source root** (or the directory that contains `common/` for GKI):

```bash
curl -LSs https://raw.githubusercontent.com/Anatdx/HymoFS/main/setup.sh | bash -s defconfig arch/arm64/configs/gki_defconfig
```

- Detects kernel version and applies the matching patch.
- Applies to `common/` if present, otherwise current directory.
- Appends HymoFS options to the given defconfig (e.g. `CONFIG_HYMOFS=y` and the optional sub-features).

### Manual options

```text
kernel-dir <path>   Kernel source root (default: auto-detect common/ or .)
defconfig <path>    Defconfig path relative to kernel dir (required)
branch <name>       HymoFS branch, e.g. android15_6.6 (default: from Makefile)
repo <url>          HymoFS repo URL (default: https://github.com/Anatdx/HymoFS)
help                Show usage
```

Example for 6.6 kernel with custom dir:

```bash
curl -LSs https://raw.githubusercontent.com/Anatdx/HymoFS/main/setup.sh | bash -s kernel-dir /path/to/kernel defconfig arch/arm64/configs/gki_defconfig branch android15_6.6
```

### After applying the patch

1. Build the kernel as usual. HymoFS is built as part of the kernel (`fs/hymofs.c`, `CONFIG_HYMOFS=y`).
2. Ensure a userspace daemon (e.g. [hymo](https://github.com/Anatdx/hymo)) obtains the HymoFS fd and configures redirect/hide rules; otherwise the patch is inert.

---

## Kconfig options

All under `CONFIG_HYMOFS`:

| Option | Default | Description |
|--------|----------|-------------|
| `CONFIG_HYMOFS` | y | Master switch for HymoFS. |
| `CONFIG_HYMOFS_REVERSE_LOOKUP` | y | Reverse path lookup (d_path → virtual path). |
| `CONFIG_HYMOFS_FORWARD_REDIRECT` | y | Forward path redirection (namei / getname). |
| `CONFIG_HYMOFS_HIDE_ENTRIES` | y | Hide entries in readdir. |
| `CONFIG_HYMOFS_INJECT_ENTRIES` | y | Inject virtual entries in readdir (experimental). |
| `CONFIG_HYMOFS_STAT_SPOOF` | y | Spoof stat/kstat. |
| `CONFIG_HYMOFS_XATTR_FILTER` | y | Filter/spoof xattrs. |
| `CONFIG_HYMOFS_UNAME_SPOOF` | y | Spoof uname. |
| `CONFIG_HYMOFS_CMDLINE_SPOOF` | y | Spoof /proc/cmdline and bootconfig. |
| `CONFIG_HYMOFS_DEBUG` | n | Verbose kernel logging (disable in production). |

Setup script appends a typical set (including debug) to your defconfig; you can edit the defconfig to turn sub-features off.

---

## Patched kernel files

HymoFS touches the following areas:

- **fs**: `Kconfig`, `Makefile`, `d_path.c`, `exec.c`, `hymofs.c` (new), `namei.c`, `open.c`, `readdir.c`, `stat.c`, `xattr.c`, `proc/cmdline.c`
- **include/linux**: `hymofs.h`, `hymo_magic.h` (new)
- **kernel**: `reboot.c`, `sys.c`

So it hooks path resolution (namei, getname in exec/open), `d_path`, readdir/filldir, stat, xattr, uname, and cmdline. Compatibility with other VFS/namei or security modules is not guaranteed.

---

## Userspace API

- **Privileged fd**: Userspace obtains a single fd (e.g. via the HYMO_CMD_GET_FD supercall or equivalent). All control is done via **ioctl** on that fd. Definitions are in `include/linux/hymo_magic.h` (or the copy in hymo).
- **Protocol version**: `HYMO_PROTOCOL_VERSION` (e.g. 12). Daemon and kernel should agree.
- **Main ioctls** (see `hymo_magic.h` for full list):
  - `HYMO_IOC_ADD_RULE` / `HYMO_IOC_DEL_RULE`: add/remove redirect rule (src → target).
  - `HYMO_IOC_HIDE_RULE`: hide path.
  - `HYMO_IOC_ADD_MERGE_RULE`: merge directory (e.g. overlay).
  - `HYMO_IOC_CLEAR_ALL`: clear all rules.
  - `HYMO_IOC_SET_ENABLED`: global on/off.
  - `HYMO_IOC_SET_STEALTH`: stealth (e.g. mount id / devname spoof).
  - `HYMO_IOC_SET_DEBUG`, `HYMO_IOC_GET_VERSION`, `HYMO_IOC_LIST_RULES`, etc.
  - Optional: `HYMO_IOC_ADD_SPOOF_KSTAT`, `HYMO_IOC_SET_UNAME`, `HYMO_IOC_SET_CMDLINE`, `HYMO_IOC_SET_HIDE_UIDS`, etc.

Rule and path lengths are limited (e.g. `HYMO_MAX_LEN_PATHNAME`). Structures and magic numbers are shared between kernel and userspace (e.g. hymo's `hymofs.cpp` / `hymo_magic.h`).

---

## Integration

- **[hymo](https://github.com/Anatdx/hymo)** (Hymo): C++ module manager for KernelSU that can use HymoFS for mounting overlays. It runs the HymoFS daemon and configures rules; the kernel patch is required only when using HymoFS mode.
- **KernelSU**: HymoFS can hide or redirect paths used by SU and modules (e.g. `/data/adb/`, overlay mounts). Allowlist and profile structures in the patch (e.g. KSU allowlist path) are for integration with KernelSU-aware logic.

---

## Risks and limitations

- **Stability**: Modifying core VFS/namei and readdir is intrusive. Bugs can cause kernel panics, freezes, or data corruption. Prefer testing on non-critical devices.
- **Performance**: Redirect/hide checks add cost to open, exec, readdir, and d_path. Sub-features (inject, stat spoof, debug) add more. Disable what you don't need.
- **Compatibility**: May conflict with other filesystem or security patches (e.g. SELinux, other overlay/hide schemes). One HymoFS patch variant may also touch `security/selinux/avc.c`; check your tree.
- **Security**: Running with a privileged HymoFS daemon and kernel patch broadens the TCB. Use only in controlled/root environments.

---

## Acknowledgements

**Special thanks to [susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu)** — HymoFS was inspired by and borrows design ideas from the SUSFS project (path hiding, readdir hooks, overlay concepts).

---

## License

- **Author's work** — Licensed under **Apache License 2.0 (Apache-2.0)**. Use, copy, modify, and distribute under Apache-2.0 when not linked with the Linux kernel.

- **Kernel use** — When used as a **Linux kernel module (LKM)** or built into the kernel (e.g. in-tree patch), **GNU General Public License v2.0 (GPL-2.0)** applies for kernel compatibility.

- [LICENSE](LICENSE) — Apache 2.0 full text  
- [LICENSE-GPL-2.0](LICENSE-GPL-2.0) — GPL-2.0 full text  
- [NOTICE](NOTICE) — copyright and license notice  

SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
