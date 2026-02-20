#!/bin/bash

# HymoFS One-Line Setup Script
# Usage: curl -LSs https://raw.githubusercontent.com/Anatdx/HymoFS/main/setup.sh | bash -s defconfig arch/arm64/configs/gki_defconfig with-susfs

set -e

# Default configuration
REPO_URL="https://github.com/Anatdx/HymoFS" 
BRANCH="main"
MANUAL_BRANCH=false

KERNEL_DIR=""
DEFCONFIG_PATH=""

function show_help {
    echo "HymoFS Setup Script"
    echo "Usage: curl ... | bash -s [options]"
    echo ""
    echo "Options:"
    echo "  kernel-dir <path>   Kernel source root directory (Default: detects common/ or current dir)"
    echo "  defconfig <path>    Path to defconfig file (Relative to kernel directory)"
    echo "  branch <name>       Specify HymoFS branch (Default: main)"
    echo "  repo <url>          Specify HymoFS repository URL"
    echo "  help                Show this help message"
    exit 1
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        kernel-dir) KERNEL_DIR="$2"; shift ;;
        defconfig) DEFCONFIG_PATH="$2"; shift ;;
        branch) BRANCH="$2"; MANUAL_BRANCH=true; shift ;;
        repo) REPO_URL="$2"; shift ;;
        help) show_help ;;
        *) echo "Unknown parameter: $1"; show_help ;;
    esac
    shift
done

# Auto-detect kernel directory
if [ -z "$KERNEL_DIR" ]; then
    if [ -d "common/fs" ] && [ -d "common/kernel" ]; then
        KERNEL_DIR="common"
        echo ">>> Kernel directory not specified, detected common/, using: $KERNEL_DIR"
    else
        KERNEL_DIR="."
        echo ">>> Kernel directory not specified, using current directory: $KERNEL_DIR"
    fi
fi

if [ -z "$DEFCONFIG_PATH" ]; then
    echo "Error: defconfig is required"
    show_help
fi

ORIGINAL_PWD="$PWD"
KERNEL_DIR=$(realpath "$KERNEL_DIR")
if [ ! -d "$KERNEL_DIR" ]; then
    echo "Error: Kernel directory does not exist: $KERNEL_DIR"
    exit 1
fi

# Resolve Defconfig Path
if [ -f "$KERNEL_DIR/$DEFCONFIG_PATH" ]; then
    TARGET_DEFCONFIG=$(realpath "$KERNEL_DIR/$DEFCONFIG_PATH")
elif [ -f "$DEFCONFIG_PATH" ]; then
    TARGET_DEFCONFIG=$(realpath "$DEFCONFIG_PATH")
else
    echo "Error: defconfig file not found: $DEFCONFIG_PATH"
    exit 1
fi

# Auto-detect branch if not manually specified
if [ "$MANUAL_BRANCH" = false ]; then
    if [ -f "$KERNEL_DIR/Makefile" ]; then
        KVER=$(grep "^VERSION =" "$KERNEL_DIR/Makefile" | head -n1 | awk '{print $3}')
        KPATCH=$(grep "^PATCHLEVEL =" "$KERNEL_DIR/Makefile" | head -n1 | awk '{print $3}')
        
        if [ -n "$KVER" ] && [ -n "$KPATCH" ]; then
            FULL_VER="$KVER.$KPATCH"
            echo ">>> Detected Kernel Version: $FULL_VER"

            AVER=""
            if [ -n "${ANDROID_VERSION:-}" ]; then
                AVER="$ANDROID_VERSION"
                echo ">>> Android version from env: $AVER"
            elif [ -f "$KERNEL_DIR/build.config.constants" ]; then
                BUILD_BRANCH=$(grep "^BRANCH=" "$KERNEL_DIR/build.config.constants" | head -n1 | sed 's/BRANCH=android\([0-9]*\).*/\1/')
                if [ -n "$BUILD_BRANCH" ]; then
                    AVER="$BUILD_BRANCH"
                    echo ">>> Android version from build.config.constants: $AVER"
                fi
            fi

            if [ "$KVER" -eq 6 ] && [ "$KPATCH" -eq 1 ]; then
                BRANCH="android14_6.1"
                echo ">>> Auto-selected branch: $BRANCH"
            elif [ "$KVER" -eq 6 ] && [ "$KPATCH" -eq 6 ]; then
                BRANCH="android15_6.6"
                echo ">>> Auto-selected branch: $BRANCH"
            elif [ "$KVER" -eq 6 ] && [ "$KPATCH" -eq 12 ]; then
                BRANCH="android16_6.12"
                echo ">>> Auto-selected branch: $BRANCH"
            elif [ "$KVER" -eq 5 ] && [ "$KPATCH" -eq 15 ]; then
                if [ "$AVER" = "14" ]; then
                    BRANCH="android14_5.15"
                else
                    BRANCH="android13_5.15"
                fi
                echo ">>> Auto-selected branch: $BRANCH"
            elif [ "$KVER" -eq 5 ] && [ "$KPATCH" -eq 10 ]; then
                if [ "$AVER" = "13" ]; then
                    BRANCH="android13_5.10"
                else
                    BRANCH="android12_5.10"
                fi
                echo ">>> Auto-selected branch: $BRANCH"
            else
                echo "Error: Unsupported kernel version detected: $FULL_VER"
                echo "Currently only Kernel5.10, 5.15, 6.1, 6.6 and 6.12 are supported."
                echo "You can force a specific branch using branch <name>"
                exit 1
            fi
        else
            echo ">>> Warning: Could not parse version from Makefile. Using default branch: $BRANCH"
        fi
    else
        echo ">>> Warning: Makefile not found in $KERNEL_DIR. Using default branch: $BRANCH"
    fi
fi

WORK_DIR=$(mktemp -d)
echo ">>> Starting HymoFS setup"
echo "    Work directory: $WORK_DIR"

function cleanup {
    echo ">>> Cleaning up temporary files..."
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

echo ">>> Cloning HymoFS ($BRANCH)..."
if git clone --depth=1 -b "$BRANCH" "$REPO_URL" "$WORK_DIR/HymoFS"; then
    echo "    Clone successful"
else
    echo "    Clone failed, please check network or repository URL"
    exit 1
fi

PATCH_FILE="$WORK_DIR/HymoFS/patch/hymofs.patch"
echo ">>> Mode: Standard"

if [ ! -f "$PATCH_FILE" ]; then
    echo "Error: Patch file not found '$PATCH_FILE'"
    exit 1
fi

echo ">>> Applying HymoFS patch to $KERNEL_DIR..."
cd "$KERNEL_DIR"

if [ -f "fs/hymofs.c" ]; then
    echo "Warning: fs/hymofs.c detected, patch might have been applied already."
    if [ -t 0 ]; then
        read -p "Continue to overwrite/apply? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Operation cancelled."
            exit 0
        fi
    else
        echo "Non-interactive mode, attempting to continue..."
    fi
fi

if patch -p1 -F 3 < "$PATCH_FILE"; then
    echo "  [*] Patch applied successfully."
else
    echo "  [!] Patch application failed, please check error logs."
    exit 1
fi

echo ">>> Modifying defconfig..."

if grep -q "CONFIG_HYMOFS=y" "$TARGET_DEFCONFIG"; then
    echo "  [*] defconfig already contains CONFIG_HYMOFS, skipping."
else
    echo "" >> "$TARGET_DEFCONFIG"
    echo "# HymoFS Support" >> "$TARGET_DEFCONFIG"
    echo "CONFIG_HYMOFS=y" >> "$TARGET_DEFCONFIG"
    echo "CONFIG_HYMOFS_REVERSE_LOOKUP=y" >> "$TARGET_DEFCONFIG"
    echo "CONFIG_HYMOFS_FORWARD_REDIRECT=y" >> "$TARGET_DEFCONFIG"
    echo "CONFIG_HYMOFS_HIDE_ENTRIES=y" >> "$TARGET_DEFCONFIG"
    echo "CONFIG_HYMOFS_INJECT_ENTRIES=y" >> "$TARGET_DEFCONFIG"
    echo "CONFIG_HYMOFS_STAT_SPOOF=y" >> "$TARGET_DEFCONFIG"
    echo "CONFIG_HYMOFS_XATTR_FILTER=y" >> "$TARGET_DEFCONFIG"
    echo "CONFIG_HYMOFS_UNAME_SPOOF=y" >> "$TARGET_DEFCONFIG"
    echo "CONFIG_HYMOFS_CMDLINE_SPOOF=y" >> "$TARGET_DEFCONFIG"
    echo "CONFIG_HYMOFS_DEBUG=y" >> "$TARGET_DEFCONFIG"
fi

echo ">>> HymoFS integration completed!"
