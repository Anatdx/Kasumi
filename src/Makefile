# make -C $KDIR ARCH=arm64 M=$(pwd) modules
# For ddk: ddk build android17-6.18  (KDIR set by container)

KDIR ?= /lib/modules/$(shell uname -r)/build
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ODIR := $(MDIR)
KMI := $(notdir $(patsubst %/,%,$(KDIR)))

ifeq ($(KMI),android17-6.18)
KBUILD_ARGS := M=$(MDIR) MO=$(ODIR)
else
KBUILD_ARGS := M=$(MDIR)
endif

obj-m += kasumi_lkm.o
# core/kasumi_sop_shadow.o owns the sb->s_op shadow used by dirhijack's virtual
# inode reclaim callbacks. The dead features/kasumi_sop_override.o stub it
# supersedes was removed.
kasumi_lkm-objs := \
	kasumi_main.o \
	core/kasumi_bootstrap.o \
	core/kasumi_runtime.o \
	core/kasumi_fop_bridge.o \
	core/kasumi_vnode.o \
	core/kasumi_dirhijack.o \
	core/kasumi_sop_shadow.o \
	core/kasumi_root_detection.o \
	control/kasumi_ioctl.o \
	policy/kasumi_path_policy.o \
	overlay/kasumi_overlay.o \
	hooks/kasumi_proc_hooks.o \
	hooks/kasumi_proc_read_hooks.o \
	hooks/kasumi_vfs_hooks.o \
	hooks/kasumi_ftrace_hooks.o \
	features/kasumi_iop_override.o \
	features/kasumi_fop_override.o \
	features/kasumi_fake_mountinfo.o \
	features/kasumi_fake_selinuxfs_access.o

kasumi_lkm-$(CONFIG_ARM64) += hooks/arm64/kasumi_patch_memory.o

ccflags-y += -gz=none

# Linux 6.18 exposes the external module source as srcroot when M/MO are
# used. Older kernels keep using src, which may be relative to srctree.
ifneq ($(KBUILD_EXTMOD),)
ifneq ($(srcroot),)
KASUMI_SRC_DIR := $(srcroot)
endif
endif
ifndef KASUMI_SRC_DIR
ifeq ($(filter /%,$(src)),)
KASUMI_SRC_DIR := $(srctree)/$(src)
else
KASUMI_SRC_DIR := $(src)
endif
endif

ccflags-y += -I$(KASUMI_SRC_DIR)/include
ccflags-y += -I$(KASUMI_SRC_DIR)/internal
ccflags-y += -I$(KASUMI_SRC_DIR)/core
ccflags-y += -I$(KASUMI_SRC_DIR)/control
ccflags-y += -I$(KASUMI_SRC_DIR)/policy
ccflags-y += -I$(KASUMI_SRC_DIR)/overlay
ccflags-y += -I$(KASUMI_SRC_DIR)/hooks
ccflags-y += -I$(KASUMI_SRC_DIR)/features
# Do not force CONFIG_DYNAMIC_FTRACE / CONFIG_FUNCTION_TRACER from module flags.
# They must follow target kernel Kconfig, otherwise some arches/toolchains
# (e.g. x86 with missing fentry flags) fail at asm/ftrace.h checks.
# Do NOT add -fno-sanitize=cfi here: init/exit must have kernel-expected CFI type for
# do_one_initcall. Use KASUMI_NOCFI only on functions that make indirect calls to resolved symbols.

all:
	$(MAKE) -C $(KDIR) $(KBUILD_ARGS) ARCH=arm64 modules

clean:
	$(MAKE) -C $(KDIR) $(KBUILD_ARGS) clean 2>/dev/null || true
	rm -rf .tmp_versions
	@find . -maxdepth 1 -type f ! -name '*.c' ! -name '*.h' ! -name 'Makefile' ! -name '*.md' ! -name '.gitignore' -exec rm -f {} + 2>/dev/null || true
.PHONY: all clean
