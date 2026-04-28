# make -C $KDIR ARCH=arm64 M=$(pwd) modules
# For ddk: ddk build android16-6.12  (KDIR set by container)

KDIR ?= /lib/modules/$(shell uname -r)/build
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

obj-m += kasumi_lkm.o
kasumi_lkm-objs := \
	kasumi_main.o \
	core/kasumi_bootstrap.o \
	core/kasumi_runtime.o \
	core/kasumi_file_view.o \
	control/kasumi_ioctl.o \
	policy/kasumi_path_policy.o \
	overlay/kasumi_overlay.o \
	hooks/kasumi_proc_hooks.o \
	hooks/kasumi_proc_read_hooks.o \
	hooks/kasumi_vfs_hooks.o \
	hooks/kasumi_tracepoint_hooks.o \
	hooks/kasumi_syscall_redirect.o \
	hooks/kasumi_ftrace_hooks.o \
	features/kasumi_uname.o \
	features/kasumi_sop_override.o \
	features/kasumi_dop_override.o \
	features/kasumi_xattr_sid_override.o \
	features/kasumi_iop_override.o \
	features/kasumi_fop_override.o \
	features/kasumi_fake_mountinfo.o

ccflags-y += -gz=none
ccflags-y += -I$(src)/include
ccflags-y += -I$(src)/internal
ccflags-y += -I$(src)/core
ccflags-y += -I$(src)/control
ccflags-y += -I$(src)/policy
ccflags-y += -I$(src)/overlay
ccflags-y += -I$(src)/hooks
ccflags-y += -I$(src)/features
# Do not force CONFIG_DYNAMIC_FTRACE / CONFIG_FUNCTION_TRACER from module flags.
# They must follow target kernel Kconfig, otherwise some arches/toolchains
# (e.g. x86 with missing fentry flags) fail at asm/ftrace.h checks.
# Do NOT add -fno-sanitize=cfi here: init/exit must have kernel-expected CFI type for
# do_one_initcall. Use KASUMI_NOCFI only on functions that make indirect calls to resolved symbols.

all:
	$(MAKE) -C $(KDIR) M=$(MDIR) ARCH=arm64 modules

clean:
	$(MAKE) -C $(KDIR) M=$(MDIR) clean 2>/dev/null || true
	rm -rf .tmp_versions
	@find . -maxdepth 1 -type f ! -name '*.c' ! -name '*.h' ! -name 'Makefile' ! -name '*.md' ! -name '.gitignore' -exec rm -f {} + 2>/dev/null || true
.PHONY: all clean
