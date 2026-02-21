#
# Out-of-tree build for HymoFS LKM.
# From kernel source root:
#   make ARCH=arm64 LLVM=1 M=/path/to/HymoFS/src modules
#
# To disable VFS kprobes if bootloop (GET_FD + uname only):
#   make ... ccflags-y="-DHYMOFS_VFS_KPROBES=0"  (or add to EXTRA_CFLAGS)
#
# To force getname_flags kprobe instead of sys_enter tracepoint (default):
#   make ... ccflags-y="-DHYMOFS_USE_SYSCALL_TRACEPOINT=0"
#

obj-m += hymofs_lkm.o

# Override -gz=zstd when host compiler does not support it.
ccflags-y += -gz=none

# Disable syscall tracepoint (use getname_flags kprobe fallback)
# Required for GKI kernels that don't export __tracepoint_sys_enter
ccflags-y += -DHYMOFS_USE_SYSCALL_TRACEPOINT=0

# CRITICAL: Disable ALL CFI/kCFI for this out-of-tree module.
# GKI kernels enforce CFI, but our dynamic symbol resolution creates
# indirect calls with mismatched CFI type hashes.
ccflags-$(call cc-option,-fno-sanitize=cfi) += -fno-sanitize=cfi
ccflags-$(call cc-option,-fno-sanitize=kcfi) += -fno-sanitize=kcfi

clean:
	rm -rf .tmp_versions
	@# Delete all files in this dir except source, Makefile, .md, .gitignore
	@find . -maxdepth 1 -type f ! -name '*.c' ! -name '*.h' ! -name 'Makefile' ! -name '*.md' ! -name '.gitignore' -exec rm -f {} + 2>/dev/null || true
.PHONY: clean
