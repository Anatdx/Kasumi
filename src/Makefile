#
# Out-of-tree build for HymoFS LKM.
# From kernel source root:
#   make ARCH=arm64 LLVM=1 M=/path/to/HymoFS/src modules
#
# To disable VFS kprobes if bootloop (GET_FD + uname only):
#   make ... ccflags-y="-DHYMOFS_VFS_KPROBES=0"  (or add to EXTRA_CFLAGS)
#

obj-m += hymofs_lkm.o

# Override -gz=zstd when host compiler does not support it.
ccflags-y += -gz=none

# Disable CFI for this out-of-tree module: all indirect calls to dynamically
# resolved kernel symbols (via kallsyms/kprobe) will have mismatched CFI type
# hashes and trigger CFI failures otherwise.
ccflags-y += $(call cc-option,-fno-sanitize=cfi)

clean:
	rm -rf .tmp_versions
	@# Delete all files in this dir except source, Makefile, .md, .gitignore
	@find . -maxdepth 1 -type f ! -name '*.c' ! -name '*.h' ! -name 'Makefile' ! -name '*.md' ! -name '.gitignore' -exec rm -f {} + 2>/dev/null || true
.PHONY: clean
