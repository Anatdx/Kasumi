#
# Out-of-tree build for HymoFS LKM.
# From kernel source root:
#   make ARCH=arm64 LLVM=1 M=/path/to/HymoFS/src modules
#
# Bootloop workaround: VFS kprobes disabled by default (GET_FD + uname only).
# To enable full path/stat/dir hooks (may cause zygote crash on some devices):
#   make ... ccflags-y="-DHYMOFS_VFS_KPROBES=1"  (or add to EXTRA_CFLAGS)
#

obj-m += hymofs_lkm.o

# Override -gz=zstd when host compiler does not support it.
ccflags-y += -gz=none

clean:
	rm -rf .tmp_versions
	@# Delete all files in this dir except source, Makefile, .md, .gitignore
	@find . -maxdepth 1 -type f ! -name '*.c' ! -name '*.h' ! -name 'Makefile' ! -name '*.md' ! -name '.gitignore' -exec rm -f {} + 2>/dev/null || true
.PHONY: clean
