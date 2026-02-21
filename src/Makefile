# make -C $KDIR ARCH=arm64 M=$(pwd) modules

obj-m += hymofs_lkm.o
hymofs_lkm-objs := hymofs_core.o hymofs_tracepoint.o

ccflags-y += -gz=none
ccflags-y += $(call cc-option,-fno-sanitize=cfi)

clean:
	rm -rf .tmp_versions
	@find . -maxdepth 1 -type f ! -name '*.c' ! -name '*.h' ! -name 'Makefile' ! -name '*.md' ! -name '.gitignore' -exec rm -f {} + 2>/dev/null || true
.PHONY: clean
