# Root Makefile for ddk build. ddk mounts workspace as /build and sets KDIR.
MDIR := $(CURDIR)/src
ODIR := $(MDIR)
KMI := $(notdir $(patsubst %/,%,$(KDIR)))

# Linux 6.18 requires an explicit external-module output directory when the
# module is built through the DDK M/MO flow. Keep it equal to the source
# directory so artifact paths remain stable for local builds and CI.
ifeq ($(KMI),android17-6.18)
KBUILD_ARGS := M=$(MDIR) MO=$(ODIR)
else
KBUILD_ARGS := M=$(MDIR)
endif

all:
	$(MAKE) -C $(KDIR) ARCH=arm64 $(KBUILD_ARGS) modules

clean:
	$(MAKE) -C $(KDIR) ARCH=arm64 $(KBUILD_ARGS) clean

.PHONY: all clean
