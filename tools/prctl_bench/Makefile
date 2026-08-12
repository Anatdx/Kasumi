CC ?= clang
OUT ?= out/prctl_bench
STATIC ?= 0

CFLAGS ?= -O2 -g0
CFLAGS += -std=c11 -Wall -Wextra -Werror

ifeq ($(STATIC),1)
LDFLAGS += -static
endif

all: $(OUT)

$(OUT): prctl_bench.c
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -rf out

.PHONY: all clean
