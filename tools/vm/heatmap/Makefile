# SPDX-License-Identifier: GPL-2.0
include ../../build/Build.include

MAKEFLAGS += --no-builtin-rules
MAKEFLAGS += --no-builtin-variables

CC := clang
KERNEL_DIR := $(abspath ../../..)

.PHONY: clean all

all: heatmap.user heatmap.skel.h vmlinux.h

%.user: %.user.o
	$(CC) -g -O2 $^ -l:libbpf.a -lelf -lz -o $@ -static

vmlinux.h: $(KERNEL_DIR)/vmlinux
	bpftool btf dump file $(KERNEL_DIR)/vmlinux format c > vmlinux.h

%.bpf.o: vmlinux.h %.bpf.c
	$(CC) -g -D__TARGET_ARCH_x86 -O2 -target bpf -c $*.bpf.c -o $*.bpf.o

%.skel.h: %.bpf.o
	bpftool gen skeleton $*.bpf.o > $*.skel.h

%.user.o: %.skel.h %.user.c
	$(CC) -g -O2 -c $*.user.c -o $*.user.o

clean:
	rm -f *.o heatmap.user *.skel.h vmlinux.h
