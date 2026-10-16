# SPDX-License-Identifier: MIT
#
# Deterministic AI Sandbox — build
#
#   make vmlinux   generate src/vmlinux.h from the running kernel's BTF
#   make           build the loader + eBPF object
#   make demo      run the end-to-end demo (root required)
#
# Requires: clang, bpftool (linux-tools), libbpf-dev, libelf-dev, zlib1g-dev
# Kernel:    >= 5.15, CONFIG_BPF_LSM=y, `bpf` in the lsm= boot param.

CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH     := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm/')

.PHONY: all demo vmlinux clean

all: sandbox

# Generate only the BTF header (e.g. to inspect what your kernel exposes).
vmlinux: src/vmlinux.h

src/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "note: vmlinux.h is machine-specific and deliberately not committed"

sandbox.bpf.o: src/sandbox.bpf.c src/policy.h src/vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Isrc -c $< -o $@

src/sandbox.skel.h: sandbox.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

sandbox: src/sandbox.c src/sandbox.skel.h src/policy.h
	$(CC) -g -O2 -Wall -Isrc -o $@ src/sandbox.c -lbpf -lelf -lz

demo: sandbox
	sudo ./demo.sh

clean:
	rm -f sandbox sandbox.bpf.o src/sandbox.skel.h src/vmlinux.h
