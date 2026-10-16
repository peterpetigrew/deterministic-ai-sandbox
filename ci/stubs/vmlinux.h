/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * ci/stubs/vmlinux.h — syntax-check stand-in for the BTF-generated
 * vmlinux.h (which `make vmlinux` produces from the running kernel).
 *
 * Contains ONLY the fixed-width types and kernel structures that
 * src/sandbox.bpf.c actually references — just enough for
 * `gcc -fsyntax-only` to parse the eBPF program in CI, where no
 * kernel BTF, bpftool, or clang is available.
 *
 * This file is never used in a real build: the Makefile generates the
 * real src/vmlinux.h, and clang compiles against that.
 */
#ifndef CI_STUB_VMLINUX_H
#define CI_STUB_VMLINUX_H

typedef unsigned char       __u8;
typedef signed char         __s8;
typedef unsigned short      __u16;
typedef signed short        __s16;
typedef unsigned int        __u32;
typedef signed int         __s32;
typedef unsigned long long  __u64;
typedef signed long long    __s64;

/* enum bpf_map_type (real value numbers, as in include/uapi/linux/bpf.h) */
enum bpf_map_type {
        BPF_MAP_TYPE_HASH    = 1,
        BPF_MAP_TYPE_RINGBUF = 27,
};

/* The one field of struct linux_binprm the exec gate reads. */
struct linux_binprm {
        const char *filename;
};

/* Sockets: only the connect gate's view of them. */
struct socket;
struct sockaddr;

typedef unsigned short __kernel_sa_family_t;

struct in_addr {
        __u32 s_addr;
};

struct sockaddr_in {
        __kernel_sa_family_t sin_family;
        __u16                sin_port;
        struct in_addr       sin_addr;
        unsigned char        __pad[8];
};

#endif /* CI_STUB_VMLINUX_H */
