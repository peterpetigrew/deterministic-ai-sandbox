/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * ci/stubs/bpf/bpf_helpers.h — syntax-check stand-in for libbpf's
 * bpf/bpf_helpers.h. Defines the map-declaration macros and declares
 * the BPF helper functions src/sandbox.bpf.c calls; nothing more.
 */
#ifndef CI_STUB_BPF_HELPERS_H
#define CI_STUB_BPF_HELPERS_H

/* Map declaration helpers (as in libbpf's bpf_helpers.h). */
#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* BPF helper declarations used by the program (signatures as in
 * include/uapi/linux/bpf.h; the verifier checks the real contracts). */
__u64 bpf_get_current_cgroup_id(void);
__u64 bpf_get_current_pid_tgid(void);
__u64 bpf_ktime_get_ns(void);
void *bpf_map_lookup_elem(const void *map, const void *key);
void *bpf_ringbuf_reserve(const void *ringbuf, __u64 size, __u64 flags);
void bpf_ringbuf_submit(void *data, __u64 flags);
void bpf_get_current_comm(void *buf, __u32 size);
long bpf_probe_read_kernel(void *dst, __u32 size, const void *unsafe_ptr);
long bpf_probe_read_kernel_str(void *dst, __u32 size, const void *unsafe_ptr);

#endif /* CI_STUB_BPF_HELPERS_H */
