/* SPDX-License-Identifier: MIT */
/*
 * ci/stubs/bpf/bpf.h — syntax-check stand-in for libbpf's bpf/bpf.h
 * (the low-level syscall wrappers the loader uses).
 */
#ifndef CI_STUB_BPF_H
#define CI_STUB_BPF_H

#include <stdint.h>

#define BPF_ANY 0

int bpf_map_update_elem(int fd, const void *key, const void *value,
                        uint64_t flags);

#endif /* CI_STUB_BPF_H */
