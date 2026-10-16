/* SPDX-License-Identifier: MIT */
/*
 * ci/stubs/bpf/libbpf.h — syntax-check stand-in for libbpf's
 * bpf/libbpf.h, with only the API surface src/sandbox.c uses.
 * Uses stdint types so it can be included before the loader's own
 * fixed-width typedefs.
 */
#ifndef CI_STUB_LIBBPF_H
#define CI_STUB_LIBBPF_H

#include <stddef.h>

struct bpf_map;
struct ring_buffer;

typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);

int  bpf_map__fd(const struct bpf_map *map);
struct ring_buffer *ring_buffer__new(int map_fd,
                                     ring_buffer_sample_fn sample_cb,
                                     void *ctx, void *opts);
int  ring_buffer__poll(struct ring_buffer *rb, int timeout_ms);
void ring_buffer__free(struct ring_buffer *rb);

#endif /* CI_STUB_LIBBPF_H */
