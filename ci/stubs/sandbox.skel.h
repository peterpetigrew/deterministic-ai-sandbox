/* SPDX-License-Identifier: MIT */
/*
 * ci/stubs/sandbox.skel.h — syntax-check stand-in for the skeleton
 * that `bpftool gen skeleton` generates (src/sandbox.skel.h). The
 * generated one exists only after a real build; this one carries the
 * same struct/function names so the loader parses in CI.
 */
#ifndef CI_STUB_SANDBOX_SKEL_H
#define CI_STUB_SANDBOX_SKEL_H

#include <bpf/libbpf.h>

struct sandbox {
        struct {
                struct bpf_map *sandbox_cgroups;
                struct bpf_map *exec_blocklist;
                struct bpf_map *egress_allowlist;
                struct bpf_map *verdicts;
        } maps;
};

struct sandbox *sandbox__open(void);
int sandbox__load(struct sandbox *skel);
int sandbox__attach(struct sandbox *skel);
void sandbox__destroy(struct sandbox *skel);

#endif /* CI_STUB_SANDBOX_SKEL_H */
