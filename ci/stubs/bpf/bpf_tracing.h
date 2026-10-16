/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * ci/stubs/bpf/bpf_tracing.h — syntax-check stand-in for libbpf's
 * bpf/bpf_tracing.h. The real macro builds a CO-RE-compatible
 * trampoline; for syntax checking it suffices that BPF_PROG(name, args)
 * expands to a plain function definition head.
 */
#ifndef CI_STUB_BPF_TRACING_H
#define CI_STUB_BPF_TRACING_H

#define BPF_PROG(name, ...) name(__VA_ARGS__)

#endif /* CI_STUB_BPF_TRACING_H */
