// SPDX-License-Identifier: GPL-2.0
/*
 * sandbox.bpf.c — Deterministic AI Sandbox: eBPF LSM enforcement.
 *
 * A proof-of-concept demonstrating how to shift from probabilistic LLM
 * guardrails to deterministic OS-level security for AI agents, using
 * eBPF LSM hooks, designed for CI/CD ephemeral environments.
 *
 * Design (see docs/architecture.png):
 *
 *   container (untrusted, cgroup-scoped)
 *        │  execve() ─────────►  bpf_lsm/bprm_check_security ─┐
 *        │  connect() ─────────►  bpf_lsm/socket_connect ─────┤
 *        ▼                                                    │
 *   policy = BPF maps  ──►  ALLOW (ret 0)  or  DENY (ret -EPERM)
 *                             │
 *                             └─► ring buffer → JSON verdict events
 *
 * Key properties:
 *   1. Enforcement lives in the HOST KERNEL, below the container. A
 *      fully prompt-injected agent (OWASP LLM01) cannot reach, read,
 *      or disable it — even with root inside the container.
 *   2. LSM hooks are pre-hooks: they fire BEFORE the action happens.
 *      A denied execve never runs the binary; a denied connect()
 *      never emits a packet. This is enforcement, not detection.
 *   3. Scoping is per-cgroup: only processes inside the pinned
 *      sandbox cgroup are affected. The rest of the host (the CI
 *      runner, the collector, your shell) is untouched. When the
 *      ephemeral container dies, its cgroup dies with it.
 *   4. Policy is data, not code: blocklist/allowlist live in BPF
 *      maps, updated from userspace without reloading the program.
 *
 * Requirements: kernel >= 5.15 with CONFIG_BPF_LSM=y and `bpf` listed
 * in the `lsm=` boot parameter (see README).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "policy.h"

/* vmlinux.h carries no libc errno definitions. */
#ifndef EPERM
#define EPERM 1
#endif
#ifndef AF_INET
#define AF_INET 2 /* also in linux/socket.h via vmlinux.h, guard anyway */
#endif
#ifndef AF_INET6
#define AF_INET6 10 /* PF_INET6 on Linux */
#endif

/* vmlinux.h is a bare BTF dump of kernel types — no libc, so no NULL.
 * Defined here so the file compiles before any userspace header can
 * supply it. */
#ifndef NULL
#define NULL ((void *)0)
#endif

char LICENSE[] SEC("license") = "GPL"; /* LSM programs must be GPL */

/* struct verdict_event + enum hook_id live in policy.h (shared with
 * the loader) — a single definition of the ring-buffer wire format. */

/* ── Maps ─────────────────────────────────────────────────────────
 * All policy state lives here. The loader owns the lifecycle; the
 * verifier guarantees the program cannot mutate its own policy.
 */

/* ringbuf: verdicts → userspace */
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 64 * 1024);
} verdicts SEC(".maps");

/* key: cgroup id (kernfs node id) → value: enforce
 * Only processes in these cgroups are constrained. This is what makes
 * the sandbox per-agent-run instead of host-wide. */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 64);
        __type(key, __u64);
        __type(value, __u8);
} sandbox_cgroups SEC(".maps");

/* key: FNV-1a of absolute binary path → value: blocked
 * The exec blocklist: exfil tooling an agent should never need. */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 256);
        __type(key, __u64);
        __type(value, __u8);
} exec_blocklist SEC(".maps");

/* key: network-order IPv4 → value: allowed
 * The egress allowlist. Empty by default = default-deny. Even
 * loopback is denied: a CI agent gets artifacts via mounted volumes,
 * not via the network. (Populate it if your runner needs a mirror.) */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 64);
        __type(key, __u32);
        __type(value, __u8);
} egress_allowlist SEC(".maps");

/* ── Helpers ──────────────────────────────────────────────────── */

static __always_inline int in_sandbox(void)
{
        __u64 cg = bpf_get_current_cgroup_id();
        __u8 *enforced = bpf_map_lookup_elem(&sandbox_cgroups, &cg);

        return enforced != NULL;
}

/* Emit a verdict event. NOTE: a logging failure must never weaken
 * enforcement — if the ringbuf is full we drop the event and still
 * return the verdict. */
static __always_inline void emit_verdict(__u8 hook, const char *what,
                                         __u32 addr, __s32 ret)
{
        struct verdict_event *e;

        e = bpf_ringbuf_reserve(&verdicts, sizeof(*e), 0);
        if (!e)
                return;

        e->ts_ns = bpf_ktime_get_ns();
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->result = ret;
        e->hook = hook;
        e->addr = addr;
        bpf_get_current_comm(e->comm, sizeof(e->comm));
        if (what)
                __builtin_memcpy(e->target, what, sizeof(e->target));
        else
                e->target[0] = '\0';

        bpf_ringbuf_submit(e, 0);
}

/* ── Hook 1: execve gate ─────────────────────────────────────────
 * bprm_check_security runs after the binary is resolved but BEFORE
 * the new program executes — the ideal single choke point for every
 * subprocess an agent could ever spawn. */
SEC("lsm/bprm_check_security")
int BPF_PROG(guard_exec, struct linux_binprm *bprm, int ret)
{
        char fn[MAX_BIN_LEN] = {};
        __u64 h;
        __u8 *blocked;
        __s32 verdict;

        if (ret)                        /* a prior LSM already denied: preserve */
                return ret;

        if (!in_sandbox())              /* not our ephemeral agent: pass */
                return 0;

        /* `bprm->filename` is the path exactly as passed to execve(2).
         * The kernel does NOT perform $PATH search — the caller (shell,
         * Python subprocess) resolves it in userspace, so tool calls in
         * practice arrive as absolute paths like "/usr/bin/curl". A raw
         * execve("curl") with no slash would not match the hash; v1's
         * dev:inode pinning (README) removes the naming dependence. */
        bpf_probe_read_kernel_str(fn, sizeof(fn), bprm->filename);

        h = fnv1a(fn);
        blocked = bpf_map_lookup_elem(&exec_blocklist, &h);

        verdict = blocked ? -EPERM : 0;
        emit_verdict(HOOK_EXEC, fn, 0, verdict);
        return verdict;
}

/* ── Hook 2: egress gate (defense in depth) ──────────────────────
 * Even a payload that never execve()s (pure-Python sockets, urllib)
 * must not leave the host. socket_connect fires on every outbound
 * connect() — we hold it to an explicit allowlist, default-deny. */
SEC("lsm/socket_connect")
int BPF_PROG(guard_connect, struct socket *sock, struct sockaddr *address,
             int addrlen, int ret)
{
        struct sockaddr_in v4 = {};
        __u32 ip;

        if (ret)
                return ret;

        if (!in_sandbox())
                return 0;

        /* The v0 allowlist is IPv4-only. Families without an allowlist
         * representation must fail CLOSED, not pass silently: IPv6
         * connects are denied outright (v6 allowlisting via lpm_trie
         * is v1 work). Local IPC families (AF_UNIX, AF_NETLINK)
         * carry no exfil path off-host and stay allowed. */
        bpf_probe_read_kernel(&v4, sizeof(v4), address);
        if (v4.sin_family == AF_INET6) {
                emit_verdict(HOOK_CONNECT, NULL, 0, -EPERM);
                return -EPERM;
        }
        if (v4.sin_family != AF_INET)
                return 0;                /* AF_UNIX & friends: local IPC */

        ip = v4.sin_addr.s_addr;        /* network order, matches map keys */

        if (bpf_map_lookup_elem(&egress_allowlist, &ip))
                return 0;               /* explicitly allowed */

        emit_verdict(HOOK_CONNECT, NULL, ip, -EPERM);
        return -EPERM;
}
