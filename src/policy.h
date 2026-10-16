/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * policy.h — shared policy constants for the Deterministic AI Sandbox.
 *
 * Included by BOTH the eBPF program (sandbox.bpf.c) and the userspace
 * loader (sandbox.c), so the blocklist hashing has a single source of
 * truth: the kernel and the loader can never disagree about what a
 * policy entry means.
 */
#ifndef POLICY_H
#define POLICY_H

/* Max length of a binary pathname we hash. Longer paths are truncated
 * before hashing — keep blocklist entries shorter than this. */
#define MAX_BIN_LEN 64

/* One verdict event per decision — emitted through the ring buffer.
 * Shared between the BPF program and the loader so the wire format
 * has a single definition. Needs __u8/__s32/__u32/__u64 (from
 * vmlinux.h in the BPF file, from typedefs in the loader). */
enum hook_id {
        HOOK_EXEC    = 1,
        HOOK_CONNECT = 2,
};

struct verdict_event {
        __u64 ts_ns;
        __u32 pid;
        __s32 result;        /* 0 or -EPERM */
        __u8  hook;          /* enum hook_id */
        __u8  pad[3];
        __u32 addr;          /* HOOK_CONNECT only: network-order IPv4 */
        char comm[16];       /* caller comm (the agent) */
        char target[64];    /* HOOK_EXEC only: binary pathname */
};

/* 64-bit FNV-1a. Chosen because it is trivial to implement inside a
 * BPF program with a bounded loop, and good enough for a PoC blocklist
 * keyed by absolute path. (See README: v1 replaces name hashing with
 * device+inode pinning to defeat path-swap attacks.) */
#define FNV_OFFSET 0xcbf29ce484222325ULL
#define FNV_PRIME  0x100000001b3ULL

static inline unsigned long long fnv1a(const char *s)
{
        unsigned long long h = FNV_OFFSET;
        int i;

        for (i = 0; i < MAX_BIN_LEN && s[i]; i++) {
                h ^= (unsigned long long)(unsigned char)s[i];
                h *= FNV_PRIME;
        }
        return h;
}

#endif /* POLICY_H */
