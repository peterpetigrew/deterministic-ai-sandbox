// SPDX-License-Identifier: MIT
/*
 * sandbox.c — Deterministic AI Sandbox: libbpf loader.
 *
 * Responsibilities (deliberately minimal — the intelligence lives in
 * the kernel program and in the maps, not here):
 *
 *   1. load + attach the two LSM programs (via skeleton, CO-RE)
 *   2. seed policy maps (blocklist, allowlist, sandbox cgroup)
 *   3. drain the verdict ring buffer and print JSON verdict events
 *
 * Run it as root on the CI host (or your laptop), scoped to the
 * cgroup of the ephemeral agent container:
 *
 *   sudo ./sandbox --cgroup /sys/fs/cgroup/agent-sandbox
 *
 * Ctrl-C detaches and unloads everything — nothing outlives the run.
 */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* vmlinux.h is BPF-side only; the loader needs fixed-width types
 * BEFORE policy.h, whose verdict_event uses them. */
typedef unsigned char     __u8;
typedef signed int        __s32;
typedef unsigned int      __u32;
typedef unsigned long long __u64;

#include "policy.h"
#include "sandbox.skel.h"

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
        (void)sig;
        stop = 1;
}

/* Default exec blocklist — exfil tooling an autonomous agent has no
 * legitimate need for in a CI sandbox. Override with --blocklist. */
static const char *default_blocklist[] = {
        "/usr/bin/curl",  "/bin/curl",
        "/usr/bin/wget",  "/bin/wget",
        "/usr/bin/nc",    "/bin/nc",  "/usr/bin/ncat", "/bin/ncat",
        "/usr/bin/telnet",
        "/usr/bin/ssh",  "/usr/bin/scp", "/usr/bin/sftp",
        NULL
};

/* Resolve a cgroup path to the id bpf_get_current_cgroup_id() reports.
 * On cgroup v2 this is simply the kernfs node id — the inode number of
 * the cgroup directory. */
static unsigned long long cgroup_id(const char *path)
{
        struct stat st;

        if (stat(path, &st) != 0) {
                fprintf(stderr, "error: cannot stat cgroup '%s': %s\n",
                        path, strerror(errno));
                exit(1);
        }
        return (unsigned long long)st.st_ino;
}

/* Default: the cgroup this process (and the agent it will supervise)
 * lives in. Read from /proc/self/cgroup, v2 unified hierarchy. */
static void default_cgroup_path(char *out, size_t len)
{
        FILE *f = fopen("/proc/self/cgroup", "r");
        char line[512], *rel;

        if (!f) {
                snprintf(out, len, "/sys/fs/cgroup");
                return;
        }
        while (fgets(line, sizeof(line), f)) {
                if (line[0] == '0' && line[1] == ':') {
                        rel = strchr(line + 3, '\n');
                        if (rel)
                                *rel = '\0';
                        snprintf(out, len, "/sys/fs/cgroup%s",
                                 line[3] == '/' ? line + 3 : "");
                        fclose(f);
                        return;
                }
        }
        fclose(f);
        snprintf(out, len, "/sys/fs/cgroup");
}

static void print_verdict(const struct verdict_event *e)
{
        char addr[INET_ADDRSTRLEN] = "-";
        const char *hook = e->hook == HOOK_EXEC ? "exec" : "connect";

        if (e->hook == HOOK_CONNECT && e->addr != 0)
                inet_ntop(AF_INET, &e->addr, addr, sizeof(addr));

        /* comm/target are char arrays from BPF; %.Ns forces termination. */
        printf("{\"ts_ns\":%llu,\"pid\":%u,\"comm\":\"%.15s\",\"hook\":\"%s\","
               "\"target\":\"%.63s\",\"addr\":\"%s\",\"action\":\"%s\","
               "\"ret\":%d}\n",
               (unsigned long long)e->ts_ns, e->pid, e->comm, hook, e->target,
               addr, e->result == 0 ? "ALLOW" : "DENY", e->result);
}

static int on_verdict(void *ctx, void *data, size_t size)
{
        (void)ctx;
        if (size >= sizeof(struct verdict_event))
                print_verdict(data);
        return 0;
}

static void seed_map(int fd, const void *key)
{
        __u8 one = 1;

        if (bpf_map_update_elem(fd, key, &one, BPF_ANY) != 0) {
                fprintf(stderr, "error: map update failed: %s\n",
                        strerror(errno));
                exit(1);
        }
}

int main(int argc, char **argv)
{
        struct sandbox *skel;
        struct ring_buffer *rb;
        char cg_path[512] = "";
        const char *blocklist_arg = NULL;
        const char *allow_arg = NULL;
        int i, err, n_blocked = 0, n_allowed = 0;

        for (i = 1; i < argc; i++) {
                if (!strcmp(argv[i], "--cgroup") && i + 1 < argc)
                        snprintf(cg_path, sizeof(cg_path), "%s", argv[++i]);
                else if (!strcmp(argv[i], "--blocklist") && i + 1 < argc)
                        blocklist_arg = argv[++i];
                else if (!strcmp(argv[i], "--allow") && i + 1 < argc)
                        allow_arg = argv[++i];
                else {
                        fprintf(stderr,
                                "usage: %s [--cgroup PATH] [--blocklist p1,p2,...] [--allow IP,IP,...]\n"
                                "  --cgroup    cgroup to enforce (default: own cgroup)\n"
                                "  --blocklist comma-separated absolute binary paths\n"
                                "  --allow     comma-separated IPv4 egress allowlist\n"
                                "  (empty --allow == default-deny, incl. loopback)\n",
                                argv[0]);
                        return 1;
                }
        }

        if (cg_path[0] == '\0')
                default_cgroup_path(cg_path, sizeof(cg_path));

        signal(SIGINT, on_signal);
        signal(SIGTERM, on_signal);
        /* NOTE: no libbpf_set_strict_mode() here — it requires libbpf
         * >= 0.6 and is a no-op on 1.x (strict is the default there).
         * Skipping it keeps the loader compilable against Ubuntu 22.04's
         * stock libbpf 0.5; our error checks work under both semantics. */

        skel = sandbox__open();
        if (!skel) {
                fprintf(stderr, "error: failed to open BPF object "
                        "(libbpf too old? need >= 0.5; Ubuntu 24.04's 1.3 is known-good)\n");
                return 1;
        }

        err = sandbox__load(skel);
        if (err) {
                /* Most common cause: kernel without BPF LSM support, or
                 * `bpf` missing from the lsm= boot parameter. */
                fprintf(stderr, "\nerror: failed to load LSM programs (err %d)\n"
                        "check: cat /sys/kernel/security/lsm   -> must list 'bpf'\n"
                        "check: kernel cmdline lsm=bpf (see README 'Requirements')\n",
                        err);
                goto out;
        }

        /* ── seed policy ─────────────────────────────────────────── */
        {
                unsigned long long cg = cgroup_id(cg_path);

                seed_map(bpf_map__fd(skel->maps.sandbox_cgroups), &cg);
                printf("[sandbox] enforcing cgroup %s (id %llu)\n", cg_path, cg);
        }

        {
                char *dup, *tok, *save = NULL;
                const char *src = blocklist_arg;
                const char **p;

                if (!src) {
                        for (p = default_blocklist; *p; p++) {
                                unsigned long long h;

                                if (strlen(*p) >= MAX_BIN_LEN) {
                                        fprintf(stderr, "warn: '%s' too long, skipped\n", *p);
                                        continue;
                                }
                                h = fnv1a(*p);
                                seed_map(bpf_map__fd(skel->maps.exec_blocklist), &h);
                                n_blocked++;
                        }
                } else {
                        dup = strdup(src);
                        for (tok = strtok_r(dup, ",", &save); tok;
                             tok = strtok_r(NULL, ",", &save)) {
                                unsigned long long h = fnv1a(tok);

                                seed_map(bpf_map__fd(skel->maps.exec_blocklist), &h);
                                n_blocked++;
                        }
                        free(dup);
                }
                printf("[sandbox] exec_blocklist: %d entries (FNV-1a keyed)\n",
                       n_blocked);
        }

        if (allow_arg && allow_arg[0]) {
                char *dup = strdup(allow_arg), *tok, *save = NULL;

                for (tok = strtok_r(dup, ",", &save); tok;
                     tok = strtok_r(NULL, ",", &save)) {
                        __u32 ip;

                        if (inet_pton(AF_INET, tok, &ip) != 1) {
                                fprintf(stderr, "warn: bad IP '%s'\n", tok);
                                continue;
                        }
                        seed_map(bpf_map__fd(skel->maps.egress_allowlist), &ip);
                        n_allowed++;
                }
                free(dup);
        }
        printf("[sandbox] egress_allowlist: %d entries (empty = default-deny)\n",
               n_allowed);

        /* ── attach + drain ───────────────────────────────────────── */
        err = sandbox__attach(skel);
        if (err) {
                fprintf(stderr, "error: failed to attach LSM hooks (err %d)\n", err);
                goto out;
        }
        printf("[sandbox] hooks attached: bpf_lsm/bprm_check_security, "
               "bpf_lsm/socket_connect\n");
        printf("[sandbox] verdict stream (JSON lines):\n");

        rb = ring_buffer__new(bpf_map__fd(skel->maps.verdicts), on_verdict,
                              NULL, NULL);
        if (!rb) {
                fprintf(stderr, "error: failed to open ring buffer\n");
                goto out;
        }

        while (!stop) {
                err = ring_buffer__poll(rb, 100 /* ms */);
                if (err == -EINTR) {
                        err = 0;
                        break;
                }
                if (err < 0) {
                        fprintf(stderr, "error: ring_buffer__poll: %d\n", err);
                        break;
                }
        }

        printf("\n[sandbox] detaching, unloading. sandbox lifetime == run lifetime.\n");
        ring_buffer__free(rb);
out:
        sandbox__destroy(skel);
        return err ? 1 : 0;
}
