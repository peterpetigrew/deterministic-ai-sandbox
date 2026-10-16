#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""bench.py — per-decision overhead measurement for the Deterministic AI Sandbox.

Measures the cost of execve() and connect() with and without the eBPF LSM
shield attached (bench.sh runs this script under both conditions and prints
the delta). Protocol matches the paper: N=10,000 ops per phase, reporting
mean and standard deviation in microseconds.

Usage:
  python3 bench.py --n 10000          # run both benchmarks
  python3 bench.py --n 10000 --only execve
  python3 bench.py --n 10000 --only connect

Exit code 0 = completed; any failure exits non-zero with a message.
"""

import argparse
import math
import os
import socket
import subprocess
import sys
import time

LISTEN = ("127.0.0.1", 8901)


def mean_sd(xs):
    m = sum(xs) / len(xs)
    var = sum((x - m) ** 2 for x in xs) / (len(xs) - 1)
    return m, math.sqrt(var)


def bench_execve(n):
    """Spawn /usr/bin/true n times via posix_spawn (minimal userspace
    overhead so the measured time is dominated by the kernel path)."""
    if not os.path.exists("/usr/bin/true"):
        sys.stderr.write("bench: /usr/bin/true not found\n")
        sys.exit(1)
    t = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        pid = os.posix_spawn("/usr/bin/true", ["/usr/bin/true"], os.environ)
        os.waitpid(pid, 0)
        t.append((time.perf_counter_ns() - t0) / 1000.0)
    return mean_sd(t)


def bench_connect(n):
    """connect() to a loopback listener n times; the listener must be
    reachable (bench.sh starts it and the loader is run with
    --allow 127.0.0.1 so the allow path is exercised, not the deny path)."""
    t = []
    for _ in range(n):
        s = socket.socket()
        t0 = time.perf_counter_ns()
        try:
            s.connect(LISTEN)
        except OSError as e:
            sys.stderr.write(f"bench: connect failed: {e}\n")
            sys.exit(1)
        finally:
            t.append((time.perf_counter_ns() - t0) / 1000.0)
            s.close()
    return mean_sd(t)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=10000)
    ap.add_argument("--only", choices=["execve", "connect"], default=None)
    args = ap.parse_args()

    results = {}
    if args.only in (None, "execve"):
        m, sd = bench_execve(args.n)
        results["execve"] = (m, sd)
        print(f"execve_us {m:.1f} {sd:.1f}")
    if args.only in (None, "connect"):
        m, sd = bench_connect(args.n)
        results["connect"] = (m, sd)
        print(f"connect_us {m:.1f} {sd:.1f}")
    if not results:
        ap.error("nothing to do")


if __name__ == "__main__":
    main()
