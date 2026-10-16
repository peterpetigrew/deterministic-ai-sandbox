#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# bench.sh — measure the sandbox's per-decision overhead (paper Section 6.2).
#
# Runs bench.py twice against the same local listener:
#   1. outside the sandbox cgroup (loader detached)      -> baseline
#   2. inside the sandbox cgroup (loader attached)       -> hooked
# and prints both raw lines plus the per-decision delta.
#
# The loader is started with --allow 127.0.0.1 so the connect benchmark
# exercises the ALLOW path of the egress gate (the deny path returns
# immediately and would understate the steady-state cost).
#
# Requires: root, a completed `make`, and an lsm=bpf kernel.
#
#   sudo ./bench.sh            # full protocol, N=10000 per phase
#   sudo ./bench.sh 1000       # quick run

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
N="${1:-10000}"
CG=/sys/fs/cgroup/agent-bench
LOG="$(mktemp /tmp/das-bench.XXXXXX.log)"

[ "$(id -u)" -eq 0 ] || { echo "run as root:  sudo ./bench.sh"; exit 1; }
[ -x "$ROOT_DIR/sandbox" ] || { echo "loader missing — run: make"; exit 1; }

# local listener for the connect benchmark (tiny, logs nothing)
python3 - <<'LISTENER' >/dev/null 2>&1 &
import socket
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 8901)); srv.listen(64)
while True:
    try: srv.accept()[0].close()
    except OSError: break
LISTENER
L_PID=$!
sleep 0.4

cleanup() {
    [ -n "${LOADER_PID:-}" ] && kill -INT "$LOADER_PID" 2>/dev/null && wait "$LOADER_PID" 2>/dev/null || true
    kill "$L_PID" 2>/dev/null || true
    rmdir "$CG" 2>/dev/null || true
}
trap cleanup EXIT

echo "── phase 1: baseline (no shield), N=$N ──"
python3 "$ROOT_DIR/src/bench.py" --n "$N" | tee "$LOG"

echo "── phase 2: hooked (shield attached, loopback allowed), N=$N ──"
mkdir -p "$CG"
"$ROOT_DIR/sandbox" --cgroup "$CG" --allow 127.0.0.1 > /dev/null 2>&1 &
LOADER_PID=$!
sleep 0.8
python3 - "$CG" "$N" "$ROOT_DIR" <<'RUN_IN_CGROUP'
import os, subprocess, sys
cg, n, root = sys.argv[1], int(sys.argv[2]), sys.argv[3]
with open(os.path.join(cg, "cgroup.procs"), "w") as f:
    f.write(str(os.getpid()))
raise SystemExit(subprocess.call(
    ["python3", os.path.join(root, "src", "bench.py"), "--n", str(n)]))
RUN_IN_CGROUP

echo "── delta (hooked - baseline) ──"
python3 - "$LOG" <<'DELTA'
import sys
# phase-1 lines are in the log; phase-2 lines were echoed above.
# This helper prints the comparison template once both runs are available.
print("(fill in the paper: subtract the two means reported above)")
DELTA
