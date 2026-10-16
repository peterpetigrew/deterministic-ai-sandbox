#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# demo.sh — Deterministic AI Sandbox: end-to-end demo.
#
# Runs the same compromised agent twice against the same "attacker":
#
#   PHASE A  baseline  — no shield: both exfiltration paths succeed
#   PHASE B  shielded  — eBPF LSM hooks attached: both are denied by
#                        the kernel, and every decision is a verdict
#
# The "attacker" is a local python http.server on 127.0.0.1:8000 that
# stands in for malicious-site.com, so the demo needs no internet and
# is fully reproducible. It keeps serving across BOTH phases, so in
# phase B the difference you see is purely the kernel's decision.
#
# Requires: root (cgroup mkdir + BPF), python3, curl, make sandbox done.

set -u
set -o pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_CG=/sys/fs/cgroup/agent-sandbox-demo
COLLECTOR_LOG="$(mktemp /tmp/das-collector.XXXXXX.log)"

[ "$(id -u)" -eq 0 ] || { echo "run as root:  sudo ./demo.sh"; exit 1; }
[ -x "$ROOT_DIR/sandbox" ] || { echo "loader missing — run: make"; exit 1; }

banner() {
    echo
    echo "════════════════════════════════════════════════════════════════"
    echo "  $1"
    echo "════════════════════════════════════════════════════════════════"
}

cleanup() {
    [ -n "${LOADER_PID:-}" ] && kill -INT "$LOADER_PID" 2>/dev/null && wait "${LOADER_PID}" 2>/dev/null
    [ -n "${COLLECTOR_PID:-}" ] && kill "$COLLECTOR_PID" 2>/dev/null
    [ -d "$SANDBOX_CG" ] && rmdir "$SANDBOX_CG" 2>/dev/null
}
trap cleanup EXIT

# ── the "attacker": a collector that will happily take your token ──
# (a 5-line HTTP server that always says 200 and logs every hit, so
#  the demo needs no internet and the transcript is unambiguous)
python3 - <<'COLLECTOR' >"$COLLECTOR_LOG" 2>&1 &
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"COLLECTOR-HIT {self.path}", flush=True)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):  # quiet the default access log
        pass
HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
COLLECTOR
COLLECTOR_PID=$!
sleep 0.6

# ── PHASE A — baseline: a plain container, no shield ──────────────
banner "PHASE A — BASELINE (no eBPF shield)"
python3 "$ROOT_DIR/src/agent.py" --mode baseline
AGENT_RC_A=$?
HITS_A=$(grep -c 'COLLECTOR-HIT' "$COLLECTOR_LOG" || true)
echo
echo "── collector log (what the attacker received): ──"
grep -o 'COLLECTOR-HIT /exfil?token=[^ ]*' "$COLLECTOR_LOG" | sort | uniq -c || echo "(nothing)"
echo "phase A collector hits: $HITS_A"

# ── PHASE B — shielded: attach the eBPF LSM hooks ──────────────────
banner "PHASE B — SHIELDED (eBPF LSM hooks attached)"
mkdir -p "$SANDBOX_CG"

"$ROOT_DIR/sandbox" --cgroup "$SANDBOX_CG" &
LOADER_PID=$!
sleep 0.8

python3 "$ROOT_DIR/src/agent.py" --mode shielded --join-cgroup "$SANDBOX_CG"
AGENT_RC=$?

echo
echo "── collector hits: phase A vs phase B ──"
HITS_TOTAL=$(grep -c 'COLLECTOR-HIT' "$COLLECTOR_LOG" || true)
HITS_B=$(( HITS_TOTAL - HITS_A ))
echo "phase A: $HITS_A, phase B: $HITS_B (expected 0 under the shield)."
echo "phase B kernel verdicts: printed above as JSON lines by the loader."

kill -INT "$LOADER_PID" 2>/dev/null; wait "$LOADER_PID" 2>/dev/null
LOADER_PID=""
rmdir "$SANDBOX_CG" 2>/dev/null

banner "VERDICT"
if [ "$AGENT_RC" -eq 0 ]; then
    echo "shielded run exit code 0 — the kernel held the line."
else
    echo "shielded run exit code $AGENT_RC — see output above."
fi
echo "replay any time:  sudo ./demo.sh"
