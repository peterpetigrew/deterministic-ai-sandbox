#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# static-checks.sh — what CI runs on every push and pull request.
#
# Deliberately needs NO kernel, NO libbpf, NO bpftool, NO root: both
# translation units are compiled with `gcc -fsyntax-only` against the
# minimal header stubs in ci/stubs/. This catches syntax errors, missing
# preprocessor guards, and API drift before any machine with `lsm=bpf`
# gets involved. It does NOT prove the programs load or attach —
# see ci/README.md for exactly what it does and does not establish.
#
# Usage: bash ci/static-checks.sh   (from anywhere; resolves repo root)

set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
step() { printf '\n=== %s\n' "$1"; }

step "1/5  loader syntax: gcc -fsyntax-only (vs ci/stubs)"
if gcc -std=gnu11 -Wall -Wextra -fsyntax-only -Ici/stubs -Isrc src/sandbox.c; then
    echo "ok"
else
    echo "FAIL"; fail=1
fi

step "2/5  eBPF program syntax: gcc -fsyntax-only (vs ci/stubs)"
# -Wno-unused-parameter: LSM hook signatures receive parameters the
# program is not obliged to use — inherent to the hook ABI, not a bug.
if gcc -std=gnu11 -Wall -Wextra -Wno-unused-parameter -fsyntax-only \
        -Ici/stubs -Isrc src/sandbox.bpf.c; then
    echo "ok"
else
    echo "FAIL"; fail=1
fi

step "3/5  Makefile: recipes must start with TAB, not spaces"
if grep -n '^ ' Makefile; then
    echo "FAIL: space-indented lines found (recipes need TABs)"; fail=1
else
    echo "ok"
fi

step "4/5  credential-pattern scan"
# AKIAIOSFODNN7EXAMPLE is AWS's own documentation example key (used by
# the demo agent on purpose); every serious scanner allowlists it too.
if grep -rInE '(AKIA|ASIA)[A-Z0-9]{16}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|ghp_[A-Za-z0-9]{30,}|xox[baprs]-' \
        --exclude-dir=.git . | grep -vF 'AKIAIOSFODNN7EXAMPLE'; then
    echo "FAIL: potential credential pattern found"; fail=1
else
    echo "ok"
fi

step "5/5  shell + python parse"
if bash -n demo.sh && bash -n bench.sh; then
    echo "bash ok"
else
    echo "FAIL: shell parse error"; fail=1
fi
if python3 - <<'PY'
import ast
for f in ("src/agent.py", "src/bench.py"):
    ast.parse(open(f).read(), filename=f)
print("python ok")
PY
then
    :
else
    echo "FAIL: python parse error"; fail=1
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
else
    echo "CHECKS FAILED"
    exit 1
fi
