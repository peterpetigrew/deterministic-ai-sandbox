# CI: static checks

`static-checks.sh` runs on every push and pull request
(`.github/workflows/static-checks.yml`) and needs no kernel, no libbpf,
no bpftool, and no root. It answers one question: *do the sources
still parse as the C we think they are?*

## What it checks

| Check | Catches |
|---|---|
| `gcc -fsyntax-only` on `src/sandbox.c` (loader) against `ci/stubs/` | syntax errors, missing preprocessor guards, API drift |
| `gcc -fsyntax-only` on `src/sandbox.bpf.c` (BPF side) against `ci/stubs/` | the same, for the program that runs in the kernel |
| Makefile recipe indentation | space-instead-of-TAB regressions (make silently does nothing) |
| credential-pattern scan | accidentally committed keys / tokens |
| `bash -n` + Python `ast.parse` | broken demo & benchmark scripts |

## What it deliberately does NOT prove

- That the BPF program **loads**. Loading needs a kernel with
  `CONFIG_BPF_LSM=y` and `bpf` in the `lsm=` boot parameter — a real
  `make` followed by `sudo ./demo.sh` on such a host remains the
  source of truth.
- That the program **verifies**. The BPF verifier's checks (bounds,
  map access, helper contracts) only run at load time, against the
  real `vmlinux.h` types.
- Any runtime behaviour.

## The stubs (`ci/stubs/`)

Minimal stand-ins for `vmlinux.h`, `bpf/bpf_helpers.h`,
`bpf/bpf_tracing.h`, libbpf, and the generated skeleton — just enough
for `gcc -fsyntax-only` to parse both translation units. They contain
nothing but the declarations the sources use.

Note: `src/sandbox.bpf.c` includes `"vmlinux.h"` (quoted), so if you
have built locally, your real generated `src/vmlinux.h` shadows the
stub and the syntax check then runs against your kernel's types
instead. `make clean` removes it.
