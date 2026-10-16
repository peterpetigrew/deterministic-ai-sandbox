# Security Policy

## Reporting a vulnerability

Use GitHub's **Private Vulnerability Reporting** ("Security" tab →
"Report a vulnerability"). If that is not possible, email the
maintainer (see CITATION.cff).

Please include:

- the affected commit or release tag
- reproduction steps (host kernel version, `lsm=` boot line)
- expected vs. observed behaviour

We will acknowledge within 72 hours and keep you informed until a fix
is released.

## Scope

In scope:

- the enforcement path: `src/sandbox.bpf.c`, `src/sandbox.c`,
  `src/policy.h`
- the harness: `demo.sh`, `bench.sh`, `src/agent.py`, `src/bench.py`

Out of scope:

- the Linux kernel, libbpf, or your container runtime — report those
  upstream
- a privileged operator disabling the sandbox on their own host
- the limitations already documented in the README ("Limitations"):
  these are known PoC trade-offs, though hardening ideas are always
  welcome

## Safe harbor

Good-faith research on systems you own or are authorized to test is
welcome and appreciated.

## Disclosure

Coordinated disclosure; credit given on request.
