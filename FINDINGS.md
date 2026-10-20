# Findings — curated backlog

Evaluated findings this fork tracks and works on. The authoritative intake —
including every entry's detection/handling experience — lives in the
maintainer's central registry (private to the maintainer's workspace); this
file only mirrors the curated queue for visibility, and fixes ship here via
CI releases.

## Accepted (priority order)

1. **F01 — No authentication; binds `INADDR_ANY:52736`** (High) — auth +
   loopback-by-default (`jailed/ceserver.c:1075`).
2. **F04 — No cap on concurrent connections** (Medium) — cheap hardening
   (`jailed/ceserver.c:1094-1106`).
3. **F02 + F05 — size caps** (Medium/Low) — client-controlled `malloc` bounds
   (`ceserver.c:866-867`, `symbols.c:920`).
4. **F03 — No arm64e/PAC awareness** (Unverified) — blocked on access to a
   real arm64e device.

## Fixed

- **F09 — iOS SDK ≥26 rejects `mach_vm.h`** (High) — drop the include, declare
  `mach_vm_*` as externs. Fix `ef8d716`, CI-validated (run 39205789415),
  shipped in release `v0.1.0`.

## Scope (won't fix)

- **F06 — Single-target Makefiles** (arm64, min iOS 12): deliberate scope;
  no arm64e slice and no iOS 8 support (upstream issue #1 answered by
  documentation).
