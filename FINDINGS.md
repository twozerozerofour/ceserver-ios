# Findings

Living queue of weaknesses and improvement opportunities for this fork of
`0xiuks/ceserver-ios`.

## Rules

1. A consuming project ONLY adds a row here (with evidence) and moves on.
   Fixes never happen inline in the consuming project.
2. This fork is where findings are prioritized, fixed, and released.
3. Fixes ship as CI releases (macOS runners + Theos) — never as ad-hoc
   binaries.

| ID | Date | Area | Finding | Evidence | Severity | Status |
|----|------|------|---------|----------|----------|--------|
| F01 | 2026-10-18 | security | No authentication on the CE TCP protocol; the server binds `INADDR_ANY:52736`, so any host on the LAN can read/write the host app's memory. Jailed mode limits blast radius to the host process, but WiFi use (as documented in the upstream README) is open to the network. | `jailed/ceserver.c:1075` (`INADDR_ANY`), `DispatchCommand` has no auth path; `CMD_WRITEPROCESSMEMORY` at `ceserver.c:856-871` | High | Open |
| F02 | 2026-10-18 | robustness | Unbounded client-controlled allocation: `c.size` (uint32 from the wire) drives `malloc` with no cap. A discard path exists when malloc fails, but a 4 GiB request still stresses the host app. Same class in symbols parsing. | `jailed/ceserver.c:866-867` | Medium | Open |
| F03 | 2026-10-18 | compat | No arm64e/PAC awareness anywhere (zero `ptrauth` references). Breakpoints, stepping and instruction patching on arm64e devices (iPhone XS and later) are unverified and likely unreliable. | grep over `ceserver-ios/*` returns no ptrauth/arm64e usage; `Makefile` has `ARCHS := arm64` only | Medium | Unverified — needs real arm64e device test |
| F04 | 2026-10-18 | robustness | No cap on concurrent connections: one detached thread per `accept` with no limit → thread/stack exhaustion can kill the host app (self-DoS of the analysis target). | `jailed/ceserver.c:1094-1106` | Medium | Open |
| F05 | 2026-10-18 | robustness | `symbols.c` trusts the on-disk Mach-O header: `malloc(info->sizeofcmds)` without a sanity cap when parsing a hostile target binary. | `jailed/symbols.c:920` | Low | Open |
| F06 | 2026-10-18 | build | Single-target Makefiles (`arm64`, min iOS 12). Upstream issue #1 (iOS 8, "bad CPU type") fails by design; no arm64e slice. | `Makefile` (`TARGET := iphone:clang:latest:12.0`, `ARCHS := arm64`); issue #1 | Info | Won't fix — documented scope |
| F07 | 2026-10-18 | positive | `recvall`/`sendall` are solid: `MSG_WAITALL`, `EINTR` retry, correct 0/-1 handling. Baseline I/O is trustworthy; protocol robustness issues are at the command layer, not the transport. | `jailed/ceserver.c:41-89` | Info | n/a |
| F08 | 2026-10-18 | architecture | Jailed mode operates on the host process only (`mach_task_self()`), not arbitrary PIDs. This sandbox scope is a feature for target analysis and should stay documented so consuming agents do not expect cross-process attach in jailed mode. | `jailed/api.c:945-958` | Info | n/a |
| F09 | 2026-10-19 | build | iOS SDK ≥26 hard-errors on `#include <mach/mach_vm.h>` ("mach_vm.h unsupported"); the snapshot only survived because it was built against an older SDK. Fix: drop the include and declare the used `mach_vm_*` functions as externs (the pattern the file already used for two of them). | CI run 39204965214 on iPhoneOS26.5 SDK; `api.c`/`debugger.c` in both targets | High | **Fixed** (CI-validated) |

## Priority order (current)

1. F01 — auth + loopback-by-default (security, open WiFi is the documented path)
2. F04 — connection cap (cheap hardening)
3. F02 + F05 — size caps (cheap hardening)
4. F03 — arm64e device validation (blocked on hardware access)

F09 was fixed in the same week it was found — the loop works: CI builds are
the gate, releases are the delivery.
