# Perdedor v2 — design and contributor rules

This document is the contract every part of Perdedor v2 follows. When in doubt,
this file wins over older documents.

## Goals

1. **Coverage**: implement every technique class that al-khaser, Pafish, VMAware,
   InviZzzible, the Check Point Evasion Encyclopedia, Unprotect, the Android
   anti-emulator/RASP projects and the iOS security suites test — on Windows,
   Linux, Android, macOS and iOS — and say explicitly what is not implemented
   and why.
2. **Meaning**: every check is tied to a technique in `catalog/techniques.json`,
   with ATT&CK/MBC ids, how decisive it is, how widely malware uses it, who uses
   it (with sources) and how to fix it.
3. **Scores that mean something**: per-class, per-category and overall scores
   that cannot be inflated by adding trivial checks, that drop sharply for
   tells real malware uses, and that state their own confidence and coverage
   (see `docs/SCORING.md`).
4. **Fix guidance**: a prioritised hardening plan (impact ÷ effort).
5. **Operator control**: every agent supports the same selection flags.
6. **Stay current**: `perdedor upstream check` reports new upstream releases and
   techniques not yet covered.

## Layout

```
catalog/
  classes.json          classes -> categories; severity weights; prevalence tiers; effort scale; fix layers
  techniques.json       cross-platform technique vocabulary (key = <class>.<name>)
  checks/<area>.json    concrete checks (one file per platform area; never edit another area's file)
  threats.json          malware families / tools / actors -> technique keys, with sources
  upstreams.json        upstream projects tracked by the watcher
  inventory/<tool>.json upstream technique inventories at a pinned revision (coverage basis)
native/                 THE agent for Windows and Linux: C++17, statically linked, no runtime needed
  src/core/             registry, selection, watchdog, JSON report, CLI (do not change without need)
  src/common/           checks compiled into both builds (x86 CPU, timing, instruction probes)
  src/windows/          Windows-only checks (+ winutil helpers); build: perdedor-windows-x64.exe / -x86.exe
  src/linux/            Linux-only checks; build: perdedor-linux-x86_64 (static, also runs on Android-x86)
agents/android/         host-side adb driver (Python): nothing is installed on the device; may push the
                        static native binary to x86_64 devices for CPU/timing probes
agents/macos/, agents/ios/  host-side ssh (or local) drivers (Python)
agents/windows/, agents/linux/  v1 PowerShell / Python agents, frozen as fallbacks (no new checks)
common/python/perdedor_common/  models, registry, catalog, scoring, planner, renderers
cli/perdedor_cli/       `perdedor` command
research/               scoring lab and research datasets
docs/                   documentation; docs/notes/<area>.md = per-area implementation notes
```

## Check ids, techniques and classes

- Id: `<prefix>.<category-short>.<name>` with prefix `win|linux|android|macos|ios`,
  category-short `env|timing|behavioural|design` (keeps v1 ids stable), name
  `[a-z0-9_]+`. Ids never change once released.
- Every check implements exactly one technique key from `catalog/techniques.json`.
  The check's class is the technique's class (`cpu.brand_string` -> `cpu`).
- If no key fits, add the proposal to `research/proposed-techniques.json`
  (`{"key","class","title","attack","mbc","discrimination","tier","platforms","why"}`)
  and use the closest existing key meanwhile. Do not edit `techniques.json` directly.

## Catalog entry (catalog/checks/<area>.json)

```json
{
  "id": "win.env.cpuid_hypervisor_leaf_range",
  "technique": "cpu.hypervisor_leaf_range",
  "status": "implemented",            // implemented | planned | not_feasible
  "reason": null,                     // required unless implemented
  "severity": "high",                 // info|low|medium|high|critical (what the agent emits)
  "cost": "fast",                     // fast <1 s, medium <10 s, slow <120 s
  "network": false,
  "requires": ["native-helper"],      // admin|root|pwsh7|native-helper|adb|ssh|interactive
  "equivalents": {"vmaware": ["HYPERVISOR_STR"], "al-khaser": ["..."], "pafish": ["..."]},
  "fix": {
    "layer": "analysis-engine",       // classes.json fix_layers
    "effort": 3,                      // classes.json effort_scale (1..5)
    "how": "Generic fix, concrete and actionable.",
    "chimera": "What it means on CHIMERA (Xen 4.19 + DRAKVUF): plugin flags, xl.cfg, hvmloader, image changes."
  },
  "references": ["https://..."]
}
```

`equivalents` keys: `al-khaser`, `pafish`, `vmaware`, `invizzzible`,
`checkpoint-evasions`, `unprotect`, `anti-emulator`, `freerasp`, `rootbeer`,
`iossecuritysuite`, `systemd-detect-virt`, `virt-what`, `capa`, `cape`, `other`. Values
are the upstream's own function or technique names, spelt exactly as in its source (for capa and
CAPE, the rule or signature path with the `capa/` or `cape/` prefix the inventory gives it).

Upstream items that describe the sample rather than the environment (packers, obfuscators,
anti-forensic actions, attacks on monitoring) are listed in that source's `out_of_scope` entry in
`catalog/upstreams.json`, as a glob `pattern` and a `reason`. They count as not feasible, show their
reason in `docs/CHECK_COVERAGE.md`, and never hide an item that a check does cover.

Techniques an upstream tool tests that cannot be done safely or at all from user
mode get a `not_feasible` entry with the reason (for example "needs a kernel
driver"). That is how coverage stays honest.

## Why native

Malware probes the machine natively; a check suite that needs PowerShell 7 or
Python on the target tests a machine that does not look like a victim, misses
low-level tells (RDTSC, exceptions, raw tables, ntdll) and cannot run on minimal
servers, appliances or IoT images. The native agent is one static binary per
target with no runtime dependencies (Windows 7+ x86/x64, any x86_64 Linux).

## Writing a check

Native (C++17, `native/src/<common|windows|linux>/<area>_*.cpp`):

```cpp
#include "../core/perdedor.hpp"
namespace perdedor { namespace {
std::vector<Finding> clock_source(Context& ctx) {
    long iterations = ctx.param_int("timing.iterations", 2000);   // operator-tunable
    ...
    return {bool_check("timing.clock_source", "Clock source", "What and why.", Severity::High,
                       is_virtual, evidence_json, "How to fix.")};
}
}  // namespace
PERDEDOR_REGISTER(clock_source, "timing.clock_source", "fast", false, "timing.clock_source");
}  // namespace perdedor
```

Ids are given without the platform prefix (`env.x` becomes `win.env.x` or
`linux.env.x`). Files are picked up by the Makefile automatically. Probes that
can fault (privileged/undefined instructions, I/O ports, debug tricks) must use
the guarded-execution helper in `src/common/guard.hpp`. Never let an exception
or a fault escape a check; the runner's watchdog only covers hangs.

Python drivers (`agents/<platform>/perdedor_<platform>/checks/<module>.py`):

```python
from perdedor_common import FindingFactory
from perdedor_common.models import Category, Platform, Severity
from perdedor_common.registry import RunContext, spec

_f = FindingFactory(category=Category.ENVIRONMENT_ARTIFACT, platform=Platform.LINUX)

def check_clock_source(ctx: RunContext):
    ...
    return _f.bool_check("linux.timing.clock_source", "Clock source", "...", Severity.HIGH,
                         is_detected=..., evidence=..., remediation="...")

CHECKS = [spec("linux.timing.clock_source", check_clock_source, "timing.clock_source")]
```

Modules are discovered automatically. The finding's category must equal the
category of the technique's class (`perdedor_common.registry.CLASS_CATEGORY`).

PowerShell (`agents/windows/probes/<Area>.ps1`): write `function Test-Xyz { ... }`
returning `New-PerdedorBoolFinding`/`New-PerdedorFinding`, then
`Register-PerdedorCheck -Ids 'win.env.xyz' -Technique 'cpu.brand_string' [-Cost medium] [-Network] -Run { Test-Xyz }`.
Read operator parameters with `Get-PerdedorParam -Key 'timing.iterations' -Default 2000`.

## Status, evidence and confidence

- `detected` = an evasion tell is present (bad for the sandbox). `clean` = the
  probe ran and found no tell. `skipped` = not applicable here (wrong OS,
  feature absent, not selected-for-reason) with `error_detail`. `error` = the
  probe should have worked and failed, with `error_detail`.
- Never report `clean` when the probe could not look. Unknown is not clean.
- `evidence` holds the raw values an analyst needs to verify the verdict.
- `confidence` (0..1) is optional; set it for statistical checks (timing) and
  heuristics with known false-positive rates.
- `measurement` (optional object) holds the numbers behind a threshold.
- Every threshold is a named constant with a comment citing where it comes from,
  and can be overridden with a parameter where that makes sense.

## Safety rules for probes (non-negotiable)

- Read-only. No persistence, no services, no drivers, no registry/file writes
  outside a temp directory the check deletes again.
- Must not crash, hang or destabilise the guest. Exception-raising instruction
  probes run behind an exception handler, with a hard timeout. (VMAware's
  EIP_OVERFLOW technique crashes Xen guests; never replicate it.)
- Bounded runtime per the `cost` class. Interactive waits only under the `deep`
  profile or when explicitly selected.
- Network probes are marked `network=True`/`-Network`, use short timeouts, and
  only contact: random non-existent domain names (DNS sinkhole / simulated
  internet tests), the cloud metadata address 169.254.169.254, and hosts the
  operator passes as parameters. Never contact real third-party services.
- No secrets, no personal data in evidence beyond what is needed (counts rather
  than contents for history, contacts, messages).
- Standard library only inside agents (Python) / built-in .NET and Win32 (PowerShell).

## Tests

- Python: `pytest tests/`. Each new module gets `tests/test_<area>.py` with
  fixtures or fakes (fake filesystem roots, fake adb/ssh transports). No test may
  need root, a VM or network.
- PowerShell: the agent must run under `pwsh` on Linux without errors in the
  non-Windows paths (they return `skipped`). Python tests may drive `pwsh`
  (`tests/test_windows_*.py`); skip them when `pwsh` is missing.
- `tests/test_catalog.py` must stay green: every emitted id is catalogued with the
  same technique, every implemented entry is emitted by an agent.
- Formatting: black/isort/ruff, line length 110.

## Writing style

Plain, specific technical English. Cite sources with URLs. Never mention AI
tools or assistants in code, comments, docs or commit messages.
