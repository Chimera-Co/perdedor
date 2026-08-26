# PERDEDOR Architecture

PERDEDOR is the cross-platform sandbox-evasion self-test suite for the CHIMERA
platform. It exists to close one specific gap identified during CHIMERA's
build: VMAware, Pafish, and al-khaser verify Windows/Linux hardening, but
none of them cover Android, and none of them share a report format. PERDEDOR
is one suite, three agents, one schema, one scoring method -- and aims for
parity with (and, on Android, coverage beyond) that combined technique
catalog; see [CHECK_COVERAGE.md](CHECK_COVERAGE.md) for the full mapping.

The user-facing shape of that is deliberately narrow: `perdedor test <platform>`
takes exactly one of `windows`/`linux`/`android`, runs *only* that
platform's full check suite against the current host (or, for Android, the
`adb`-attached device), and returns a score. There is no mode that runs
multiple platforms' checks in one invocation -- the tool never guesses which
sandbox it's running on.

## Design principles (from CHIMERA Ch.8)

1. **One suite, three platforms.** Every agent emits the same JSON shape
   (`schema/perdedor-report.schema.json`) so results are directly comparable
   across Windows, Linux, and Android sandboxes.
2. **Check categories, not just individual techniques.** Every finding is
   tagged with one of the four detection categories from CHIMERA Ch.3:
   - `environment_artifact` — hardware/firmware/driver signatures
   - `timing` — RDTSC-class and uptime-based timing discrepancies
   - `behavioural_interaction` — absence of human wear-and-tear
   - `design_specific` — quirks of a particular analysis platform/build
3. **Feed hardening, don't just report on it.** Every finding that can be
   detected carries a `remediation` string describing the hardening-profile
   change that would close it, so CHIMERA's hardening profiles can consume
   PERDEDOR output directly instead of routing through manual analyst judgement.

## Components

```
perdedor/
├── schema/                     unified report JSON Schema
├── common/python/perdedor_common/ shared models, scoring engine, report renderer
├── agents/
│   ├── linux/                  Python3 agent + small C helper for CPUID/RDTSC
│   ├── windows/                PowerShell 7 agent (WMI/CIM, registry, PnP, raw SMBIOS, native CPUID intrinsics)
│   └── android/                Python3 agent driving the target over adb
└── cli/perdedor_cli/              `perdedor test <platform>`: run one agent locally and score it
                                 `perdedor report`: aggregate JSON already collected from remote guests
```

## Why agents run *inside* the guest, unlike CHIMERA's detonation model

CHIMERA's malware detonation sandboxes are deliberately agentless — no
tooling exists inside the guest, because modern malware refuses to run in
the presence of analysis tools. PERDEDOR is different: it is an *analyst-run
self-test*, executed deliberately against a golden image before it is ever
used for detonation, in the same way Pafish and al-khaser are literally run
as executables inside the guest. There is no conflict — PERDEDOR never runs
during a real detonation, only during sandbox verification.

## Aggregation workflow

1. Copy the appropriate agent into the golden image (or run it over adb for
   Android) and execute it. Each agent writes one JSON file conforming to
   the schema.
2. Pull the JSON files back to the analyst host.
3. Run `perdedor report <file1.json> <file2.json> ...` to render a single
   unified HTML/JSON report scored consistently across all platforms
   tested.

## Scoring

Two scores are reported side by side, deliberately mirroring the CHIMERA
KVM hardening report's own finding that not all detections are equally
significant:

- **raw_score** — `clean/applicable`, the VMAware-style headline number
  (`errored`/`skipped` findings are excluded from the denominator, since
  neither one is a pass/fail result on this host).
- **weighted_score** — a 0-100 score where each `detected` finding is
  discounted by its severity weight (`info`=0.05 ... `critical`=1.0), so a
  sandbox with one critical RDTSC leak scores worse than one with ten
  low-severity sensor-telemetry gaps, even though the raw count says
  otherwise.
