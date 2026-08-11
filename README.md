# HYDRA

A cross-platform sandbox-evasion self-test suite for Windows, Linux, and
Android — the companion probe suite for CHIMERA, a hardened multi-platform
malware detonation sandbox.

VMAware, Pafish, and al-khaser verify Windows/Linux hardening well, but none
of them cover Android, and none of them share a report format or a score
across platforms. HYDRA aims for parity with (and, for Android, coverage
beyond) that combined technique catalog in one CLI: pick the sandbox platform
you're standing on, HYDRA runs *only* that platform's full check suite, and
returns a score. One suite, three agents, one JSON schema, one scoring
method — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and
[docs/CHECK_COVERAGE.md](docs/CHECK_COVERAGE.md) for exactly which
Pafish/al-khaser/VMAware technique classes are covered, extended, or (with
justification) left out.

## Quick start

```bash
pip install -e .

# Pick the platform this sandbox actually is and run its full check suite.
# Only that platform's checks run -- there is no "run everything" mode.
hydra test linux
hydra test android -s emulator-5554
hydra test windows                    # shells out to the PowerShell agent

# Same thing, writing the JSON report to disk instead of (or as well as)
# printing the human-readable summary:
hydra test linux -o linux-report.json --json

# The Windows agent can also be run directly on the guest (no Python needed):
#   pwsh -File agents\windows\Invoke-Hydra.ps1 -OutputPath windows-report.json

# Aggregate whatever reports you've collected into one unified report
hydra report linux-report.json android-report.json windows-report.json \
    -o hydra-report.html --json hydra-report.json
```

`hydra test <platform>` prints a colored terminal summary by default —
per-check results grouped by category, then a score line:

```
Score: 41/46 clean, weighted 93.2/100
```

`raw_score` is a VMAware-style `clean/applicable` count (errored/skipped
checks are excluded from the denominator); `weighted_score` additionally
weighs each detection by severity, so one `critical` detection costs far more
than several `info`-level ones. Every finding is tagged with one of four
detection categories (`environment_artifact`, `timing`,
`behavioural_interaction`, `design_specific`), a severity, and — when
detected — a suggested hardening-profile fix, so HYDRA's output can feed
straight back into CHIMERA's hardening work instead of only reporting on it.

## Layout

```
schema/                     unified report JSON Schema
common/python/hydra_common/ shared models, scoring engine, text/HTML report renderers
agents/
├── linux/     Python3 agent + a small C helper for CPUID/RDTSC (see agents/linux/README.md)
├── windows/   PowerShell 7 agent -- CIM/WMI, registry, PnP, raw SMBIOS, native CPUID intrinsics (see agents/windows/README.md)
└── android/   Python3 agent driving the target over adb, no on-device APK (see agents/android/README.md)
cli/hydra_cli/ `hydra` command: `hydra test <platform>` runs one agent locally and scores it; `hydra report` aggregates collected reports
docs/
├── ARCHITECTURE.md    the 4-category detection model and "one suite, three platforms" design
└── CHECK_COVERAGE.md  per-check mapping to Pafish/al-khaser/VMAware, and what's explicitly out of scope
```

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -q
```

The Linux agent's checks are exercised against real Linux containers, not
just mocks, during development (`docker run --rm python:3.12-slim ...`) — see
[agents/linux/README.md](agents/linux/README.md). The Windows agent is
syntax- and logic-validated by running the actual PowerShell script under
`pwsh` cross-platform; `tests/test_windows_agent_report.py` round-trips its
output through the same Python schema validator the rest of the suite uses.
