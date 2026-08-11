# HYDRA Build Guide — Volume 2: The Complete Source, Line by Line
### Every file in the HYDRA repository, explained well enough to rebuild the whole project from an empty folder

---

## How to use this document

This is Volume 2 of a two-volume set. Volume 1
(`LEARNING_GUIDE_VOL1_FOUNDATIONS.md`) taught every concept — programming
fundamentals, Python, PowerShell, C, computer architecture, virtualization,
malware analysis, and everything else — that this document assumes you
already know. If a term here feels unfamiliar, it is defined in Volume 1's
glossary (its Chapter 21); this volume does not re-explain general
concepts, only HYDRA's specific application of them.

**How this document is organized:** it walks through the HYDRA repository
in the order a new contributor would naturally explore it — starting from
the schema (the one thing every other file agrees on), through the shared
Python library, then each of the three platform agents in turn, then the
CLI that ties them together, then the tests, and finally a step-by-step
guide to rebuilding the entire project yourself, from nothing, in the
correct dependency order.

**How "line by line" works in practice:** for files under roughly 40
lines, this document walks through literally every line. For longer files
(especially the check modules, which repeat the same pattern many times
over), this document explains the pattern in complete, exhaustive detail
the *first* time it appears, and then, for each subsequent repetition,
explains only what's genuinely different about that specific instance —
because mechanically re-explaining an identical pattern dozens of times
would bury the parts that actually matter under repetition. This is
itself a real software-engineering lesson worth internalizing: once you
understand a pattern, recognizing "this is that same pattern again, with
X changed" is a more valuable skill than re-deriving it from scratch every
time.

**A note on accuracy:** every code excerpt in this document is copied
directly from the real, current HYDRA source tree at the time this volume
was written. If you're reading this alongside a checkout of the repository,
the file paths given (relative to the repository root, e.g.
`common/python/hydra_common/models.py`) are exact.

### Table of Contents

1. Repository Tour
2. The JSON Schema, Line by Line
3. `hydra_common` — The Shared Library, Line by Line
4. `pyproject.toml` and Packaging, Explained
5. The Linux Agent, Part 1: The Native C Helper
6. The Linux Agent, Part 2: `cpu.py`, `signatures.py`, `utils.py`
7. The Linux Agent, Part 3: The Check Modules
8. The Linux Agent, Part 4: `runner.py`, `__main__.py`, Wiring It Together
9. The Windows Agent, Part 1: `Hydra.Common.psm1` and `Signatures.ps1`
10. The Windows Agent, Part 2: The Probe Modules
11. The Windows Agent, Part 3: `Invoke-Hydra.ps1`, the Entry Point
12. The Android Agent, Part 1: `adb.py` and `signatures.py`
13. The Android Agent, Part 2: The Check Modules
14. The Android Agent, Part 3: `runner.py`, `__main__.py`
15. The CLI: `cli/hydra_cli/__main__.py`, Line by Line
16. The Tests, File by File
17. End-to-End Trace: What Actually Happens When You Run `hydra test linux`
18. Case Studies: Six Real Bugs Caught During Development
19. Rebuild It Yourself: A Step-by-Step Guide From an Empty Folder
20. How to Extend HYDRA Yourself
21. Final Checklist

---

## Chapter 1: Repository Tour

Here is the complete file layout, with a one-line purpose for every file —
your map for the rest of this document.

```
hydra/
├── README.md                          top-level overview and quick start
├── pyproject.toml                     Python packaging/build configuration
├── .gitignore                         files Git should never track
│
├── schema/
│   └── hydra-report.schema.json       the one shape every agent's output must match
│
├── docs/
│   ├── ARCHITECTURE.md                design principles and component map
│   └── CHECK_COVERAGE.md              per-check mapping to Pafish/al-khaser/VMAware
│
├── common/python/hydra_common/        shared Python library, used by every Python agent + the CLI
│   ├── __init__.py                    the package's public exports
│   ├── models.py                      Category/Platform/Status/Severity enums, Finding, PlatformReport
│   ├── scoring.py                     severity-weighted scoring formula
│   ├── validation.py                  dependency-free JSON schema validator
│   ├── report.py                      multi-platform aggregation + HTML report renderer
│   ├── text_format.py                 human-readable colored terminal output
│   └── finding_factory.py             FindingFactory: boilerplate reducer for check modules
│
├── agents/
│   ├── linux/
│   │   ├── README.md
│   │   ├── native/
│   │   │   ├── cpuid_rdtsc.c          tiny C helper: the only way to reach CPUID/RDTSC from this agent
│   │   │   └── Makefile               builds cpuid_rdtsc.c into the cpuid_rdtsc binary
│   │   └── hydra_linux/
│   │       ├── __init__.py
│   │       ├── __main__.py            `python -m hydra_linux` entry point
│   │       ├── runner.py              runs every check module, assembles one PlatformReport
│   │       ├── cpu.py                 Python wrapper around the native helper (CPUID/RDTSC access)
│   │       ├── signatures.py          known hypervisor/VM/sandbox identity signatures
│   │       ├── utils.py               small filesystem/process helpers shared by every check module
│   │       └── checks/
│   │           ├── __init__.py        CHECK_MODULES tuple wiring all four category modules together
│   │           ├── environment.py     category 1: environment_artifact checks
│   │           ├── timing.py          category 2: timing checks
│   │           ├── behavioural.py     category 3: behavioural_interaction checks
│   │           └── design.py          category 4: design_specific checks
│   │
│   ├── windows/
│   │   ├── README.md
│   │   ├── Invoke-Hydra.ps1           entry point: `pwsh -File Invoke-Hydra.ps1`
│   │   ├── common/
│   │   │   ├── Hydra.Common.psm1      Finding/report construction + scoring, mirrors hydra_common
│   │   │   └── Signatures.ps1         known hypervisor/VM/sandbox identity signatures (Windows-specific)
│   │   └── probes/
│   │       ├── Environment.ps1        category 1 checks
│   │       ├── Timing.ps1             category 2 checks
│   │       ├── Behavioural.ps1        category 3 checks
│   │       └── Design.ps1             category 4 checks
│   │
│   └── android/
│       ├── README.md
│       └── hydra_android/
│           ├── __init__.py
│           ├── __main__.py            `python -m hydra_android` entry point
│           ├── runner.py              runs every check module, assembles one PlatformReport
│           ├── adb.py                 thin wrapper around the `adb` command
│           ├── signatures.py          known Android emulator identity signatures (HYDRA-original)
│           └── checks/
│               ├── __init__.py
│               ├── environment.py     category 1 checks
│               ├── timing.py          category 2 checks
│               ├── behavioural.py     category 3 checks
│               └── design.py          category 4 checks
│
├── cli/hydra_cli/
│   └── __main__.py                    the `hydra` command: `hydra test <platform>` / `hydra report`
│
└── tests/
    ├── test_common.py                 tests for hydra_common (models, scoring, validation, report, FindingFactory)
    ├── test_linux_agent.py            tests for Linux-specific logic + regression tests
    ├── test_windows_agent_report.py   integration test: runs the real pwsh agent, validates output
    ├── test_android_agent.py          tests for Android-specific logic + regression tests
    └── test_cli.py                    end-to-end tests for the `hydra` command itself
```

**Why this specific layout?** Three independent design decisions, each
traceable to a concept from Volume 1:

1. **`hydra_common` is separate from every agent.** Only the *Python*
   agents (Linux, Android) and the CLI can literally `import` it (Volume
   1, §4.9) — PowerShell cannot import a Python module at all. This is why
   the Windows agent has its own, independent (but carefully kept
   equivalent) `Hydra.Common.psm1`, rather than somehow sharing code
   directly with the Python side. The JSON Schema (Chapter 2, below) is
   what actually keeps the two independent implementations honest against
   each other, not shared code.
2. **Every agent is organized into the same four `checks/` category
   files** (`environment.py`/`.ps1`, `timing.py`/`.ps1`,
   `behavioural.py`/`.ps1`, `design.py`/`.ps1`), because the four-category
   model (Volume 1, Chapter 15) is the organizing principle of the entire
   project — an engineer who already understands one agent's layout can
   immediately navigate any of the other two, even across the Python/
   PowerShell language boundary, because the *shape* is identical.
3. **The native C helper lives inside `agents/linux/native/`, not
   somewhere shared**, because it is genuinely Linux-agent-specific
   tooling (Volume 1, §7.1) — nothing else in the project needs it, so it
   has no business living anywhere more central.

## Chapter 2: The JSON Schema, Line by Line

**File:** `schema/hydra-report.schema.json`

This is the single most important file in the entire project — the one
document every other file, in every language, is written to agree with.
We start here for exactly that reason: understanding the schema first
means every agent's code you read afterward will make sense in terms of
"which part of the agreed-upon shape is this line building."

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://hydra.chimera.local/schema/hydra-report.schema.json",
  "title": "HYDRA Platform Report",
  "description": "Unified report format emitted by every HYDRA agent (Windows, Linux, Android). One suite, one schema, three platforms.",
  "type": "object",
```

`$schema` declares which *version* of the JSON Schema specification this
file itself follows (Draft 7 — one of several standardized JSON Schema
versions; the exact version rarely matters day-to-day, but declaring it
avoids ambiguity). `$id` is a unique identifying URL for this schema — it
does not need to be a real, fetchable web address (and isn't, here); it
just needs to be a globally unique name. `title`/`description` are
human-readable documentation, ignored by validators. `"type": "object"`
is the first real rule: a valid HYDRA report must be a JSON object (Volume
1, §9.1) — not an array, not a bare string, at the top level.

```json
  "required": ["hydra_version", "platform", "hostname", "generated_at", "findings", "summary"],
  "additionalProperties": false,
```

`required` lists every field that *must* be present at the top level —
miss even one and the report is invalid. `"additionalProperties": false`
is a strict rule: a report is *not* allowed to have extra fields beyond
the ones this schema explicitly names in `properties` (below) — this
deliberately prevents silent schema drift, e.g. if someone later adds a
new top-level field to one agent's code without updating the schema (and
therefore without updating the other agents to match), that agent's output
would immediately fail validation, loudly, rather than the drift going
unnoticed.

```json
  "properties": {
    "hydra_version": { "type": "string" },
    "platform": { "type": "string", "enum": ["windows", "linux", "android"] },
    "hostname": { "type": "string" },
    "generated_at": { "type": "string", "format": "date-time" },
    "agent_metadata": {
      "type": "object",
      "description": "Free-form platform-specific identity info (OS build, device model, etc.) for report context only.",
      "additionalProperties": { "type": "string" }
    },
    "findings": {
      "type": "array",
      "items": { "$ref": "#/definitions/finding" }
    },
    "summary": { "$ref": "#/definitions/summary" }
  },
```

Each top-level field's rule, one at a time:
- `hydra_version` — any string (the project's own version number, e.g.
  `"0.1.0"`).
- `platform` — a string, but constrained by `"enum"` to be *exactly* one
  of the three listed values — this is JSON Schema's equivalent of
  Volume 1's enum concept (§4.8): a fixed, closed set of legal values.
- `hostname` — any string.
- `generated_at` — a string, additionally constrained by
  `"format": "date-time"` to look like a standard timestamp (JSON Schema's
  `date-time` format follows the widely-used **ISO 8601** timestamp
  convention, e.g. `"2026-08-11T03:42:00+00:00"`).
- `agent_metadata` — optional (not in the `required` list above), and if
  present, must itself be an object whose every value is a string (this is
  what `"additionalProperties": { "type": "string" }` means here — unlike
  the strict top-level `false`, this is instead a *type constraint*
  applied to whatever extra keys are present, since `agent_metadata` is
  deliberately meant to hold free-form, agent-specific info like OS build
  numbers or device models, whose exact key names legitimately differ per
  platform).
- `findings` — must be a JSON array (Volume 1, §9.1), where every element
  must independently satisfy the `finding` definition (below) — `$ref`
  is JSON Schema's way of reusing a rule defined once elsewhere in the same
  document, rather than repeating it.
- `summary` — must satisfy the separate `summary` definition (below).

```json
  "definitions": {
    "finding": {
      "type": "object",
      "required": ["id", "category", "platform", "name", "description", "status", "severity"],
      "additionalProperties": false,
      "properties": {
        "id": {
          "type": "string",
          "description": "Stable, dotted check id, e.g. 'linux.env.dmi_sys_vendor'.",
          "pattern": "^[a-z0-9]+\\.[a-z_]+\\.[a-z0-9_]+$"
        },
```

`"pattern"` applies a **regular expression** (Volume 1, §4.10) to
constrain exactly what a valid `id` string can look like: lowercase
letters/digits, a dot, lowercase letters/underscores, a dot, lowercase
letters/digits/underscores. This is precisely the `platform.category
.check_name` naming convention every check ID in the whole project follows
(e.g. `linux.env.cpuid_hypervisor_bit`, `win.design.debugger_present`,
`android.behavioural.battery_temperature`) — encoding the convention
directly into the schema means a malformed or inconsistently-named check
ID is caught immediately by validation, rather than silently slipping
through.

```json
        "category": {
          "type": "string",
          "enum": ["environment_artifact", "timing", "behavioural_interaction", "design_specific"],
          "description": "The four detection categories from the CHIMERA theoretical model (Ch.3)."
        },
        "platform": { "type": "string", "enum": ["windows", "linux", "android"] },
        "name": { "type": "string", "description": "Short human title, e.g. 'SMBIOS system vendor string'." },
        "description": { "type": "string", "description": "What the check does and why it matters." },
        "status": {
          "type": "string",
          "enum": ["clean", "detected", "error", "skipped"],
          "description": "clean = no tell found; detected = evasion tell found (BAD); error = probe could not run; skipped = not applicable on this host."
        },
        "severity": {
          "type": "string",
          "enum": ["info", "low", "medium", "high", "critical"],
          "description": "Real-world significance if detected -- mirrors the KVM hardening report's per-flag justification approach, not just pass/fail."
        },
```

`category` and `status` are exactly the enums covered in Volume 1
(§4.8/Chapter 15) — this is where those Python/PowerShell enum
definitions ultimately trace back to: the schema is the *authoritative*
source, and each language's own enum type (`Category`/`Status` in Python,
`-ValidateSet` in PowerShell — Volume 1, §6.3) is a separate, independent
re-implementation of exactly these same allowed values, kept in sync by
convention and by this schema catching any drift.

```json
        "evidence": {
          "description": "Raw observed value(s) supporting the status, for analyst review.",
          "type": ["string", "object", "array", "null"]
        },
        "remediation": {
          "type": ["string", "null"],
          "description": "Suggested hardening-profile change to close this gap, so findings feed back into CHIMERA hardening rather than only being reported."
        },
        "error_detail": {
          "type": ["string", "null"],
          "description": "Populated when status == error."
        }
      }
    },
```

`"type": ["string", "object", "array", "null"]` — a JSON Schema type
constraint can itself be a *list* of allowed types, meaning "must be one
of these," not just a single fixed type. `evidence` is allowed to be
several different shapes because different checks naturally produce
different kinds of evidence — a single matched string, a list of matched
paths, a small structured object (like the timing check's min/median/
mean/max numbers) — and `null` (Volume 1, §3.2) covers "no evidence
attached" (e.g. a `clean` result with nothing noteworthy to show).
`remediation` and `error_detail` are each `string`-or-`null`, precisely
because exactly one of them is meaningful depending on the finding's
`status` — a `clean` finding has neither; a `detected` finding typically
has `remediation` but not `error_detail`; an `error` finding has
`error_detail` but not `remediation`.

Notice that the schema *cannot* fully express "error_detail must be
non-null when status is 'error'" — that's a rule *across* two different
fields, which basic JSON Schema's per-field `properties` block has no way
to state. This exact gap is why HYDRA's own validator (Chapter 3.3, below)
adds one specific extra check beyond what the schema file alone captures.

```json
    "summary": {
      "type": "object",
      "required": ["total", "clean", "detected", "errored", "skipped", "raw_score", "weighted_score"],
      "additionalProperties": false,
      "properties": {
        "total": { "type": "integer", "minimum": 0 },
        "clean": { "type": "integer", "minimum": 0 },
        "detected": { "type": "integer", "minimum": 0 },
        "errored": { "type": "integer", "minimum": 0 },
        "skipped": { "type": "integer", "minimum": 0 },
        "raw_score": {
          "type": "string",
          "description": "VMAware-style 'clean/total' string, e.g. '91/93'."
        },
        "weighted_score": {
          "type": "number",
          "minimum": 0,
          "maximum": 100,
          "description": "Severity-weighted cleanliness score 0-100 (100 = nothing detected). See hydra_common.scoring."
        }
      }
    }
  }
}
```

The `summary` block's five integer counts (`total`, `clean`, `detected`,
`errored`, `skipped`) are constrained to be non-negative integers
(`"minimum": 0`); `raw_score` is deliberately a *string* (not a number),
because it's meant to be displayed exactly as-is, in the human-readable
`"5/5"` form (a number can't represent that shape at all); `weighted_score`
is a number, additionally bounded between 0 and 100 inclusive, matching
exactly the range the scoring formula (Chapter 3.2, below) is designed to
produce.

## Chapter 3: `hydra_common` — The Shared Library, Line by Line

### 3.1 `models.py` — the data model

**File:** `common/python/hydra_common/models.py`

```python
"""Shared data model for every HYDRA agent.

This module is the single source of truth for the report shape described in
schema/hydra-report.schema.json. Windows, Linux, and Android agents that are
written in Python import this directly; the PowerShell agent emits matching
JSON by hand (see agents/windows/README.md) since it cannot import Python.
"""

from __future__ import annotations

import platform as _platform
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
```

The module **docstring** (a string literal placed as the very first
statement in a file/function/class, Python's built-in convention for
documentation — accessible at runtime via `module.__doc__`, and what tools
like `help()` display) states this module's authority explicitly: it *is*
the schema, translated into Python types.

`from __future__ import annotations` is a specific, common Python idiom
that changes how type hints (Volume 1, §4.3) are handled internally
(they're kept as plain text rather than evaluated immediately), which lets
you write forward references like `str | None` without worrying about
Python version compatibility details — you'll see this exact line at the
top of essentially every `.py` file in this project; it's boilerplate
worth recognizing but not worth dwelling on.

`import platform as _platform` — Python's own *built-in* `platform` module
(unrelated to HYDRA's own `Platform` enum below, hence the leading
underscore rename to `_platform`, avoiding a naming collision) provides
OS-identification helpers like `platform.system()` (returns `"Linux"`,
`"Windows"`, `"Darwin"` for macOS, etc.).

```python
class Category(str, Enum):
    ENVIRONMENT_ARTIFACT = "environment_artifact"
    TIMING = "timing"
    BEHAVIOURAL_INTERACTION = "behavioural_interaction"
    DESIGN_SPECIFIC = "design_specific"


class Platform(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    ANDROID = "android"


class Status(str, Enum):
    CLEAN = "clean"
    DETECTED = "detected"
    ERROR = "error"
    SKIPPED = "skipped"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
```

Four enums (Volume 1, §4.8), each a direct, literal transcription of one
`enum` block from the JSON Schema (Chapter 2). `class Category(str, Enum)`
— inheriting from *both* `str` and `Enum` (Python allows a class to
inherit from multiple parent classes at once) means each member is
simultaneously a real enum member *and* behaves like an ordinary string
wherever a string is expected — this specific combination is why
`Category.ENVIRONMENT_ARTIFACT.value` (or, in string contexts, sometimes
even the member itself directly) gives you back exactly `"environment_artifact"`,
matching the schema's raw string exactly, with no extra conversion step
needed when serializing to JSON later.

```python
@dataclass(frozen=True)
class Finding:
    id: str
    category: Category
    platform: Platform
    name: str
    description: str
    status: Status
    severity: Severity
    evidence: Any = None
    remediation: str | None = None
    error_detail: str | None = None
```

This is HYDRA's single most important class (Volume 1, §3.5) — the result
of running exactly one check. `@dataclass(frozen=True)` (Volume 1, §4.7)
auto-generates `__init__` from these ten fields and makes every instance
immutable after construction (Volume 1, §3.8/§18.2). Field order matters
here for one subtle reason: dataclasses require fields *with* a default
value (`evidence`, `remediation`, `error_detail` — each defaulting to
`None`) to come *after* every field *without* one — this is a plain
Python language rule (mirroring how default-valued function parameters
must come last, Volume 1, §3.4), not a HYDRA-specific design choice.

```python
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category.value,
            "platform": self.platform.value,
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "error_detail": self.error_detail,
        }
```

`to_dict()` is the explicit "translate down to JSON-serializable plain
Python types" step (Volume 1, §9.2) — notice `self.category.value`
specifically (not just `self.category`): `.value` unwraps the enum member
down to its raw string (`"environment_artifact"`) — necessary because,
while `Category` inherits from `str` and mostly *behaves* like one, Python's
`json.dumps` needs an *actual* `dict`/`str`/`int`/etc. at serialization
time to produce clean, minimal JSON, and calling `.value` explicitly is
the reliable, unambiguous way to guarantee that rather than depending on
`str`-subclass behavior working out correctly in every case.

```python
@dataclass(frozen=True)
class PlatformReport:
    """Immutable snapshot of a completed scan.

    Agents collect findings in a plain list while probes run, then construct
    exactly one PlatformReport at the end -- there is no in-place mutator by
    design, so a report can never be observed half-built.
    """

    platform: Platform
    findings: tuple[Finding, ...]
    hostname: str = field(default_factory=socket.gethostname)
    hydra_version: str = "0.1.0"
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    agent_metadata: dict[str, str] = field(default_factory=dict)
```

The second core class: a complete report for one platform run, bundling
every `Finding` together with metadata about the run itself. Two things
worth understanding precisely here:

- **`findings: tuple[Finding, ...]`, not `list[Finding]`.** This is a
  deliberate, meaningful choice, not a stylistic preference: tuples are
  immutable (Volume 1, §3.3/§3.8), while lists are mutable. If this field
  were a `list`, a completely different, well-intentioned piece of code
  holding a reference to the same `PlatformReport` could still silently
  `.append()` to (or otherwise mutate) its `findings` list *after* the
  report was supposedly finalized — quietly defeating the entire point of
  marking `PlatformReport` itself `frozen=True`. Using `tuple` here closes
  that loophole completely: there is no mutating operation a tuple even
  *has* to accidentally call.
- **`field(default_factory=...)` instead of a plain default value.**
  Python dataclasses specifically forbid using a *mutable* default value
  directly (e.g. `agent_metadata: dict = {}` is a language-level error in
  a dataclass) — because a plain default value is created *once*, when the
  class is defined, and then silently *shared* across every instance that
  doesn't override it, meaning one instance mutating its "default" dict
  would corrupt every other instance's supposedly-independent default too
  (a classic, historically well-known Python footgun). `default_factory`
  fixes this by taking a zero-argument function that gets *called fresh*,
  producing a brand-new independent value, every single time a new
  instance is created without an explicit override. `socket.gethostname`
  (no parentheses — passing the function itself, to be called later, not
  calling it immediately) supplies the machine's real hostname by default;
  the `lambda: datetime.now(timezone.utc)` (an anonymous, inline function,
  Volume 1, §3.4 — a `lambda` is Python's syntax for a function defined in
  a single expression, with no `def`/name needed) supplies the current UTC
  timestamp, freshly computed at the moment each report is actually
  created.

```python
    def to_dict(self) -> dict:
        from .scoring import score_report  # local import avoids a cycle

        return {
            "hydra_version": self.hydra_version,
            "platform": self.platform.value,
            "hostname": self.hostname,
            "generated_at": self.generated_at.isoformat(),
            "agent_metadata": self.agent_metadata,
            "findings": [f.to_dict() for f in self.findings],
            "summary": score_report(self.findings),
        }
```

`from .scoring import score_report` appearing *inside* the method body,
rather than at the top of the file alongside the other imports, is a
deliberate **local import** — used specifically to break a **circular
import** (a situation where module A needs something from module B, and
module B also needs something from module A, which would otherwise make
Python unable to fully load either one first). Here, `scoring.py` needs to
`import` `Finding`/`Status`/`Severity` *from* `models.py` (you'll see this
in §3.2 below) — so `models.py` cannot *also* import from `scoring.py` at
the top level without creating exactly that cycle. Deferring the import
to the one specific moment it's actually needed (inside `to_dict`, only
called once a `PlatformReport` already fully exists) sidesteps the problem
entirely, since by the time this line actually runs, both modules have
already finished loading.

`self.generated_at.isoformat()` converts Python's internal `datetime`
object into the ISO 8601 string format the schema requires (Chapter 2).
`[f.to_dict() for f in self.findings]` is a list comprehension (Volume 1,
§4.6) calling `Finding.to_dict()` on every element — translating the
*entire* nested structure down to plain JSON-serializable types, all the
way through, in one line.

```python
    @staticmethod
    def default_metadata() -> dict[str, str]:
        return {
            "os": _platform.system(),
            "os_release": _platform.release(),
            "machine": _platform.machine(),
        }
```

A `@staticmethod` (Volume 1, §3.5/§4.7) is a method that doesn't need
`self` at all — it belongs to the class conceptually, but doesn't operate
on any particular instance, callable directly as
`PlatformReport.default_metadata()`. This one builds a small, generic
`agent_metadata` dict using Python's own `platform` module (renamed
`_platform` above) — `.system()`/`.release()`/`.machine()` report the
OS name, OS version, and CPU architecture string respectively. Volume 2's
Chapter 8 shows exactly where the Linux agent's `runner.py` calls this.

### 3.2 `scoring.py` — the weighted scoring formula

**File:** `common/python/hydra_common/scoring.py`

```python
SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.05,
    Severity.LOW: 0.15,
    Severity.MEDIUM: 0.35,
    Severity.HIGH: 0.65,
    Severity.CRITICAL: 1.0,
}


def score_report(findings: Iterable[Finding]) -> dict:
    findings = list(findings)
    total = len(findings)
    clean = sum(1 for f in findings if f.status == Status.CLEAN)
    detected = sum(1 for f in findings if f.status == Status.DETECTED)
    errored = sum(1 for f in findings if f.status == Status.ERROR)
    skipped = sum(1 for f in findings if f.status == Status.SKIPPED)
```

`SEVERITY_WEIGHT` is the exact weight table Volume 1 (§18.4) described in
words, now as real code — a dictionary (Volume 1, §3.3) mapping each
`Severity` enum member to a 0-1 weight. `Iterable[Finding]` (rather than,
say, `list[Finding]`) is a slightly more permissive type hint meaning
"anything you can loop over with a `for` loop, producing `Finding`
objects" — accepting a `tuple` (like `PlatformReport.findings`), a
`list`, or any other iterable, without forcing the caller to convert first.
`findings = list(findings)` immediately converts whatever was passed in
into a concrete `list` internally — necessary because the function needs
to loop over `findings` *multiple times* below (once per `sum(...)` call),
and some kinds of iterables (though not tuples or lists specifically) can
only be consumed once; converting up front makes the function robust
regardless of exactly what kind of iterable was handed to it.

Each `sum(1 for f in findings if f.status == Status.X)` is a **generator
expression** (a close cousin of the list comprehension from Volume 1,
§4.6, but producing values lazily one at a time instead of building a full
list first) — `1 for f in findings if ...` produces the number `1` once
for every finding matching the condition, and `sum(...)` adds them all up
— an idiomatic, compact way to count how many items in a collection match
a condition, without writing an explicit loop-with-a-counter-variable by
hand.

```python
    applicable = clean + detected
    raw_score = f"{clean}/{applicable}" if applicable else "0/0"

    if applicable == 0:
        weighted_score = 100.0
    else:
        penalty = sum(SEVERITY_WEIGHT[f.severity] for f in findings if f.status == Status.DETECTED)
        # Normalise against the number of applicable checks so a suite with
        # more checks isn't automatically penalised harder for the same
        # proportion of failures.
        weighted_score = max(0.0, 100.0 * (1.0 - penalty / applicable))
```

`applicable = clean + detected` — this is the precise, concrete definition
of "applicable" mentioned throughout this project's documentation:
checks that produced a genuine pass/fail verdict, explicitly excluding
`errored` and `skipped` findings (Volume 1, §18.4 explained *why*; this is
*where* that rule is actually enforced in code). `raw_score` is built as
an f-string (Volume 1, §4.4), with a fallback to the literal string
`"0/0"` if `applicable` is zero (avoiding a division-by-zero-flavored
`"0/0"` division, and more importantly avoiding a nonsensical `"0/0"` that
Python's own division would actually error on if attempted directly —
here it's just string formatting, so no error would occur either way, but
the explicit `if applicable else "0/0"` guard keeps the *logic*
symmetric with the `weighted_score` calculation just below it, which
*does* need the same zero-guard to avoid a real division-by-zero crash).

The `if applicable == 0: weighted_score = 100.0` branch encodes a
specific, deliberate policy decision: a scan where *every single check*
came back `error` or `skipped` (nothing genuinely applicable at all) is
scored as a perfect 100, not a 0 — the reasoning being that a score is
meant to represent "how much evidence of virtualization was found," and
zero applicable checks means zero evidence was found, which is
indistinguishable, numerically, from a genuinely clean result, even
though *in practice* an all-skipped/errored run is really signaling "this
scan didn't actually check anything meaningful," which a human reading the
report needs to notice from the `errored`/`skipped` counts sitting right
next to the score, not from the score number itself.

The `penalty` line sums up `SEVERITY_WEIGHT[f.severity]` for every
`detected` finding — using the enum member itself (`f.severity`, a
`Severity` instance) directly as a dictionary key, which works cleanly
here specifically because `Severity` inherits from `str` (§3.1) and
dictionary keys just need to be *hashable* (a technical requirement that
both plain strings and `str`-subclass enum members satisfy identically).
`weighted_score = max(0.0, 100.0 * (1.0 - penalty / applicable))` is the
formula from Volume 1 (§18.4), written out exactly: start at 100, subtract
the average per-check penalty (normalized by dividing by `applicable`, so
a report with more checks doesn't get unfairly penalized harder for the
same *proportion* of failures — Volume 1's own explanation, now visible
as the actual comment in the real source), and `max(0.0, ...)` is a safety
clamp preventing the score from going negative (which could theoretically
happen if enough high-severity detections accumulated for the raw formula
to dip below zero, even though the current weight table makes this
mathematically impossible in practice — the clamp is defensive, cheap
insurance regardless).

```python
    return {
        "total": total,
        "clean": clean,
        "detected": detected,
        "errored": errored,
        "skipped": skipped,
        "raw_score": raw_score,
        "weighted_score": round(weighted_score, 2),
    }
```

The return value is a plain `dict`, matching the schema's `summary`
definition (Chapter 2) field-for-field, exactly. `round(weighted_score, 2)`
rounds to 2 decimal places purely for display cleanliness (e.g. `93.2`
instead of `93.199999999999996`, a common floating-point artifact of the
division/multiplication above — Volume 1, §3.2 introduced floats; this is
a very typical, harmless example of their limited precision in practice).

### 3.3 `validation.py` — the dependency-free schema validator

**File:** `common/python/hydra_common/validation.py`

This module deliberately does **not** use the popular third-party
`jsonschema` PyPI package (Volume 1, §4.12 covered `pip`/third-party
packages) — its own docstring explains exactly why: HYDRA agents are
meant to run inside isolated sandbox environments that might have no
internet access to install anything, so the shared library stays
dependency-free (standard-library only), and instead implements just
the specific subset of validation logic HYDRA actually needs, by hand.

```python
_REQUIRED_TOP = {"hydra_version", "platform", "hostname", "generated_at", "findings", "summary"}
_PLATFORMS = {"windows", "linux", "android"}
_CATEGORIES = {"environment_artifact", "timing", "behavioural_interaction", "design_specific"}
_STATUSES = {"clean", "detected", "error", "skipped"}
_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_REQUIRED_FINDING = {"id", "category", "platform", "name", "description", "status", "severity"}
_REQUIRED_SUMMARY = {"total", "clean", "detected", "errored", "skipped", "raw_score", "weighted_score"}
```

Every one of these is a Python `set` (Volume 1, §3.3) — chosen
specifically because checking "is this value in the set" and computing
"which required keys are missing" (below) are both extremely fast, natural
operations on sets, and because a set automatically has no meaningful
order or duplicates, which is exactly right for "a collection of legal
values" or "a collection of required field names." Each of these is a
hand-written, plain-Python mirror of the exact same constraints from the
JSON Schema file (Chapter 2) — this file is, in effect, a second,
independent implementation of a subset of that schema's rules, written to
avoid the external dependency.

```python
class ValidationError(ValueError):
    pass
```

A **custom exception class** (Volume 1, §3.4 introduced exceptions in
general): `ValidationError` inherits from Python's built-in `ValueError`
(a natural parent choice, since a validation failure genuinely *is* "a
value was wrong"), and the class body is just `pass` (Python's explicit
"do nothing further" keyword, needed here because a class body cannot be
completely empty syntactically) — meaning `ValidationError` adds no new
behavior of its own beyond what `ValueError` already provides; its entire
purpose is to give this specific project's validation failures their own
distinct, catchable, greppable exception *type*, separate from any other
possible `ValueError` that might occur elsewhere in the code for
unrelated reasons.

```python
def validate_report(report: dict, *, source: str = "<report>") -> None:
    """Raise ValidationError with a precise message on the first problem found."""
    if not isinstance(report, dict):
        raise ValidationError(f"{source}: top-level report must be an object")

    missing = _REQUIRED_TOP - report.keys()
    if missing:
        raise ValidationError(f"{source}: missing required top-level field(s): {sorted(missing)}")

    if report["platform"] not in _PLATFORMS:
        raise ValidationError(f"{source}: platform '{report['platform']}' not in {_PLATFORMS}")

    findings = report["findings"]
    if not isinstance(findings, list):
        raise ValidationError(f"{source}: 'findings' must be a list")

    for i, finding in enumerate(findings):
        _validate_finding(finding, source=f"{source}.findings[{i}]")

    _validate_summary(report["summary"], source=f"{source}.summary")
```

`def validate_report(report: dict, *, source: str = "<report>") -> None:`
— the lone `*` in the parameter list is a Python syntax feature meaning
"everything after this point must be passed by name, not by position" (a
**keyword-only argument**) — so callers must write
`validate_report(report, source="reports[2]")`, never
`validate_report(report, "reports[2]")` positionally; this is a
deliberate readability choice, making call sites self-documenting about
what that second argument actually means, since `source` by itself, seen
at a call site with no name attached, would be genuinely ambiguous.
`source` defaults to the placeholder string `"<report>"` and exists purely
so that error messages can say *precisely which* report (out of possibly
several being validated together — see `aggregate_reports` in §3.5) failed,
and where within it — you'll see this `source` string get extended,
piece by piece (`f"{source}.findings[{i}]"`), as validation descends into
nested structures, building up something like `"reports[1].findings[4]"`
in a final error message: a precise, navigable path to the exact problem.

`missing = _REQUIRED_TOP - report.keys()` — Python's set subtraction
operator (`-`) applied to `report.keys()` (a *view* of a dict's keys,
which itself behaves set-like) computes "every required field name that
is *not* present" in one expression — a `not isinstance(...)`, an
explicit `not in` set-membership check, and this set-subtraction idiom
are the three basic tools this entire file is built from, used repeatedly.

`isinstance(report, dict)` checks report's actual Python type at runtime
(Volume 1, §3.2 introduced types; `isinstance` is how Python code checks a
value's type explicitly, since — unlike languages such as C, Volume 1
§7.2 — Python doesn't enforce types automatically at runtime by default;
type hints, §4.3, are optional documentation, not runtime guarantees,
which is precisely why *this* validator function needs to exist at all:
someone has to actually check, at runtime, that a piece of JSON parsed
from an external file/process really does match the expected shape).

`for i, finding in enumerate(findings):` — `enumerate()` is a built-in
Python function that, given any iterable, produces `(index, value)` pairs
— here giving both the finding's position (`i`, for building that precise
error path) and the finding itself, in one loop.

```python
def _validate_finding(finding: dict, *, source: str) -> None:
    if not isinstance(finding, dict):
        raise ValidationError(f"{source}: finding must be an object")
    missing = _REQUIRED_FINDING - finding.keys()
    if missing:
        raise ValidationError(f"{source}: missing required field(s): {sorted(missing)}")
    if finding["category"] not in _CATEGORIES:
        raise ValidationError(f"{source}: category '{finding['category']}' not in {_CATEGORIES}")
    if finding["platform"] not in _PLATFORMS:
        raise ValidationError(f"{source}: platform '{finding['platform']}' not in {_PLATFORMS}")
    if finding["status"] not in _STATUSES:
        raise ValidationError(f"{source}: status '{finding['status']}' not in {_STATUSES}")
    if finding["severity"] not in _SEVERITIES:
        raise ValidationError(f"{source}: severity '{finding['severity']}' not in {_SEVERITIES}")
    if finding["status"] == "error" and not finding.get("error_detail"):
        raise ValidationError(f"{source}: status is 'error' but 'error_detail' is empty")
```

A leading underscore in a function name (`_validate_finding`,
`_validate_summary`) is a Python-wide convention (not a language-enforced
rule — just a strongly followed one) meaning "this is an internal
implementation detail of this module, not part of its public interface" —
other code is *able* to call it, but is signaling "please don't; use
`validate_report` instead."

The very last check here —
`if finding["status"] == "error" and not finding.get("error_detail"):` —
is precisely the cross-field rule mentioned back in Chapter 2 as something
the JSON Schema file *itself* structurally cannot express (a rule spanning
two different fields' values together). `finding.get("error_detail")`
(rather than `finding["error_detail"]`) is used specifically because,
unlike the fields checked with `not in _REQUIRED_FINDING` (guaranteed
present by the earlier `missing` check), `error_detail` is genuinely
*optional* — `.get()` returns `None` if the key is absent entirely, rather
than raising a `KeyError` the way `[...]` indexing would; and
`not finding.get("error_detail")` is `True` for `None`, an empty string,
or a missing key alike (Volume 1, §4.5's "falsy" values), which is exactly
the "empty" condition this rule is guarding against.

```python
def _validate_summary(summary: dict, *, source: str) -> None:
    if not isinstance(summary, dict):
        raise ValidationError(f"{source}: summary must be an object")
    missing = _REQUIRED_SUMMARY - summary.keys()
    if missing:
        raise ValidationError(f"{source}: missing required field(s): {sorted(missing)}")
    counted = summary["clean"] + summary["detected"] + summary["errored"] + summary["skipped"]
    if counted != summary["total"]:
        raise ValidationError(
            f"{source}: clean+detected+errored+skipped ({counted}) != total ({summary['total']})"
        )
```

A second cross-field rule the raw schema file alone cannot express: the
four individual counts must literally add up to the stated `total` —
internal arithmetic self-consistency, catching a bug where, say, a
`score_report`-equivalent implementation (Python's real one, or the
independent PowerShell reimplementation, §9 below) accidentally
miscounted something.

### 3.4 `finding_factory.py` — the boilerplate reducer

**File:** `common/python/hydra_common/finding_factory.py`

This module exists purely for ergonomics: with dozens of checks per
platform (Chapters 7, 13 will show ~37 on Linux, ~30 on Windows, ~22 on
Android), spelling out a full `Finding(id=..., category=..., platform=...,
status=..., severity=..., ...)` constructor call by hand, every single
time, would be repetitive and error-prone (easy to mistype a
status/severity pairing, or forget a field). `FindingFactory` is created
*once* per check module, pre-bound to that module's fixed `category` and
`platform`, and then every individual check function just calls one of its
short methods.

```python
@dataclass(frozen=True)
class FindingFactory:
    category: Category
    platform: Platform

    def clean(self, id: str, name: str, description: str, severity: Severity, evidence: Any = None) -> Finding:
        return Finding(
            id=id,
            category=self.category,
            platform=self.platform,
            name=name,
            description=description,
            status=Status.CLEAN,
            severity=severity,
            evidence=evidence,
        )
```

`FindingFactory` is itself a frozen dataclass (Volume 1, §4.7) — slightly
unusual at first glance, since it holds no per-check data at all, only the
two values (`category`, `platform`) that are genuinely fixed for an
entire check module's lifetime. Making it frozen/immutable isn't strictly
load-bearing here (nothing in the codebase ever tries to mutate a
`FindingFactory` instance), but it's consistent with the project's blanket
immutability convention (Volume 1, §18.2) and costs nothing.

`clean()` builds a `Finding` with `status=Status.CLEAN` filled in
automatically, `remediation`/`error_detail` left at their `None` defaults
(correct for a clean result — Volume 1, §9's schema discussion explained
why those two fields are meaningless outside their specific statuses), and
every other value passed straight through from the caller.

```python
    def detected(
        self,
        id: str,
        name: str,
        description: str,
        severity: Severity,
        evidence: Any = None,
        remediation: str | None = None,
    ) -> Finding:
        return Finding(
            id=id, category=self.category, platform=self.platform, name=name, description=description,
            status=Status.DETECTED, severity=severity, evidence=evidence, remediation=remediation,
        )

    def error(self, id: str, name: str, description: str, severity: Severity, detail: str) -> Finding:
        return Finding(
            id=id, category=self.category, platform=self.platform, name=name, description=description,
            status=Status.ERROR, severity=severity, error_detail=detail,
        )

    def skipped(self, id: str, name: str, description: str, severity: Severity, detail: str) -> Finding:
        return Finding(
            id=id, category=self.category, platform=self.platform, name=name, description=description,
            status=Status.SKIPPED, severity=severity, error_detail=detail,
        )
```

`detected()` mirrors `clean()` but fixes `status=Status.DETECTED` and
additionally accepts `remediation`. `error()` and `skipped()` are
structurally near-identical to each other — both take a required `detail`
string (not optional, unlike `evidence`/`remediation` elsewhere, because
the whole point of `Status.ERROR`/`Status.SKIPPED` is to explain *why* no
real verdict was reached, so omitting that explanation would defeat the
entire purpose) and populate `error_detail` (never `evidence` or
`remediation`, since — per the schema, Chapter 2 — those two fields are
specifically meant for `clean`/`detected` results, and `error_detail` is
specifically meant for `error`/`skipped` results).

```python
    def bool_check(
        self,
        id: str,
        name: str,
        description: str,
        severity: Severity,
        *,
        is_detected: bool,
        evidence: Any = None,
        remediation: str | None = None,
    ) -> Finding:
        """Convenience for the common "detected if condition else clean" shape."""
        if is_detected:
            return self.detected(id, name, description, severity, evidence=evidence, remediation=remediation)
        return self.clean(id, name, description, severity, evidence=evidence)
```

`bool_check()` is the single most-used method in the entire codebase — a
further convenience on top of `clean()`/`detected()`, for the extremely
common "run one test, get one true/false answer, produce either a
`detected` or a `clean` finding accordingly" shape that the overwhelming
majority of individual checks in this project actually follow. `*,
is_detected: bool` marks `is_detected` (and everything after it) as
keyword-only (§3.3's technique again) — deliberately forcing every call
site to write `is_detected=some_condition`, so that reading any check's
code, you can immediately see *what* boolean condition is being tested,
rather than having to remember "is the third positional argument the
detection flag or something else." Notice `clean()` is called *without*
`remediation` in the `else` branch — a deliberate, meaningful omission:
remediation advice only makes sense attached to a *problem* that needs
fixing, never to a clean result, so even if a caller passed a
`remediation` string in anyway, `bool_check`'s clean path silently drops
it rather than attaching irrelevant "fix" text to a finding that has
nothing to fix.

### 3.5 `report.py` — multi-platform aggregation and HTML rendering

**File:** `common/python/hydra_common/report.py`

This is the module behind the `hydra report` CLI subcommand (Chapter 15
covers the CLI itself) — combining multiple already-collected platform
reports (Windows + Linux + Android, or any subset) into one unified view.

```python
def aggregate_reports(reports: list[dict], *, validate: bool = True) -> dict:
    """Combine multiple platform reports into one unified report dict."""
    if validate:
        for i, report in enumerate(reports):
            validate_report(report, source=f"reports[{i}]")

    total = clean = detected = errored = skipped = 0
    penalty = 0.0
    applicable = 0
    for report in reports:
        s = report["summary"]
        total += s["total"]
        clean += s["clean"]
        detected += s["detected"]
        errored += s["errored"]
        skipped += s["skipped"]
        for finding in report["findings"]:
            if finding["status"] == "detected":
                penalty += SEVERITY_WEIGHT[Severity(finding["severity"])]
        applicable += s["clean"] + s["detected"]

    overall_weighted = 100.0 if applicable == 0 else max(0.0, 100.0 * (1.0 - penalty / applicable))
```

`total = clean = detected = errored = skipped = 0` is Python's **chained
assignment** syntax — a compact way of initializing five separate
variables to the same starting value (`0`) in one line, equivalent to
writing five separate `x = 0` lines. The function loops over every
`report` given to it, pulling each one's *already-computed* `summary`
(each individual agent computed its own summary independently, via
`score_report`, before ever reaching this aggregation step) and simply
*adding* the five counts together across all reports — this is why
`aggregate_reports` never needs to re-derive `clean`/`detected`/etc. from
scratch; it trusts each individual report's own already-validated summary.

The *weighted* score, however, genuinely is recomputed from scratch here
(the inner `for finding in report["findings"]:` loop), rather than simply
averaging the pre-computed `weighted_score` values together — this is a
deliberate, mathematically important choice: averaging three already-
averaged percentages together does *not* produce the same, correct result
as computing one weighted average directly over every individual
detection across all three platforms combined (a classic pitfall — a
report with 5 checks at a 50% weighted score and a report with 500 checks
at a 90% weighted score should *not* simply average out to 70% overall;
the 500-check report's result should dominate proportionally, and only
recomputing the penalty sum directly over every individual finding gets
that right). `Severity(finding["severity"])` reconstructs a real
`Severity` enum member from its raw string value (`Severity(...)` used
this way — calling the enum class itself with a value — is Python's
built-in mechanism for looking up "which member has this exact value,"
the reverse operation of `.value`), needed because `finding["severity"]`
here is a plain string (having come from parsed JSON, Volume 1 §9.2, not
a live `Finding` object), but `SEVERITY_WEIGHT`'s dictionary keys are the
actual enum members.

```python
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platforms": [r["platform"] for r in reports],
        "reports": reports,
        "overall_summary": {
            "total": total, "clean": clean, "detected": detected, "errored": errored, "skipped": skipped,
            "raw_score": f"{clean}/{applicable}" if applicable else "0/0",
            "weighted_score": round(overall_weighted, 2),
        },
    }
```

The aggregate result bundles the *original, unmodified* per-platform
reports (`"reports": reports`) alongside one new `overall_summary` block
computed across all of them combined — so nothing from the individual
reports is lost or flattened away; a consumer can drill into any single
platform's full detail, or read just the combined top-line numbers.

```python
def render_html(aggregate: dict) -> str:
    parts: list[str] = [_HTML_HEAD, _summary_block(aggregate)]
    for report in aggregate["reports"]:
        parts.append(_platform_block(report))
    parts.append("</body></html>")
    return "\n".join(parts)
```

`render_html` builds a complete, self-contained HTML document as one big
string, purely through Python string manipulation and f-strings (Volume
1, §4.4) — no external templating library or web framework involved at
all, deliberately (consistent with the earlier "no external dependencies"
principle from §3.3). It's built up piece by piece — a fixed HTML/CSS
header (`_HTML_HEAD`, a big triple-quoted string constant defined near the
bottom of the file, containing an inline `<style>` block so the resulting
file needs no separate CSS file to look right), one summary block, then
one block per platform report — and finally joined together with
newlines.

```python
def _finding_row(f: dict) -> str:
    status_color = _STATUS_COLOR.get(f["status"], "#000")
    sev_color = _SEVERITY_COLOR.get(f["severity"], "#000")
    evidence = _stringify_evidence(f.get("evidence"))
    remediation = f.get("remediation") or f.get("error_detail") or "&mdash;"
    return (
        "      <tr>"
        f'<td><span class="pill" style="background:{status_color}">{html.escape(f["status"])}</span></td>'
        ...
        "</tr>"
    )
```

`html.escape(...)` (from Python's built-in `html` module) is used on
*every* piece of text being embedded into the generated page — this
matters for a real, important reason beyond just "correctness": any of
this text ultimately originates from a check's own output, which in turn
can include raw system data (a hostname, a file path, a registry value) —
data this program does not fully control the contents of. If that raw
text happened to contain characters with special meaning in HTML (like
`<` or `&`), and it were inserted into the page *unescaped*, it could
corrupt the page's structure or, in a worse case, allow **script
injection** (a real, well-known category of web security vulnerability
called **XSS**, "Cross-Site Scripting," where attacker-controlled text
ends up being interpreted as active HTML/JavaScript instead of inert
display text). `html.escape()` converts those special characters into
their safe, literal display equivalents (e.g. `<` becomes `&lt;`),
guaranteeing the generated report always displays as plain data, never as
active markup — a small but genuinely important defensive-programming
detail, applied consistently everywhere text flows into this generated
HTML.

`remediation = f.get("remediation") or f.get("error_detail") or "&mdash;"`
— chained `or` (Volume 1, §4.5's "truthiness" idea) picks the first
non-empty value among three options: prefer `remediation` if present,
otherwise fall back to `error_detail`, otherwise fall back to a plain
em-dash HTML entity (`&mdash;`, meaning "—") as a final "nothing to show
here" placeholder.

### 3.6 `text_format.py` — human-readable colored terminal output

**File:** `common/python/hydra_common/text_format.py`

This is what a user actually sees by default when running
`hydra test <platform>` (without `--json`) — HYDRA's primary,
CLI-native output format (Volume 1, §18.6 covered CLI design principles;
this module is where that philosophy is realized concretely).

```python
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_COLOR = {
    "clean": "\033[32m",  # green
    "detected": "\033[31m",  # red
    ...
}
```

These strings are **ANSI escape codes** — a decades-old, still
universally supported convention where a terminal recognizes certain
special byte sequences (starting with the character `\033`, the ASCII
"escape" character) as *formatting commands* rather than literal text to
display: `\033[32m` means "switch to green text," `\033[0m` means "reset
back to default formatting," and so on. Printing these specific byte
sequences interleaved with ordinary text is the entire mechanism behind
colored/bold terminal output — no special library is needed; it's a
convention nearly every terminal emulator understands natively.

```python
def supports_color(stream: Any = None) -> bool:
    stream = stream or sys.stdout
    return hasattr(stream, "isatty") and stream.isatty()
```

Not every place a program's output goes is an interactive terminal a
human is directly looking at — output might be redirected into a file, or
piped into another program (Volume 1, §5.3) — and printing raw ANSI
escape codes into a *file* would leave ugly, literal `\033[32m` garbage
text sitting in it, since nothing is there to interpret those bytes as
color commands. `stream.isatty()` is the standard, universal way to ask
"is this output destination actually an interactive terminal?" — and this
function uses that check to decide, automatically, whether color codes
should be emitted at all. `hasattr(stream, "isatty")` (checking the
method exists *before* calling it) is a small defensive touch, for
compatibility with any lower-level compatibility-shim stream object that
might not implement `isatty` at all.

```python
def render_platform_text(report: dict, *, use_color: bool | None = None, verbose: bool = False) -> str:
    if use_color is None:
        use_color = supports_color()

    s = report["summary"]
    lines: list[str] = []
    lines.append(f"{_BOLD}HYDRA -- {report['platform'].capitalize()} Sandbox-Evasion Self-Test{_RESET}")
    ...
    lines.append(
        f"Score: {_BOLD}{s['raw_score']}{_RESET} clean (applicable checks)"
        f"    Weighted: {_BOLD}{s['weighted_score']}/100{_RESET}"
    )
```

`use_color: bool | None = None` — three-way logic (Volume 1, §4.3's union
types): `None` means "auto-detect" (the default, calling `supports_color()`
above), while an explicit `True`/`False` overrides the auto-detection
entirely — this is exactly what the CLI's `--no-color` flag maps to
(Chapter 15 shows the exact wiring). The function builds its entire
output as a Python `list` of individual text lines first, appending one
line at a time, and only joins them into one final string (`"\n".join(...)`)
right at the very end — a common, efficient pattern for building up
multi-line text, since repeatedly concatenating (`+=`) onto one big string
directly is comparatively wasteful in Python (each `+=` on a string
creates an entirely new string object, since strings are immutable —
Volume 1, §3.2/§3.8 — so accumulating into a list and joining once at the
end avoids that repeated-copying cost).

```python
    findings = _sorted_findings(report["findings"])
    shown = findings if verbose else [f for f in findings if f["status"] in ("detected", "error")]

    if shown:
        lines.append(f"{_BOLD}{'STATUS':10} {'SEVERITY':9} {'CATEGORY':24} CHECK{_RESET}")
        for f in shown:
            status = _c(f["status"].upper().ljust(10), f["status"], use_color)
            ...
```

`shown = findings if verbose else [...]` — a **conditional expression**
(Python's "ternary" one-line if/else, `value_if_true if condition else
value_if_false`) implements exactly the behavior the function's own
docstring describes: in the default, non-verbose mode, only `detected`
and `error` findings are actually listed in detail — a long scroll of
"clean, clean, clean, ..." lines would be pure noise for the common case
of "did anything actually go wrong," so they're deliberately suppressed
(though still *counted* in the summary line above) unless `--verbose` is
explicitly requested. `f["status"].upper().ljust(10)` chains three string
operations (Volume 1, §4.4): `.upper()` converts to uppercase (`"detected"`
→ `"DETECTED"`), and `.ljust(10)` left-justifies/pads the result with
trailing spaces out to exactly 10 characters wide — producing the neat,
aligned column layout you see in the actual terminal output, purely
through careful manual string padding, with no external table-formatting
library involved at all.

`_sorted_findings` (defined just above, not shown in full here) sorts
findings so the most important ones surface first — `detected` before
`error` before `skipped` before `clean`, and within each status group,
`critical` severity before `high` before `medium`/`low`/`info` — via a
sort key built from two small lookup dictionaries (`_STATUS_RANK`,
`_SEVERITY_ORDER`), the same general pattern used again, independently,
in `report.py`'s HTML renderer (§3.5) — deliberately duplicated rather
than shared, since these two output formats' exact sort/display logic are
allowed to (and eventually might) diverge slightly, and a shared
dependency between "plain-text CLI renderer" and "HTML report renderer"
would be a slightly awkward, unnecessary coupling between two genuinely
independent output formats.

### 3.7 `__init__.py` — the package's public interface

**File:** `common/python/hydra_common/__init__.py`

```python
from .finding_factory import FindingFactory
from .models import Category, Finding, PlatformReport, Severity, Status
from .scoring import score_report
from .text_format import render_platform_text

__all__ = [
    "Category", "Finding", "FindingFactory", "PlatformReport",
    "Severity", "Status", "render_platform_text", "score_report",
]

__version__ = "0.1.0"
```

This file is what makes `hydra_common` usable as `import hydra_common` /
`from hydra_common import FindingFactory` (Volume 1, §4.9) from anywhere
else in the project, rather than callers needing to know and write out
the deeper, real internal path (`from hydra_common.finding_factory import
FindingFactory`) every time. It deliberately re-exports only a curated
subset of names — the ones every check-module author actually needs day
to day — leaving things like the internal `validate_report`/HTML-renderer
functions reachable only via their own specific submodule
(`from hydra_common.validation import validate_report`), signaling "this
is a more specialized, less frequently needed piece of the library."
`__all__` is a special, Python-recognized variable name that explicitly
declares a module's public interface — among other effects, it controls
exactly what `from hydra_common import *` (a wildcard import, generally
discouraged in most real code, but sometimes used in quick interactive
exploration) would actually bring in.

## Chapter 4: `pyproject.toml` and Packaging, Explained

**File:** `pyproject.toml`

`pyproject.toml` is the modern, standardized configuration file Python
projects use to describe themselves — what the project is called, what it
depends on, how it should be built/installed, and configuration for
various development tools, all in one place, using the **TOML** format (a
simple, human-readable configuration-file format — `.toml` — broadly
similar in spirit to JSON, Volume 1 §9.1, but designed specifically to be
pleasant to hand-edit as a config file, with sections marked by
`[bracketed.names]` rather than nested braces).

```toml
[project]
name = "hydra"
version = "0.1.0"
description = "HYDRA: cross-platform sandbox-evasion self-test suite for CHIMERA (Windows, Linux, Android)"
readme = "README.md"
requires-python = ">=3.10"
license = { text = "MIT" }
dependencies = []
```

`[project]` is the standardized core metadata block. `dependencies = []`
— an empty list — states explicitly, formally, that HYDRA has *zero*
required third-party packages (the same "stdlib-only" principle from
§3.3, now declared at the project-configuration level, not just as a
docstring comment). `requires-python = ">=3.10"` declares the minimum
Python version this project needs (Volume 1's type-hint syntax like
`str | None`, §4.3, specifically requires Python 3.10 or newer to work
without extra `from __future__ import annotations` workarounds in every
single file — this version floor and that import statement, seen in every
module, are directly related).

```toml
[project.optional-dependencies]
dev = ["pytest>=7", "black", "isort", "ruff"]
```

Unlike `dependencies` (needed just to *run* HYDRA), `[project.optional-
dependencies]` declares packages only needed for *development* —
`pytest` (Volume 1, §18.1), `black`/`isort`/`ruff` (Volume 1, §18.5).
Installed on demand with `pip install -e ".[dev]"` (the `[dev]` suffix
selects this specific optional group) — someone who only wants to *run*
HYDRA, not develop it, never needs to install any of these four packages
at all.

```toml
[project.scripts]
hydra = "hydra_cli.__main__:main"
```

This is the specific configuration that makes the plain `hydra` command
(Chapter 15) exist at all, system-wide, after installation — it tells
Python's packaging tooling "generate a small executable script named
`hydra`, and have it import the `main` function from
`hydra_cli.__main__` and call it" (this is called an **entry point**).
This is precisely why `cli/hydra_cli/__main__.py`'s `main()` function
(Chapter 15) has the exact structure it does — this line is what actually
wires that function up to a real, typeable terminal command.

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools]
package-dir = { "hydra_common" = "common/python/hydra_common", "hydra_linux" = "agents/linux/hydra_linux", "hydra_android" = "agents/android/hydra_android", "hydra_cli" = "cli/hydra_cli" }
packages = ["hydra_common", "hydra_linux", "hydra_android", "hydra_cli"]
```

`[build-system]` declares which tool actually performs the "build/
install this project" process — **setuptools**, one of the oldest and
most widely used Python packaging tools. The `[tool.setuptools]`
`package-dir` mapping is the single line that makes this project's
somewhat unusual repository layout (Chapter 1) actually work as an
installable Python package: by default, Python packaging tools expect
every package to live directly under one common root folder — but HYDRA's
real layout deliberately spreads its four Python packages across
`common/python/`, `agents/linux/`, `agents/android/`, and `cli/`, for the
organizational reasons Chapter 1 explained (grouping by platform/
component, not flattening everything Python-related into one folder just
because it's all Python). This mapping explicitly tells setuptools "when
you see the *import name* `hydra_common`, its actual files live over
here, at this specific different path" — one entry per package, resolving
the mismatch between "how the project is organized for humans reading it"
and "the flat namespace Python's own import system expects."

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.black]
line-length = 110
target-version = ["py310"]

[tool.isort]
profile = "black"
line_length = 110

[tool.ruff]
line-length = 110
```

The remaining blocks configure the development tools from §3.5/Volume 1
§18.5 directly inside this same one file, rather than each tool needing
its own separate configuration file scattered elsewhere in the repo —
another small piece of "one file, one source of truth" design philosophy
this project applies consistently. `testpaths = ["tests"]` tells `pytest`
where to look for test files by default, so simply running `pytest` from
the repository root (with no further arguments) finds everything.
`line-length = 110` is set identically for `black`, `isort`, and `ruff` —
kept in sync deliberately, since a formatter and a linter disagreeing
about the "correct" line length would otherwise produce contradictory
demands on the same code. `profile = "black"` tells `isort` to format
imports in a style specifically compatible with `black`'s own output
conventions, so running both tools back-to-back never results in one
undoing the other's work.

## Chapter 5: The Linux Agent, Part 1: The Native C Helper

### 5.1 `Makefile`

**File:** `agents/linux/native/Makefile`

```makefile
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
TARGET  := cpuid_rdtsc

.PHONY: all clean
all: $(TARGET)

$(TARGET): cpuid_rdtsc.c
	$(CC) $(CFLAGS) -o $(TARGET) cpuid_rdtsc.c

clean:
	rm -f $(TARGET)
```

`CC ?= cc` — the `?=` operator (Makefile syntax, distinct from a plain
`=`) means "set this variable to `cc` *only if it isn't already set*" —
so a user (or the Python code that invokes `make`) can override which
compiler to use by setting the `CC` environment variable beforehand,
while `cc` (a name virtually every Unix-like system provides as an alias
for whatever the system's default C compiler actually is — often `gcc` or
`clang` underneath) serves as a sensible universal default. `CFLAGS`
similarly defaults to a specific set of compiler flags: `-O2` (a
moderate, standard optimization level — Volume 1, §7.3 covered
compilation; `-O2` asks the compiler to produce reasonably fast code
without excessive build-time cost), `-Wall -Wextra` (enable a broad set of
compiler warnings — extra diagnostic messages about code that compiles
successfully but might be subtly wrong, deliberately turned on to catch
mistakes early rather than staying silent about them), and `-std=c11`
(target the C11 language standard specifically, a fixed, well-defined
version of the C language specification, ensuring consistent behavior
across different compilers/systems rather than depending on whichever
default standard version a given compiler happens to assume).

`$(TARGET): cpuid_rdtsc.c` declares a **build rule**: "the file
`cpuid_rdtsc` (the `$(TARGET)` variable, defined above) depends on
`cpuid_rdtsc.c`," and the indented line right below it (which, in a real
Makefile, must be indented with an actual **tab** character, not spaces —
a famously easy-to-get-wrong Makefile quirk) is the exact shell command
`make` runs to actually produce that target from its dependency:
`cc -O2 -Wall -Wextra -std=c11 -o cpuid_rdtsc cpuid_rdtsc.c`. `make`'s own
built-in logic automatically skips rebuilding if `cpuid_rdtsc` already
exists and is *newer* than `cpuid_rdtsc.c` (comparing file modification
timestamps) — this is `make`'s entire reason for existing: avoid
redundant recompilation, rebuilding only what's actually changed.
`.PHONY: all clean` marks `all` and `clean` as **phony targets** — a
Makefile convention meaning "these target names don't correspond to real
output files; always run their recipe when asked, regardless of whether a
file with that exact name happens to already exist in the directory"
(without this, if a stray file literally named `clean` ever existed in
this folder, `make clean` might do nothing at all, since `make` would
otherwise think that "target" was already "up to date").

### 5.2 `cpuid_rdtsc.c`

**File:** `agents/linux/native/cpuid_rdtsc.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ERR_USAGE 1
#define ERR_NOT_X86 2
```

`#include` lines pull in C's own standard library headers (Volume 1,
§7.7): `stdio.h` for `printf`/`fprintf`, `stdlib.h` for `malloc`/`free`/
`strtoul`/`strtol`, `string.h` for `strcmp`. `#define` (Volume 1, §7.8
introduced the C preprocessor) creates named constants purely as text
substitution — every later occurrence of `ERR_USAGE` in the file is
literally replaced with `1` before real compilation even begins; this is
used here purely for readability (so the rest of the code can say
`return ERR_USAGE;` instead of the less self-explanatory `return 1;`),
matching the specific exit-code convention (Volume 1, §5.5) this whole
project relies on for communicating outcomes back to the calling Python
code.

```c
#if defined(__x86_64__) || defined(__i386__)

#include <stdint.h>

static void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t out[4]) {
    __asm__ volatile("cpuid"
                      : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3])
                      : "a"(leaf), "c"(subleaf));
}
```

This is the exact architecture guard from Volume 1, §7.8: everything
between `#if defined(__x86_64__) || defined(__i386__)` and the matching
`#else` (further down) only exists — is only even *seen by the
compiler* — when building on x86 hardware. `uint32_t`/`uint64_t` (from
`<stdint.h>`) are precisely-sized integer types — "an unsigned integer,
*guaranteed* to be exactly 32/64 bits, on every platform" — a more
precise, portable choice than plain `int` (whose exact size, while
practically always 32 bits on modern systems, is not technically
guaranteed by the C standard itself), and an exact match for the CPU
register sizes (Volume 1, §10.2) this code is directly manipulating.

The `cpuid` function's body is the **inline assembly** (Volume 1, §7.6)
that actually issues the real `CPUID` instruction:
- `__asm__ volatile("cpuid" ...)` — `__asm__` (or its shorter alias
  `asm`) is the compiler-specific keyword for embedding raw assembly;
  `volatile` tells the compiler "do not optimize this away or reorder it
  relative to surrounding code, even if it looks like it has no visible
  effect" — necessary here because, from the compiler's own point of
  view, executing `cpuid` genuinely looks like it *could* be removed or
  reordered without consequence (it doesn't obviously read or write any C
  variable the compiler can see, since its real effects are entirely in
  CPU registers) — `volatile` overrides that assumption explicitly.
- `"cpuid"` is the literal assembly instruction being embedded — just the
  bare instruction name, taking its inputs and leaving its outputs
  entirely in specific, fixed CPU registers, exactly as Volume 1 §10.3
  described.
- `: "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3])` is the
  **output operand list** — GCC/Clang inline-assembly syntax that says
  "after this instruction runs, take whatever ends up in register `a`
  (i.e. `EAX`) and store it into `out[0]`," and likewise `b`→`out[1]`
  (`EBX`), `c`→`out[2]` (`ECX`), `d`→`out[3]` (`EDX`) — the `=` prefix
  means "this is a write-only output"; the single letters `a`/`b`/`c`/`d`
  are the compiler's own shorthand names for the `EAX`/`EBX`/`ECX`/`EDX`
  registers specifically.
- `: "a"(leaf), "c"(subleaf)` is the **input operand list** — "before
  running this instruction, put the C variable `leaf` into register `a`
  (`EAX`) and `subleaf` into register `c` (`ECX`)" — matching exactly how
  Volume 1 §10.3 described `CPUID`'s calling convention: you put the leaf
  number into `EAX` (and, for some leaves, a sub-leaf number into `ECX`)
  *before* executing the instruction, and it overwrites all four
  registers with its answer.

This one function is, quite literally, the single lowest-level piece of
the entire HYDRA project — every CPUID-based check on Linux, no matter
how many layers of Python wrap around it, ultimately bottoms out at these
four lines of inline assembly.

```c
static uint64_t rdtsc_now(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
```

`RDTSC` (Volume 1, §10.4) is a *64-bit* value, but returned split across
*two* separate 32-bit registers — `EDX` holds the high (more significant)
32 bits, `EAX` holds the low 32 bits (this specific split is simply how
the x86 instruction is architecturally defined to behave, not a HYDRA
design choice). `((uint64_t)hi << 32) | lo` reassembles the full 64-bit
value: `(uint64_t)hi` first *widens* `hi` from 32 bits to 64 bits (a
**cast**, Volume 1 §3.2's type concept applied explicitly — without this
cast, the following left-shift could overflow/misbehave since `hi` alone
is only a 32-bit value to begin with), `<< 32` is a **bit-shift**
operation moving those bits 32 positions to the left (into the *upper*
half of the 64-bit result — conceptually the same operation as multiplying
by 2³², just phrased in terms of raw bit positions instead of arithmetic,
which is the natural, idiomatic way to think about it at this level), and
`| lo` (bitwise OR) merges in the lower 32 bits, completing the
reassembly into one genuine 64-bit cycle count.

```c
static int cmd_rdtsc_jitter(int argc, char **argv) {
    if (argc != 3) return ERR_USAGE;
    long n = strtol(argv[2], NULL, 10);
    if (n < 1) n = 1;
    if (n > 1000000) n = 1000000;

    uint64_t *deltas = malloc((size_t)n * sizeof(uint64_t));
    if (!deltas) return ERR_USAGE;

    uint32_t junk[4];
    for (long i = 0; i < n; i++) {
        uint64_t t0 = rdtsc_now();
        cpuid(0, 0, junk); /* leaf 0: always forces a VM exit under KVM */
        uint64_t t1 = rdtsc_now();
        deltas[i] = t1 - t0;
    }

    qsort(deltas, (size_t)n, sizeof(uint64_t), cmp_u64);
    uint64_t min = deltas[0];
    uint64_t max = deltas[n - 1];
    uint64_t median = deltas[n / 2];
    double sum = 0;
    for (long i = 0; i < n; i++) sum += (double)deltas[i];
    double mean = sum / (double)n;

    printf("min=%llu median=%llu mean=%.2f max=%llu n=%ld\n", ...);
    free(deltas);
    return 0;
}
```

This is the exact timing-jitter measurement technique Volume 1 §10.4
described conceptually, now as real, complete code: `argv[2]` (command-
line arguments, Volume 1 §5.3 — `argv[0]` is always the program's own
name, `argv[1]` is the subcommand `"rdtsc_jitter"`, `argv[2]` is the
requested iteration count) is parsed from text into a number with
`strtol` (string-to-long), then clamped between 1 and 1,000,000 (a safety
bound, preventing an absurdly large or negative iteration count from
requesting an enormous or nonsensical memory allocation just below).
`malloc((size_t)n * sizeof(uint64_t))` (Volume 1, §7.4 — manual memory
allocation, requesting a contiguous block big enough for `n` separate
64-bit values) followed immediately by `if (!deltas) return ERR_USAGE;`
is the required, disciplined C pattern for handling allocation failure:
`malloc` returns a special value called a **null pointer** if the
requested memory genuinely couldn't be allocated (e.g. the system is out
of memory), and dereferencing (using) a null pointer is exactly the kind
of memory-safety mistake Volume 1 §7.4 warned crashes a C program — so
this check must come immediately after every `malloc` call, before that
memory is ever actually used.

The core loop is precisely "read the timestamp counter, execute `CPUID`
(guaranteed to force an expensive VM exit under KVM — the comment states
this explicitly), read the timestamp counter again, record the
difference" — repeated `n` times, storing every individual measurement.
`qsort` (a standard C library sorting function, taking a raw memory
buffer, an element count, an element size, and a comparison function
pointer — `cmp_u64`, defined just above this function in the real source,
not shown here) sorts the collected deltas in place, after which the
minimum, maximum, and median are all trivially the first element, last
element, and middle element of the now-sorted array respectively — no
separate min/max/median-finding logic needed once the array is sorted.
`free(deltas)` releases the manually allocated memory (Volume 1, §7.4 —
in C, unlike Python, memory obtained with `malloc` is *never*
automatically reclaimed; the programmer must explicitly call `free` on it
once it's no longer needed, or the memory is permanently "leaked" for the
remaining lifetime of the process — a small, single-purpose, short-lived
program like this one could technically get away without ever calling
`free` at all, since the OS reclaims *everything* the moment any process
exits regardless, but doing it properly anyway is good, disciplined
practice worth following as a default habit).

```c
#else /* not x86 */

static int cmd_cpuid(int argc, char **argv) {
    (void)argc;
    (void)argv;
    fprintf(stderr, "cpuid_rdtsc: CPUID is not available on this architecture\n");
    return ERR_NOT_X86;
}
```

The `#else` branch — compiled *instead of* the real implementation, only
on non-x86 hosts (Volume 1, §7.8/§10.1, e.g. an ARM-based analysis
workstation) — provides functions with the exact same names and
signatures, so the rest of the file (specifically `main()`, below) can
call `cmd_cpuid`/`cmd_rdtsc_jitter` uniformly, without needing to know or
care at compile time which actual implementation is present underneath.
`(void)argc; (void)argv;` is a small, common C idiom explicitly
discarding otherwise-unused function parameters — without it, the
compiler's `-Wextra` warning flag (from the `Makefile`, §5.1) would flag
`argc`/`argv` as "declared but never used," and this line silences that
specific, expected, harmless warning deliberately, rather than genuinely
suppressing all warnings globally (which would risk hiding real ones
elsewhere).

```c
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s cpuid <leaf_hex> <subleaf_hex> | rdtsc_jitter <iterations>\n", argv[0]);
        return ERR_USAGE;
    }
    if (strcmp(argv[1], "cpuid") == 0) return cmd_cpuid(argc, argv);
    if (strcmp(argv[1], "rdtsc_jitter") == 0) return cmd_rdtsc_jitter(argc, argv);
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return ERR_USAGE;
}
```

`main` is the mandatory entry point every C program must define (Volume
1, §3.4's "every program starts somewhere" idea, made explicit and
required by the C language itself) — the OS calls exactly this function,
with `argc`/`argv` already populated from however the program was
actually invoked, when the compiled binary is run. This specific `main`
does essentially nothing but dispatch: check that at least one argument
was given (`argc < 2`, since `argc` always includes the program's own
name as `argv[0]`), then compare `argv[1]` against the two known
subcommand names with `strcmp` (C's string-comparison function — unlike
Python's `==` operator, Volume 1 §4.4, C strings cannot be compared with
plain `==` at all, since that would just compare two raw memory
addresses rather than the actual text content; `strcmp` is the correct,
required tool for comparing what two C strings actually *say*, returning
`0` specifically when they're equal), routing to whichever specific
command function applies. **This entire `main` function is precisely
where the "usage error" exit code (`ERR_USAGE`, value `1`) that Volume
1's §7.3/Chapter 5.5 already told you about comes from** — and it is
exactly this same, deterministic "called with no arguments → exit code 1"
behavior that the Python `cpu.py` wrapper (Chapter 6, next) deliberately
exploits to detect a stale, wrong-platform binary, as a real bug case
study (Chapter 18) will cover in full.

## Chapter 6: The Linux Agent, Part 2: `cpu.py`, `signatures.py`, `utils.py`

### 6.1 `utils.py` — small, shared helpers

**File:** `agents/linux/hydra_linux/utils.py`

This is the smallest, most foundational file in the Linux agent — three
tiny functions every single check module (Chapter 7) ultimately builds on.

```python
def read_text(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
```

`Path(path).read_text(...)` (Volume 1, §4.10's `pathlib`) reads an entire
file's contents as a string in one call. `errors="replace"` handles a
subtle real-world issue: some of the files this function reads (like raw
`/sys`/`/proc` entries, Volume 1 §11.1) are not guaranteed to contain
valid, well-formed UTF-8 text — a hardware string could, in principle,
contain a stray invalid byte sequence — and `errors="replace"` tells
Python "if you hit an undecodable byte, substitute a placeholder
character and keep going" rather than raising a decoding exception and
aborting the whole read. `.strip()` removes leading/trailing whitespace
(most of these files end with a trailing newline character, which callers
essentially never want as part of the "value"). `except OSError:` catches
the whole family of filesystem-related failures (file doesn't exist, no
permission, path is actually a directory, etc. — `OSError` is Python's
broad built-in exception category for OS-level failures) and converts
every one of them uniformly into a plain `None` return — this is the
concrete, foundational instance of the "`None` means could-not-determine"
principle from Volume 1 §4.5/§18.3, propagating upward from literally the
lowest-level file-reading function in the whole agent.

```python
def any_signature_in(haystack: str | None, signatures: tuple[str, ...] | dict[str, str]) -> str | None:
    """Return the matched signature key, or None if haystack is empty/no match."""
    if not haystack:
        return None
    lowered = haystack.lower()
    for signature in signatures:
        if signature.lower() in lowered:
            return signature
    return None
```

This is the single function underlying nearly every signature-matching
check across the entire Linux agent (Chapter 7 will show it called
dozens of times). `haystack: str | None` — accepting `None` directly as
a valid input (rather than requiring every single caller to check for
`None` first) is a deliberate ergonomics choice: `if not haystack: return
None` handles both "genuinely `None`" and "an empty string" identically,
in one line, immediately at the top, so every caller downstream can just
pass whatever `read_text()` gave them straight through without an extra
guard clause of its own. `signatures: tuple[str, ...] | dict[str, str]` —
accepting *either* a tuple of plain strings *or* a dict (Volume 1, §3.3)
works because the `for signature in signatures:` loop, immediately below,
behaves identically either way: looping over a plain tuple yields its
string elements directly, while looping over a dict yields its *keys*
(Python dictionaries, by default, iterate over their keys when used
directly in a `for` loop) — and every one of this project's signature
dictionaries (Chapter 6.2, below) is deliberately structured with the
*match string itself* as the key and a human-readable label as the value,
specifically so this exact one function works unmodified against both
shapes of signature collection. `signature.lower() in lowered` performs a
case-insensitive substring search (Volume 1, §4.4's `in` operator on
strings) — lowercasing *both* sides explicitly (rather than assuming
signatures are already stored lowercase) makes the function robust
regardless of how a given signature list happens to be capitalized in its
own source.

```python
def run(cmd: list[str], timeout: float = 5.0) -> str | None:
    """Run a command and return stdout, or None if it fails/is unavailable."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout
```

This is the shared wrapper around Python's `subprocess.run` (Volume 1,
§4.10) used by every check that shells out to an external command (`ps`,
`fc-list`, `systemd-detect-virt`, `dpkg-query`, etc.) — `cmd: list[str]`
takes the command already split into its individual words (e.g.
`["ps", "-eo", "comm"]`), rather than one combined shell-syntax string,
which is both simpler to build programmatically and avoids an entire
category of shell-injection-style bugs that can arise from
naively interpolating dynamic values into a single shell command string
(a topic Volume 1 didn't cover in depth, but worth knowing: whenever
possible, passing a command as a pre-split list of arguments, as this
function does, is safer than building one shell command line by string
concatenation). `except (OSError, subprocess.SubprocessError):` — a
tuple of exception types after `except` catches *either* kind of failure
in one clause (`OSError` typically means "the command doesn't exist at
all on this system"; `subprocess.SubprocessError` covers other
subprocess-specific failures, including the `timeout` being exceeded) —
and, exactly like `read_text()` above, every failure path converges on a
single, uniform `None` return, letting every calling check treat "command
not found," "command timed out," and "command failed" all identically, as
one general "couldn't get an answer" outcome.

### 6.2 `signatures.py` — the known-vendor identity data

**File:** `agents/linux/hydra_linux/signatures.py`

This file contains no logic at all — it's pure data: the actual
hypervisor/VM-identity strings and values every Linux check compares
against, kept entirely separate from the *checks themselves* (Chapter 7),
which is a deliberate, meaningful separation of concerns (Volume 1, §3.6):
updating or extending HYDRA's known-signature coverage (e.g. adding a
newly-discovered VirtualBox DMI string) never requires touching any actual
check *logic* — only this one data file.

```python
DMI_VENDOR_SIGNATURES: tuple[str, ...] = (
    "qemu", "bochs", "kvm", "virtualbox", "vbox", "innotek", "vmware", "xen",
    "microsoft corporation",  # Hyper-V reports this as system-manufacturer
    "parallels", "bhyve", "amazon ec2",  # Nitro-based instances expose this in product_name
    "google compute engine",
    "ovmf",  # generic upstream OVMF firmware string, not vendor-specific but still a tell
    "seabios",
)
```

Every entry here corresponds directly to a real-world hypervisor covered
in Volume 1, Chapter 12 — `"qemu"`/`"kvm"`/`"seabios"`/`"ovmf"` all trace
back to the QEMU/KVM ecosystem (SeaBIOS and OVMF are two different
firmware implementations QEMU can use, §1.7's BIOS/UEFI distinction —
their presence is itself a tell, even without a more specific hypervisor
name attached); `"innotek"` is the original company name behind
VirtualBox (Sun Microsystems acquired Innotek, then Oracle acquired Sun —
but the string never got updated in VirtualBox's own default DMI data, so
it persists as a detection signature to this day); `"amazon ec2"`/
`"google compute engine"` are cloud-provider-specific strings that only
show up on their respective platforms' VM instances, connecting directly
to Volume 1 §12.8's cloud-VM discussion.

```python
DMI_FIELDS: tuple[str, ...] = (
    "sys_vendor", "product_name", "product_family", "product_sku", "product_version",
    "bios_vendor", "bios_version", "board_vendor", "board_name",
    "chassis_vendor", "chassis_asset_tag",
)
```

Eleven separate SMBIOS/DMI fields (Volume 1, §1.7/§11.1) — each one
independently checked (Chapter 7 shows exactly how) because, in practice,
different hypervisors are inconsistent about which specific fields they
bother to override with a plausible/spoofed value versus which they leave
at an obviously synthetic default — checking only one or two fields would
systematically miss real evidence sitting in whichever fields a
particular hypervisor happened not to bother spoofing.

```python
CPUID_HYPERVISOR_VENDORS: dict[str, str] = {
    "KVMKVMKVM\0\0\0": "KVM",
    "TCGTCGTCGTCG": "QEMU TCG (software emulation)",
    "VMwareVMware": "VMware",
    "XenVMMXenVMM": "Xen",
    "Microsoft Hv": "Hyper-V",
    "prl hyperv  ": "Parallels",
    "VBoxVBoxVBox": "VirtualBox (minimal vendor id)",
    "bhyve bhyve ": "bhyve",
}
```

This is the exact hypervisor-vendor-string lookup table from Volume 1
§10.3 — a `dict`, specifically, because each entry needs *two* pieces of
information (the raw 12-character CPUID string as the key, a human-
readable vendor name as the value), unlike the flat tuples above which
only need the bare signature text itself. Notice the literal `\0\0\0`
(null-byte escape sequences, Volume 1 §3.2's string-escapes concept) at
the end of the KVM entry — KVM's actual signature string is only 9
meaningful characters (`"KVMKVMKVM"`), padded out to the full 12-byte
field width with three trailing null bytes, and this dictionary key has
to match that padding *exactly*, byte-for-byte, or the lookup would fail
to match a genuine KVM guest.

```python
PCI_VIRT_VENDOR_IDS: dict[str, str] = {
    "0x1af4": "Red Hat / virtio",
    "0x1b36": "QEMU (red hat virtual PCI device)",
    "0x15ad": "VMware",
    "0x80ee": "VirtualBox (Oracle/innotek)",
    "0x5853": "Xen",
}
```

This is the PCI vendor-ID table (Volume 1, §1.6/§12.5) — hex strings
(Volume 1, §1.3) exactly as they appear when read directly out of
`/sys/bus/pci/devices/*/vendor` (Chapter 7 shows this file read directly).
`0x1af4` (Red Hat's VirtIO vendor ID) is the single most reliable entry
in this entire table, for the precise reason Volume 1 §12.5 explained: no
real, physical hardware vendor legitimately uses this ID at all — its
only possible meaning is "this is a VirtIO paravirtualized device," which
only exists inside a virtual machine.

The remaining tables in this file — `GUEST_KERNEL_MODULES`,
`BLOCK_DEVICE_VENDOR_SIGNATURES`, `MAC_OUI_SIGNATURES`,
`ANALYSIS_TOOL_PROCESS_NAMES`, `SUSPICIOUS_NAME_TOKENS`,
`SANDBOX_USERNAME_EXACT`, `GUEST_AGENT_PATHS`, `SANDBOX_FRAMEWORK_PATHS`,
and the single `CLOUD_METADATA_URL` string constant — follow the exact
same two patterns (a flat tuple of substring signatures, or a
key-to-vendor-label dict), and each one maps directly onto a specific
concept already covered in depth in Volume 1: kernel modules (§11.2),
block-device vendor strings (§12.5's disk-controller angle), MAC OUIs
(§19.2), the four detection-technique categories' concrete example lists
(Chapter 15), and the cloud metadata endpoint (§12.8). Chapter 7 shows
each one consumed by its corresponding check function.

### 6.3 `cpu.py` — the Python wrapper around the native helper

**File:** `agents/linux/hydra_linux/cpu.py`

This module is the bridge between the Python agent and the compiled C
binary from Chapter 5 — every function in it either builds/locates that
binary, or shells out to it and parses its plain-text output back into
structured Python data.

```python
_NATIVE_DIR = Path(__file__).resolve().parent.parent / "native"
_BINARY = _NATIVE_DIR / "cpuid_rdtsc"
_USAGE_EXIT_CODE = 1
_NOT_APPLICABLE_EXIT_CODE = 2
```

`Path(__file__)` — `__file__` is a special, automatically-populated
Python variable holding the current module's own file path;
`.resolve()` converts it to an absolute, fully-resolved path (following
any symbolic links, collapsing any `..` segments); `.parent.parent` walks
up two directory levels (from `hydra_linux/cpu.py` up to `hydra_linux/`,
then up again to `agents/linux/`); `/ "native"` (pathlib's overloaded `/`
operator, Volume 1 §4.10, joins path segments) arrives at
`agents/linux/native/` — the exact directory containing the `Makefile`
and `.c` source from Chapter 5, located this way (relative to *this
source file's own location on disk*, not relative to the current working
directory the agent happens to have been launched from) specifically so
this code works correctly no matter what directory a user happens to be
sitting in when they run the agent. `_USAGE_EXIT_CODE = 1` and
`_NOT_APPLICABLE_EXIT_CODE = 2` are the Python-side names for exactly the
same two exit-code constants (`ERR_USAGE`, `ERR_NOT_X86`) defined on the
C side in Chapter 5.2 — two independent constants, in two different
languages, that must be kept numerically in sync by convention (there is
no automatic mechanism enforcing this; if one side's number were ever
changed without updating the other, the whole scheme would silently
break — a real, if currently unexercised, coupling risk worth being aware
of).

```python
def _is_runnable(binary: Path) -> bool:
    """A stale binary compiled for a different OS/arch (e.g. reused from a
    bind-mounted repo across host and container, or across containers of
    different --platform) fails at exec() rather than at runtime -- that
    must not be mistaken for a legitimate build failure and silently
    swallowed. Calling with no args should deterministically hit the usage
    error path (exit 1); anything else means the binary doesn't belong here."""
    try:
        result = subprocess.run([str(binary)], capture_output=True, timeout=5, check=False)
    except OSError:
        return False
    return result.returncode == _USAGE_EXIT_CODE
```

This function exists entirely because of a real bug caught during
development — Chapter 18 covers the full story as a named case study, but
the mechanism itself is worth understanding precisely here: it runs the
compiled binary with **no arguments at all**, and checks that doing so
produces *exactly* exit code `1` — which, tracing back to Chapter 5.2's
`main()` function, is the deterministic, guaranteed behavior of a
correctly-built, architecture-appropriate `cpuid_rdtsc` binary when called
with `argc < 2`. If the binary is instead a stale leftover, compiled for
a *different* CPU architecture than the machine currently trying to run
it, attempting to execute it fails at a much lower level — the OS itself
refuses to even start running it, which Python surfaces as an `OSError`
(caught here, returning `False`) rather than as any kind of exit code at
all. This function is the load-bearing safety check that tells the
difference between "this binary is fine, just needs building" and "this
binary exists on disk but is fundamentally wrong for this machine and
must be discarded and rebuilt."

```python
def _ensure_built() -> Path | None:
    if _BINARY.exists() and not _is_runnable(_BINARY):
        _BINARY.unlink(missing_ok=True)
    if not _BINARY.exists():
        try:
            subprocess.run(["make", "-C", str(_NATIVE_DIR)], check=True, capture_output=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            return None
    return _BINARY if _BINARY.exists() and _is_runnable(_BINARY) else None
```

This is the function every public function in this module calls first,
implementing exactly the "build on first use, if needed" behavior Volume
1 §4.12/§7.3 described. Its logic, read as plain English: *if* a binary
already exists on disk *but* it fails the runnable-check above, delete it
(`.unlink(missing_ok=True)` — `missing_ok=True` means "don't raise an
error if it turns out the file was already gone by the time we get here,"
a small defensive touch against an unlikely race condition); *then*, if
no binary exists at all (either it never did, or it was just deleted
above), attempt to build one by running `make -C <native_dir>` (`-C`
tells `make` to operate as if it had been run from inside that specific
directory, without actually needing to `cd` there first) — and if that
build itself fails for any reason (`check=True` makes `subprocess.run`
raise an exception on a non-zero exit code, deliberately, so this
specific failure path is easy to catch in one `except` clause, unlike the
`check=False` pattern used almost everywhere else in this project — a
rare, deliberate exception to that general convention, chosen here
specifically because a build failure genuinely is exceptional, unlike
"a normal check found nothing"), return `None` immediately. The final
line only returns the binary's path if it both exists *and* independently
re-passes the exact same runnable-check one more time — guaranteeing that
by the time any *caller* of `_ensure_built()` receives a non-`None`
result, that binary is verified, freshly, to actually work correctly on
this exact machine, right now.

```python
def _run(*args: str) -> str | None:
    binary = _ensure_built()
    if binary is None:
        return None
    try:
        result = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode == _NOT_APPLICABLE_EXIT_CODE:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()
```

`def _run(*args: str) -> str | None:` — `*args` (Volume 1's function-
parameter concept, §3.4, extended with Python's "variable number of
arguments" syntax) lets this one function accept any number of trailing
command-line-argument strings, forwarded straight through to the actual
binary invocation (`[str(binary), *args]` — the `*` here, on the *calling*
side this time, unpacks the `args` tuple back out into individual list
elements). This function treats *three* distinct outcomes distinctly:
a genuine execution failure (`OSError`/`SubprocessError`, e.g. the binary
somehow still doesn't exist despite `_ensure_built()`'s best efforts) →
`None`; exit code `2` specifically (the "not applicable on this
architecture" signal from Chapter 5.2's `#else` branch) → also `None`
(deliberately treated identically to a hard failure from this function's
own point of view — it's the *caller*, one level up in `checks/
environment.py`, Chapter 7, that's responsible for turning "the primitive
is unavailable" into the specifically-worded `skipped` finding, rather
than this low-level wrapper needing to know or care about `Finding`
objects at all); and any other non-zero exit code → also `None` (a
generic "something else went wrong" catch-all). Only a clean `0` exit
returns the binary's actual stdout text, stripped of surrounding
whitespace.

```python
@dataclass(frozen=True)
class CpuidResult:
    eax: int
    ebx: int
    ecx: int
    edx: int

    @property
    def vendor_string(self) -> str:
        """Decode ebx/ecx/edx as an ASCII vendor string for the hypervisor
        signature leaf (0x40000000). Note this register order (EBX,ECX,EDX)
        is specific to the hypervisor leaf, per the QEMU/KVM signature
        convention -- it differs from leaf 0's vendor string, which uses
        EBX,EDX,ECX. Mixing the two up is an easy, silent-wrong-answer bug."""
        raw = self.ebx.to_bytes(4, "little") + self.ecx.to_bytes(4, "little") + self.edx.to_bytes(4, "little")
        return raw.decode("ascii", errors="replace")
```

`CpuidResult` is a small, frozen dataclass (Volume 1, §4.7) bundling the
four raw register values from one `CPUID` call — the Python-side
equivalent of the C `struct` from Volume 1 §7.5. `@property` (a Python
decorator, Volume 1 §4.7 introduced decorators generally) turns
`vendor_string` from an ordinary method (which you'd have to call as
`result.vendor_string()`) into something accessed like a plain attribute
(`result.vendor_string`, no parentheses) — appropriate here because
computing it has no side effects and conceptually *is* just a derived
piece of data belonging to the result, not an action being performed.

This is the exact register-order-sensitive decoding logic Volume 1 §10.3
and §10.5 walked through conceptually — now, here, is precisely where it
lives in real code, and precisely where the real historical bug (Chapter
18's case study) was caught and fixed. `self.ebx.to_bytes(4, "little")`
converts the raw 32-bit integer stored in `ebx` into 4 individual raw
bytes, in little-endian order (Volume 1, §10.5) — Python integers have no
inherent "byte representation" the way C's `struct` layout does
automatically; `.to_bytes(length, byteorder)` is the explicit, deliberate
Python method for producing one. The three resulting 4-byte chunks are
concatenated with `+` (Python's `bytes` objects support concatenation
with the same `+` operator as strings/lists) in the exact order
`ebx, ecx, edx` — matching the hypervisor leaf's specific convention, not
leaf 0's — before finally being decoded from raw bytes into a readable
text string with `.decode("ascii", errors="replace")` (mirroring
`read_text()`'s same defensive `errors="replace"` choice from §6.1, for
the same underlying reason: robustness against any byte that doesn't
happen to form valid text).

```python
def brand_string() -> str | None:
    chunks: list[bytes] = []
    for leaf in (0x80000002, 0x80000003, 0x80000004):
        result = cpuid(leaf)
        if result is None:
            return None
        chunks.append(
            result.eax.to_bytes(4, "little")
            + result.ebx.to_bytes(4, "little")
            + result.ecx.to_bytes(4, "little")
            + result.edx.to_bytes(4, "little")
        )
    raw = b"".join(chunks)
    return raw.decode("ascii", errors="replace").rstrip("\x00").strip()
```

This mirrors §10.3's third CPUID leaf group — notice the register order
used here is `eax, ebx, ecx, edx`, the *plain*, non-tricky order, deliberately
different from `vendor_string`'s `ebx, ecx, edx` order just above it — and
the function's own docstring (elided here for space, but present in the
real source) explicitly calls this difference out, precisely to prevent
a future reader from assuming the two functions ought to use the same
register order just because they're both "CPUID string decoding." Looping
over all three brand-string leaves (`0x80000002` through `0x80000004`)
and concatenating their results in order reconstructs the full, up-to-48-
character brand string. `.rstrip("\x00")` strips trailing null bytes (the
brand string is often shorter than the full 48-byte field it's stored in,
padded out with nulls, similar to the KVM vendor-string padding seen in
§6.2) before the final `.strip()` removes any remaining ordinary
whitespace.

## Chapter 7: The Linux Agent, Part 3: The Check Modules

Every check module in every agent (twelve files total across all three
platforms) follows the *exact same skeleton*. This chapter explains that
skeleton exhaustively, once, using `environment.py`'s first few checks as
the worked example — then, for the remaining checks in this file and
every other check module in the project, explains only what's genuinely
new about each one, trusting you to recognize the now-familiar shape.

### 7.1 The skeleton, explained in full

**File:** `agents/linux/hydra_linux/checks/environment.py`

```python
from hydra_common import FindingFactory
from hydra_common.models import Category, Finding, Platform, Severity

from .. import cpu, signatures, utils

_PLATFORM = Platform.LINUX
_CATEGORY = Category.ENVIRONMENT_ARTIFACT
_f = FindingFactory(category=_CATEGORY, platform=_PLATFORM)
```

`from .. import cpu, signatures, utils` — the double-dot (`..`) is
Python's **relative import** syntax (Volume 1, §4.9's import mechanism,
extended): a single dot would mean "from the current package"
(`hydra_linux.checks`), two dots means "from the parent package"
(`hydra_linux` itself) — reaching `cpu.py`, `signatures.py`, `utils.py`,
the three files from Chapter 6, which all live one directory level up
from this `checks/` folder. The three module-level constants — `_PLATFORM`,
`_CATEGORY`, and, built from both of them, `_f` (the module's one
`FindingFactory` instance, Chapter 3.4) — are created exactly *once*, when
this module is first imported, and every check function in the file
reuses this same `_f` instance rather than each constructing its own —
this is precisely the "bind the factory once per module" pattern Chapter
3.4 described.

```python
def check_cpuid_hypervisor_bit() -> Finding:
    check_id, name = "linux.env.cpuid_hypervisor_bit", "CPUID hypervisor-present bit"
    description = (
        "CPUID leaf 1, ECX bit 31 -- set by every mainstream hypervisor to advertise itself to the guest."
    )
    result = cpu.cpuid(1)
    if result is None:
        return _f.skipped(
            check_id, name, description, Severity.HIGH, "CPUID unavailable (non-x86 host or native helper failed to build)"
        )
    present = bool(result.ecx & (1 << 31))
    return _f.bool_check(
        check_id, name, description, Severity.CRITICAL,
        is_detected=present,
        evidence=f"ecx=0x{result.ecx:08x} bit31={'1' if present else '0'}",
        remediation="Set <kvm><hidden state='on'/></kvm> in the libvirt domain XML.",
    )
```

This is a complete, representative check function — every one of the
~37 Linux checks, ~30 Windows checks, and ~22 Android checks in this
project follows this identical five-part shape:

1. **Declare the check's identity**: a stable `check_id` (matching the
   schema's dotted-naming pattern from Chapter 2) and a short human
   `name`.
2. **Declare the `description`**: a fixed, static string explaining what
   the check does and why — written once, identically regardless of the
   outcome.
3. **Gather the raw data**: here, `cpu.cpuid(1)` (Chapter 6.3) — the one
   line that actually does the check's real "work."
4. **Handle "couldn't determine" first, and return early**: `if result is
   None:` — using `_f.skipped(...)` (Chapter 3.4), *before* attempting any
   further logic that would assume the data is actually present. This
   ordering (handle the failure case first, then proceed with the success
   case unindented afterward) is a common, deliberate style choice called
   *guard clauses* — avoiding deeply nested `if`/`else` blocks (Volume 1's
   coding-style rules explicitly discourage deep nesting) by exiting early
   whenever a precondition isn't met.
5. **Compute the actual verdict, and return `_f.bool_check(...)`**:
   `present = bool(result.ecx & (1 << 31))` is the exact bit-check from
   Volume 1 §10.3 in real code — `1 << 31` produces a number with only bit
   31 set (a **bit mask**), `result.ecx & (1 << 31)` (bitwise AND) isolates
   just that one bit from the full register value, and `bool(...)` converts
   the resulting nonzero-or-zero integer into a genuine `True`/`False`.
   The `evidence` f-string (`f"ecx=0x{result.ecx:08x} ..."`) uses a format
   specifier (`:08x`) inside the f-string's `{}` — `x` means "format as
   lowercase hexadecimal" (Volume 1, §1.3), `08` means "pad with leading
   zeros to at least 8 characters wide," producing a clean, fixed-width hex
   dump of the register's full raw value for a human analyst to inspect
   directly, alongside the plain-English `bit31=1`/`bit31=0` summary.

**Every single check function in this entire project is a variation on
exactly this five-step shape.** From here on, this document highlights
only what's genuinely different in each subsequent check.

### 7.2 The remaining `environment.py` checks — what's different

- **`_dmi_checks()`** loops over `signatures.DMI_FIELDS` (Chapter 6.2)
  and builds one `Finding` per field inside the loop, returning a `list`
  rather than a single `Finding` — the one function in this file that
  doesn't follow the single-check-per-function shape exactly, because
  eleven near-identical DMI checks are more maintainable expressed as one
  small loop over a data table than as eleven separately hand-written,
  nearly-duplicate functions.
- **`check_cpuid_hypervisor_vendor()`** calls `cpu.cpuid(0x40000000)` and
  looks up `result.vendor_string` (Chapter 6.3) against
  `signatures.CPUID_HYPERVISOR_VENDORS` with a plain dict `.get()` lookup
  (Volume 1, §4.6) — this is the exact check protected by the register-
  order regression test covered fully in Chapter 18.
- **`check_cpu_brand_string()`** calls `cpu.brand_string()` (Chapter 6.3)
  and runs it through `utils.any_signature_in()` (§6.1) against
  `signatures.CPU_BRAND_STRING_SIGNATURES`.
- **`check_pci_virtio_devices()`** is the first check to read the
  filesystem directly rather than going through `cpu.py`:
  `Path("/sys/bus/pci/devices").iterdir()` (Volume 1, §11.1) lists every
  PCI device directory, and for each one, `utils.read_text(str(device_dir
  / "vendor"))` reads that device's raw vendor-ID file, checked against
  `signatures.PCI_VIRT_VENDOR_IDS`. Note it builds a `hits: list[str] = []`
  and *accumulates evidence across every matching device* rather than
  stopping at the first match — because, unlike a single CPUID call, a
  system can have several suspicious PCI devices at once, and a complete
  evidence list is more useful to an analyst than just the first one
  found.
- **`check_guest_kernel_modules()`** reads `/proc/modules` (Volume 1,
  §11.1/§11.2) and checks each loaded module's name against
  `signatures.GUEST_KERNEL_MODULES` using `.startswith(prefix)` rather
  than a substring `in` check — because kernel module names are matched
  by *prefix* specifically (e.g. any module starting with `"vmw_"`), not
  by an arbitrary substring appearing anywhere in the name.
- **`check_systemd_detect_virt()`** is the first check to shell out to an
  external command (via `utils.run()`, §6.1) rather than reading a file
  directly — running the literal `systemd-detect-virt` binary (Volume 1,
  §11.3) and comparing its single-word text answer against the literal
  string `"none"`.
- **`check_low_core_count()` / `check_low_ram()` / `check_small_disk()`**
  are the three "suspiciously minimal hardware" checks (Volume 1, §15.1) —
  using `os.cpu_count()`, parsing `MemTotal:` out of `/proc/meminfo`'s raw
  text by hand (`line.split()[1]`, splitting the line on whitespace and
  taking the second word), and finding the *largest* value among every
  eligible entry in `/sys/block` (explicitly skipping loop/ram/CD-ROM
  pseudo-devices by name prefix) respectively.
- **`check_cloud_metadata_reachable()`** is the one check that performs
  real network I/O (Volume 1, §12.8/§19.3) — the only check in the entire
  Linux agent using `urllib.request` rather than reading a file or running
  a command, and the one place the deliberately-broad
  `except Exception:` pattern from Volume 1 §4.11 appears in this file,
  for exactly the reason explained there.

### 7.3 `timing.py` — the two timing checks

**File:** `agents/linux/hydra_linux/checks/timing.py`

```python
def check_uptime() -> Finding:
    ...
    uptime_seconds = float(text.split()[0])
    return _f.bool_check(..., is_detected=uptime_seconds < _LOW_UPTIME_SECONDS, ...)


def check_rdtsc_cpuid_jitter() -> Finding:
    jitter = cpu.rdtsc_cpuid_jitter()
    if jitter is None:
        return _f.skipped(..., "CPUID/RDTSC unavailable ...")
    cv = cpu.jitter_coefficient_of_variation(jitter)
    evidence = {
        "min_cycles": jitter.min_cycles, "median_cycles": jitter.median_cycles,
        "mean_cycles": round(jitter.mean_cycles, 2), "max_cycles": jitter.max_cycles,
        "samples": jitter.samples, "coefficient_of_variation": round(cv, 3),
    }
    is_detected = jitter.median_cycles > _JITTER_MEDIAN_THRESHOLD or cv > _JITTER_CV_THRESHOLD
    return _f.bool_check(..., is_detected=is_detected, evidence=evidence, ...)
```

`check_uptime()` reads `/proc/uptime` (Volume 1, §11.1) and parses just
the first whitespace-separated field (the file actually contains two
numbers — total uptime and total idle time — separated by a space; only
the first is needed here). `check_rdtsc_cpuid_jitter()` is the real
implementation of Volume 1's §10.4 timing-attack technique — notice its
`evidence` is a *dictionary*, not a plain string, unlike every check
you've seen so far — the schema (Chapter 2) explicitly allows `evidence`
to be an object precisely to support cases like this one, where several
related numbers (min/median/mean/max cycle counts, sample count, and a
computed "coefficient of variation" — Volume 1 §10.4's "how erratic are
the numbers" measure) are all part of one coherent result, better
presented together as structured data than flattened into one long,
harder-to-parse string. The detection condition itself,
`jitter.median_cycles > _JITTER_MEDIAN_THRESHOLD or cv >
_JITTER_CV_THRESHOLD`, combines *two* independent thresholds with `or`
— either a high absolute cycle count, *or* high erraticness/instability
alone, is suffient to flag detection — reflecting the real-world
observation (Volume 1, §10.4) that virtualization overhead shows up as
both slower *and* noisier timing, and either symptom alone is meaningful
evidence.

### 7.4 `behavioural.py` and `design.py` — what's different

**Files:** `agents/linux/hydra_linux/checks/behavioural.py`,
`agents/linux/hydra_linux/checks/design.py`

These two files implement Volume 1's Chapter 15.3/15.4 categories exactly
— `check_shell_history()` reads `~/.bash_history`/`~/.zsh_history` via
`Path.home()` (Volume 1, §4.10) and counts non-blank lines;
`check_aged_files()` uses `Path.rglob("*")` (a recursive glob — walking
every file under the home directory, Volume 1 §2.4's directory-tree
concept) checking each file's modification time
(`entry.stat().st_mtime`, a Unix timestamp — seconds since a fixed
reference point, January 1st 1970 — the universal, standard way Unix-like
systems represent a point in time internally) against a week-old
threshold, deliberately `break`-ing out of the loop early once enough
aged files have been found (`if aged >= _MIN_AGED_FILES: break` — an
efficiency choice: once the answer is already known to be "not fewer than
the threshold," there's no need to keep scanning every remaining file in
a potentially huge home directory).

`design.py`'s `check_suspicious_hostname_or_user()` is the one this
project's own regression tests (Chapter 16) directly exercise via
`monkeypatch` (Volume 1, §18.1) — it calls `socket.gethostname()` (Volume
1, §4.10) and reads the `USER`/`LOGNAME` environment variables (Volume 1,
§2.6), checking both independently against `signatures.SUSPICIOUS_NAME_TOKENS`.
`check_exact_sandbox_username()` is functionally almost identical but
checks *exact* equality (`username in signatures.SANDBOX_USERNAME_EXACT`,
a set/tuple membership test, not a substring search) against a
*separately maintained* list, `SANDBOX_USERNAME_EXACT` — precisely
because, as both this module's and Volume 1's (§15.4) comments explain,
substring-matching a short word like `"test"` would false-positive
constantly against ordinary real names, so this specific al-khaser-style
check deliberately requires the *entire* username to match, nothing more
or less.

### 7.5 `checks/__init__.py` — wiring the four category modules together

**File:** `agents/linux/hydra_linux/checks/__init__.py`

```python
from . import behavioural, design, environment, timing

CHECK_MODULES = (environment, timing, behavioural, design)

__all__ = ["CHECK_MODULES", "behavioural", "design", "environment", "timing"]
```

This is a small but important file: `CHECK_MODULES` is a tuple containing
the four *module objects themselves* (Volume 1, §4.9 — in Python, a
module, once imported, is itself a first-class value that can be stored
in a variable, put into a collection, and iterated over, just like any
other object) — this is precisely what lets `runner.py` (Chapter 8) run
every category with one small, generic loop
(`for module in CHECK_MODULES: findings.extend(module.run_all())`)
instead of needing four separate, hand-written, near-identical lines
calling each category module by name individually. Adding a hypothetical
fifth category to the whole project would require exactly one new line
here (Chapter 20 covers extending HYDRA this way in more depth).

## Chapter 8: The Linux Agent, Part 4: `runner.py`, `__main__.py`, Wiring It Together

### 8.1 `runner.py`

**File:** `agents/linux/hydra_linux/runner.py`

```python
def run_scan() -> PlatformReport:
    findings: list[Finding] = []
    for module in CHECK_MODULES:
        findings.extend(module.run_all())
    return PlatformReport(
        platform=Platform.LINUX,
        findings=tuple(findings),
        agent_metadata=PlatformReport.default_metadata(),
    )
```

This entire function is only seven lines, and it is the precise moment
every individual check function's output gets collected into one final
report. `findings: list[Finding] = []` starts with an ordinary *mutable*
list (Volume 1, §3.3/§3.8) — a deliberate, correct choice, *not* a
violation of this project's immutability principle: this list is purely
local, temporary scratch space that exists only for the brief duration of
this one function call, never shared with or exposed to any other code —
the moment it's done being built, it's converted into an immutable
`tuple(findings)` (Volume 1, §3.3) right as the final, truly-shared
`PlatformReport` object is constructed. This is the general, correct
pattern for working *with* immutable data structures without fighting
them: build up intermediate state with an ordinary mutable collection
during a function's own private work, then freeze it into an immutable
form at the exact moment it's handed off and becomes shared, longer-lived
data.

`module.run_all()` — this is where `CHECK_MODULES` (Chapter 7.5) actually
gets used: `for module in CHECK_MODULES:` loops over the four category
module objects, and `module.run_all()` calls each one's own `run_all()`
function (defined at the bottom of every check module, e.g.
`environment.py`'s `run_all()` from Chapter 7 — a small function whose
entire body is just a list literal calling every individual check
function in that module, in a fixed order, and returning the resulting
list of `Finding` objects) — `findings.extend(...)` (rather than
`.append(...)`) adds *all* the elements of that returned list
individually onto the running `findings` list, rather than nesting one
whole list inside another.

`agent_metadata=PlatformReport.default_metadata()` — this is exactly
where the static method from Chapter 3.1 gets called, populating the
report's metadata with the running host's own OS name/release/machine-
architecture strings, gathered once, at report-assembly time.

### 8.2 `__main__.py`

**File:** `agents/linux/hydra_linux/__main__.py`

The presence of a file literally named `__main__.py` inside the
`hydra_linux` package is what makes `python3 -m hydra_linux` (Volume 1,
§4.12) work at all — Python specifically looks for this exact filename
when run this way.

```python
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hydra_linux")
    parser.add_argument(
        "-o", "--output", type=str, default=None, help="write JSON report to this path instead of stdout"
    )
    args = parser.parse_args(argv)

    report = run_scan().to_dict()
    text = json.dumps(report, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Wrote report to {args.output}", file=sys.stderr)
    else:
        print(text)

    summary = report["summary"]
    print(
        f"HYDRA linux scan: {summary['raw_score']} clean, weighted {summary['weighted_score']}/100 "
        f"({summary['errored']} errored, {summary['skipped']} skipped)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

`argparse.ArgumentParser` (Volume 1, §4.10) builds the small command-line
interface for running this agent standalone — just one optional
`-o`/`--output` flag (Volume 1, §5.3's short/long flag convention).
`report = run_scan().to_dict()` is the entire pipeline from Chapters 7-8.1
condensed to one line: run every check, get back one `PlatformReport`
object, immediately convert it to a plain dict (Chapter 3.1's `to_dict()`,
Volume 1 §9.2) ready for JSON serialization. `json.dumps(report,
indent=2)` (Volume 1, §4.10/§9.2) — `indent=2` produces nicely
human-readable, multi-line, indented JSON rather than one dense unbroken
line, since this output is meant to be readable both by other programs
*and* directly by a human glancing at it.

The `if args.output: ... else: ...` branch is the exact stdout/stderr
discipline from Volume 1 §5.6: when writing to a file, the confirmation
message ("Wrote report to ...") goes to **stderr** via
`print(..., file=sys.stderr)`; when *no* output file was given, the
actual JSON report itself is what goes to **stdout** (a bare `print(text)`,
which defaults to stdout). The final summary line, printed unconditionally,
*also* goes to stderr — meaning that in both cases, **stdout contains
either nothing (file-output mode) or purely the raw JSON (no-file mode) —
never a mix of JSON and human status text** — which is exactly the
property that lets other programs (the CLI in Chapter 15, or a shell
pipeline) safely capture and parse this agent's stdout without any
special filtering.

`if __name__ == "__main__":` is a near-universal Python idiom (Volume 1
briefly touched module mechanics in §4.9-4.12, and this is the concrete
payoff): `__name__` is a special, automatically-set variable equal to
`"__main__"` specifically when a file is being run directly (as opposed
to being imported by some other module) — this guard ensures `main()` is
only actually *called* when this file is genuinely being executed as a
program, never as a side effect of some other code merely importing this
module for its functions/values. `raise SystemExit(main())` — `main()`
returns an integer exit code (`0` for success, matching Volume 1's §5.5
convention), and wrapping that return value in `SystemExit(...)` and
`raise`-ing it is the correct, standard way to make that number actually
become the process's real, observable exit code when the script finishes
running.

## Chapter 9: The Windows Agent, Part 1: `Hydra.Common.psm1` and `Signatures.ps1`

The Windows agent is a complete, independent reimplementation of
everything `hydra_common` (Chapter 3) provides — necessarily so, since
PowerShell cannot `import` a Python module (Chapter 1 already explained
why). This chapter shows exactly how each piece was rebuilt in PowerShell,
kept deliberately equivalent to its Python counterpart field-for-field and
formula-for-formula.

### 9.1 `Hydra.Common.psm1`

**File:** `agents/windows/common/Hydra.Common.psm1`

A `.psm1` file is a **PowerShell module** (Volume 1, §3.6's module
concept, PowerShell's specific file extension for it) — a collection of
related functions, loaded with `Import-Module` (you'll see this in
Chapter 11).

```powershell
$Script:SeverityWeight = @{
    info     = 0.05
    low      = 0.15
    medium   = 0.35
    high     = 0.65
    critical = 1.0
}
```

`$Script:SeverityWeight` — the `Script:` prefix is a PowerShell **scope
modifier**, making this variable visible to every function defined later
in this same script/module, rather than being local to just one function
call (PowerShell, unlike Python, requires this kind of explicit scope
annotation for a variable meant to be shared module-wide this way). `@{
... }` is PowerShell's hashtable (dictionary, Volume 1 §3.3) literal
syntax — this is the exact `SEVERITY_WEIGHT` table from Chapter 3.2,
re-expressed in PowerShell, with identical numeric weights (kept
numerically synchronized with the Python version entirely by convention
and careful cross-checking — Chapter 18 discusses this kind of
"synchronized twin implementation" risk as a general lesson).

```powershell
function New-HydraFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('environment_artifact', 'timing', 'behavioural_interaction', 'design_specific')][string]$Category,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][ValidateSet('clean', 'detected', 'error', 'skipped')][string]$Status,
        [Parameter(Mandatory)][ValidateSet('info', 'low', 'medium', 'high', 'critical')][string]$Severity,
        $Evidence = $null,
        $Remediation = $null,
        $ErrorDetail = $null
    )
    if ($Status -eq 'error' -and [string]::IsNullOrEmpty($ErrorDetail)) {
        throw "New-HydraFinding: status 'error' requires -ErrorDetail (check id: $Id)"
    }
    [PSCustomObject]@{
        id            = $Id
        category      = $Category
        platform      = 'windows'
        ...
    }
}
```

This is the PowerShell equivalent of Python's `Finding` dataclass (Chapter
3.1) — but notice a genuinely different design choice: rather than a
frozen dataclass with named fields, this is a plain **function** that
*constructs and returns* a `[PSCustomObject]` (PowerShell's built-in
generic "object with named properties" type, Volume 1 §6.1's
"everything is an object" principle) — PowerShell has no exact equivalent
of Python's `@dataclass(frozen=True)` construct that would be idiomatic
to reach for here, so a constructor *function* returning a fresh, never-
mutated-afterward object achieves the same practical immutability
*outcome* (nothing in this codebase ever modifies a finding object after
`New-HydraFinding` returns it) through discipline and convention, rather
than a language-enforced guarantee.

`[ValidateSet('environment_artifact', ...)]` is PowerShell's own built-in
mechanism for exactly Volume 1 §4.8's enum concept — a parameter
attribute that makes PowerShell itself reject, immediately and loudly, any
call passing a `-Category` value outside this fixed list, functioning as
a genuine, enforced runtime guarantee (unlike Python's type hints, §4.3,
which are unenforced documentation only) — an interesting, worthwhile
cross-language contrast: PowerShell's parameter-validation attributes are
*stricter*, by default, than Python's own type-hint system.

`$Evidence = $null` (and `$Remediation`, `$ErrorDetail` similarly) —
these three parameters are deliberately declared with **no** explicit
`[string]` or other type constraint. This is precisely the fix for the
real bug documented in Volume 1 §6.3 and covered fully as a case study in
Chapter 18: declaring `[string]$Remediation = $null` would have PowerShell
silently *coerce* an explicitly-passed `$null` into an empty string `""`
the instant the parameter is bound — corrupting the crucial distinction
between "there is genuinely no remediation because this is a clean
result" (`$null`, matching the JSON schema's `null`, Chapter 2) and "there
is remediation text that just happens to be blank" (an empty string,
which would fail schema validation on the Python side, since the schema
declares `remediation` as `["string", "null"]`, deliberately *not*
including empty-string as some kind of third meaning). The comment
directly above this exact line in the real source (elided in this
excerpt for brevity, quoted here) says plainly: *"Deliberately untyped
($null, not [string]): a typed [string] parameter coerces an omitted/$null
argument to "" in PowerShell, which would silently drift from the schema's
`null` for an absent remediation/error_detail rather than round-tripping
it faithfully."*

```powershell
function Get-HydraSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][array]$Findings)

    $total = $Findings.Count
    $clean = @($Findings | Where-Object { $_.status -eq 'clean' }).Count
    ...
    $applicable = $clean + $detected
    $rawScore = if ($applicable -gt 0) { "$clean/$applicable" } else { '0/0' }
    if ($applicable -eq 0) { $weighted = 100.0 }
    else {
        $penalty = 0.0
        foreach ($finding in $Findings) {
            if ($finding.status -eq 'detected') { $penalty += $Script:SeverityWeight[$finding.severity] }
        }
        $weighted = [Math]::Max(0.0, 100.0 * (1.0 - $penalty / $applicable))
    }
    [PSCustomObject]@{ total = $total; clean = $clean; ...; weighted_score = [Math]::Round($weighted, 2) }
}
```

This is `score_report` (Chapter 3.2), reimplemented, formula-for-formula
identical. `[AllowEmptyCollection()][array]$Findings` — PowerShell, by
default, has a quirky behavior where passing an *empty* collection to a
`[Parameter(Mandatory)]` parameter can be treated as if nothing at all
was passed (triggering PowerShell to interactively *prompt* for a value,
which would hang a non-interactive script dead) — `[AllowEmptyCollection()]`
explicitly overrides that default, allowing a genuinely-empty findings
list through cleanly (relevant for the Linux/Android agents' own
"unreachable device, zero applicable checks" edge case, mirrored here for
completeness on Windows too, even though a fully-empty findings list is
less likely in practice on Windows specifically).
`@($Findings | Where-Object { $_.status -eq 'clean' }).Count` — a
PowerShell pipeline (Volume 1, §6.2): `Where-Object` filters `$Findings`
down to just the elements matching the condition (`$_.status -eq 'clean'`
— `$_` referring to "the current item," `-eq` being PowerShell's
equality-comparison operator), and wrapping the whole pipeline in `@(...)`
forces the result to always be treated as an array/collection (even if
exactly zero or exactly one item matches — a PowerShell-specific quirk
where a pipeline producing a single result can otherwise "unwrap" it to a
bare scalar value rather than a one-element array, which would break the
subsequent `.Count` call in that specific edge case) before `.Count`
reads how many elements survived the filter.

```powershell
function New-HydraBoolFinding {
    ...
    $status = if ($IsDetected) { 'detected' } else { 'clean' }
    $effectiveRemediation = if ($IsDetected) { $Remediation } else { $null }
    New-HydraFinding -Id $Id -Category $Category -Name $Name -Description $Description `
        -Status $status -Severity $Severity -Evidence $Evidence -Remediation $effectiveRemediation
}
```

This is the direct PowerShell equivalent of Python's `FindingFactory.
bool_check()` (Chapter 3.4) — same logic, same "only attach remediation
text on the detected path" behavior, expressed as one standalone function
(rather than a method on a bound-factory object, since PowerShell scripts
tend to favor plain functions taking explicit `-Category`/`-Name`
parameters every call, over Python-style pre-bound objects — a genuine,
idiomatic difference between the two languages' typical styles, not a
functional one). The backtick `` ` `` at the end of the first
`New-HydraFinding` line is PowerShell's **line-continuation** character —
purely a formatting device letting one long logical command span multiple
physical lines for readability, with no effect on the command's actual
behavior.

```powershell
function Find-HydraSignature {
    [CmdletBinding()]
    param([string]$Text, [Parameter(Mandatory)][array]$Signatures)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    foreach ($signature in $Signatures) {
        if ($Text.ToLowerInvariant().Contains($signature.ToLowerInvariant())) {
            return $signature
        }
    }
    return $null
}
```

The PowerShell equivalent of Python's `any_signature_in()` (Chapter 6.1)
— `.ToLowerInvariant()` is .NET's culture-independent lowercasing method
(Volume 1, §6.4's .NET-string-library concept — "invariant" specifically
means the lowercasing rules don't vary depending on the operating
system's regional/language settings, avoiding a subtle class of bug where
the exact same code could behave differently on machines configured for
different languages/locales — e.g. Turkish has locale-specific rules
about the letter 'I' that can trip up naive case-insensitive comparisons
if the *culture-aware* lowercasing method were used instead).

```powershell
Export-ModuleMember -Function New-HydraFinding, New-HydraBoolFinding, Get-HydraSummary, New-HydraReport, Find-HydraSignature
```

The final line of the module: `Export-ModuleMember` explicitly declares
which functions this module makes available to code that `Import-Module`s
it — PowerShell modules, by default, only expose functions you list here,
keeping any other, unlisted helper function private to the module itself
(directly analogous to Python's `__all__`, Chapter 3.7).

### 9.2 `Signatures.ps1` — Windows-specific signature data

**File:** `agents/windows/common/Signatures.ps1`

A `.ps1` file **dot-sourced** (Chapter 11 shows the exact `. (Join-Path
...)` syntax) rather than `Import-Module`d — the practical difference
(worth knowing, though not critical): dot-sourcing runs a script's
top-level statements directly into the *caller's* current scope, which is
exactly what's wanted here, since this file's entire content is just
`$Script:SomeName = @(...)` variable assignments meant to become directly
visible to the probe files (Chapter 10) that dot-source it — not a
self-contained module with its own function-exporting boundary the way
`Hydra.Common.psm1` is.

This file mirrors Chapter 6.2's Linux `signatures.py` closely for the
signatures both platforms share (`DmiVendorSignatures`,
`CpuBrandStringSignatures`, `CpuidHypervisorVendors`,
`MacOuiSignatures`, `AnalysisToolProcessNames`, `SuspiciousNameTokens`,
`SandboxUsernameExact`, `CloudMetadataUrl`), and adds several genuinely
**Windows-only** tables that have no Linux equivalent at all, because they
describe Windows-only concepts (Volume 1, §6.7):

```powershell
$Script:GuestServiceNames = @(
    'VBoxService', 'VBoxSF', 'VBoxGuest', 'VBoxMouse', 'VBoxVideo', ...
)
```
— Windows **service** names (Volume 1, §2.7), checked one at a time via
`Get-Service` (Chapter 10).

```powershell
$Script:RegistryArtifactKeys = @{
    'HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions' = 'VirtualBox'
    ...
}
```
— roughly thirty registry key paths (Volume 1, §6.7) mapped to a vendor
label, the single largest individual signature table in the entire
project, directly reflecting al-khaser's own registry-heavy technique
catalog (Volume 1, §17.2).

```powershell
$Script:BlacklistedDllNames = @('vboxhook.dll', ..., 'sbiedll.dll', ...)
$Script:VmWindowClassNames = @('VBoxTrayToolWndClass', ..., 'VMwareTrayIcon', ...)
```
— DLL names (Volume 1, §6.5's DLL concept) and window class names (Volume
1, §6.5's `FindWindow` discussion), both genuinely Windows-GUI-specific
concepts with no meaningful Linux counterpart.

## Chapter 10: The Windows Agent, Part 2: The Probe Modules

### 10.1 The PowerShell check skeleton

**File:** `agents/windows/probes/Environment.ps1`

```powershell
function Test-SmbiosVendor {
    $id = 'win.env.smbios_vendor'
    $name = 'SMBIOS/Win32_ComputerSystem + Win32_BIOS vendor strings'
    $description = 'Manufacturer/Model/BIOS strings checked against known hypervisor vendor names.'
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    }
    catch {
        return New-HydraFinding -Id $id -Category environment_artifact -Name $name -Description $description `
            -Status error -Severity high -ErrorDetail "CIM query failed: $($_.Exception.Message)"
    }

    $candidates = @($cs.Manufacturer, $cs.Model, $bios.Manufacturer, $bios.Version, $bios.SerialNumber)
    $hit = $null
    foreach ($candidate in $candidates) {
        $match = Find-HydraSignature -Text $candidate -Signatures $Script:DmiVendorSignatures
        if ($match) { $hit = "$candidate (matched '$match')"; break }
    }
    $evidence = "CS.Manufacturer=$($cs.Manufacturer) CS.Model=$($cs.Model) BIOS.Manufacturer=$($bios.Manufacturer) BIOS.Version=$($bios.Version)"
    New-HydraBoolFinding -Id $id -Category environment_artifact -Name $name -Description $description -Severity high `
        -IsDetected ([bool]$hit) -Evidence $evidence `
        -Remediation 'Override SMBIOS via libvirt <sysinfo> (or -smbios flags) to a real vendor identity.'
}
```

This is the exact PowerShell equivalent of Chapter 7.1's Python
`check_cpuid_hypervisor_bit()` skeleton — the same five-part shape:
declare identity, declare description, gather data (here, two
`Get-CimInstance` calls — Volume 1, §6.7 — wrapped in a `try`/`catch`,
Volume 1 §6.6, since a CIM query genuinely can fail), handle the failure
case first (`catch { return New-HydraFinding -Status error ... }`), then
compute and return the verdict (`New-HydraBoolFinding ... -IsDetected
([bool]$hit)`). The one Windows-specific wrinkle worth calling out:
`$candidates = @($cs.Manufacturer, $cs.Model, $bios.Manufacturer,
$bios.Version, $bios.SerialNumber)` gathers *five* separate string
fields and checks each one with `Find-HydraSignature` (Chapter 9.1) in a
`foreach` loop, `break`-ing as soon as the first match is found — directly
mirroring the Linux agent's own multi-field DMI-scanning approach
(Chapter 7.2's `_dmi_checks()`), just implemented as an explicit loop over
a small, fixed list here instead of a loop over a full data-driven table
(`DMI_FIELDS`) — a reasonable, minor structural difference, not a
meaningful behavioral one.

### 10.2 The P/Invoke-based checks — where Windows genuinely diverges

Four checks in this agent are fundamentally impossible to write using
only ordinary PowerShell/.NET calls, and instead reach directly into the
native Win32 API via the P/Invoke declarations from Volume 1 §6.5. Each
one is worth understanding individually, since each is doing something
genuinely different from anything the Linux/Android agents do.

**`Test-SmbiosFirmwareTableRaw`** (in `Environment.ps1`):
```powershell
function Get-HydraFirmwareTableBytes {
    param([Parameter(Mandatory)][string]$Provider, [string]$TableId = '')
    try {
        $providerSig = ConvertTo-HydraFirmwareSignature -Text $Provider
        $tableSig = if ($TableId) { ConvertTo-HydraFirmwareSignature -Text $TableId } else { [uint32]0 }
        $size = [Hydra.Firmware]::GetSystemFirmwareTable($providerSig, $tableSig, $null, 0)
        if ($size -eq 0) { return $null }
        $buffer = New-Object byte[] $size
        $written = [Hydra.Firmware]::GetSystemFirmwareTable($providerSig, $tableSig, $buffer, $size)
        if ($written -eq 0) { return $null }
        return $buffer
    }
    catch { return $null }
}
```
This function calls the real `GetSystemFirmwareTable` Win32 API (Volume
1, §6.5) **twice**, deliberately — this two-call pattern is a standard,
common Win32 API idiom worth understanding on its own: the *first* call
passes `$null` for the actual output buffer and `0` for its size,
specifically to ask the API "how large a buffer would you actually need?"
— its return value in this mode is exactly that required size, not the
data itself. Only *then*, having learned the correct size, does the code
allocate a real byte array of exactly that size (`New-Object byte[]
$size`) and call the *same* function again, this time actually passing
that buffer in, to receive the real firmware table data. `Test-
SmbiosFirmwareTableRaw` itself then treats those raw bytes as plain ASCII
text (`[System.Text.Encoding]::ASCII.GetString($buffer)`) and runs the
exact same `Find-HydraSignature` substring search against it — this is
the concrete implementation of Volume 1 §12.7's "read the raw table
directly, bypassing the higher-level WMI layer entirely" technique.

**`Test-DebuggerPresent` / `Test-RemoteDebuggerPresent`** (in
`Design.ps1`): call `[Hydra.Debug]::IsDebuggerPresent()` and
`[Hydra.Debug]::CheckRemoteDebuggerPresent($handle, [ref]$isPresent)`
directly (Volume 1, §16.4) — the `[ref]$isPresent` syntax is PowerShell's
way of passing a variable **by reference** rather than by value (matching
the underlying Win32 function's own signature, which expects a pointer to
a boolean it can write its answer into, rather than simply returning a
value the ordinary way — Volume 1 §7.4's pointer concept, showing up here
even in PowerShell, one layer removed, because the *underlying* native
function genuinely works that way).

**`Test-WindowClassArtifacts`** (in `Design.ps1`): loops over
`$Script:VmWindowClassNames` (Chapter 9.2) calling
`[Hydra.Window]::FindWindow($className, $null)` for each one — passing
`$null` for the second parameter (the window's *title text*) means "match
by class name alone, regardless of title," and checking whether the
returned handle is `[IntPtr]::Zero` (a null/invalid handle, .NET's
`IntPtr` type representing a raw native pointer-sized value, Volume 1
§7.4's pointer concept again) or a real, non-zero handle — implementing
exactly Volume 1's §6.5 "search for hidden windows even if minimized"
capability.

**`Test-MouseMovement`** (in `Behavioural.ps1`): this is precisely the
check behind the real bug Volume 1 §6.5 already previewed and Chapter 18
covers in full — the custom `POINT` struct declared specifically to work
around `System.Drawing.Point` no longer being directly usable via
`Add-Type`'s default type-reference set on modern .NET.

### 10.3 What's structurally new in `Behavioural.ps1` and `Design.ps1`

- **`Test-FontCount`** uses `System.Drawing.Text.InstalledFontCollection`
  (a genuine, working, non-P/Invoke .NET class, unlike the `Point` issue
  above — this specific class *is* reachable through the ordinary
  `Add-Type -AssemblyName System.Drawing` route) to count installed fonts
  — the Windows equivalent of Linux's `fc-list`-based check (Chapter 7.4),
  reached through a completely different mechanism because Windows has no
  `fc-list`-equivalent command-line tool at all.
- **`Test-InstalledPrograms`** reads two registry "Uninstall" keys
  (`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` and its
  WOW6432Node — 32-bit-compatibility — equivalent) — the Windows-specific
  mechanism software installers use to register themselves for
  Control Panel's "Programs and Features" list, functioning as the
  Windows equivalent of Linux's `dpkg`/`rpm` package-count check (Volume
  1, §11.4).
- **`Test-ExactSandboxUsername`** and **`Test-MacOui`** are near-line-for-
  line translations of their Linux `design.py` counterparts (Chapter 7.4),
  substituting `[System.Environment]::UserName` for `os.environ.get("USER")`
  and `Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration` for
  reading `/sys/class/net/*/address` directly — different underlying data
  sources, identical detection *logic*.

## Chapter 11: The Windows Agent, Part 3: `Invoke-Hydra.ps1`, the Entry Point

**File:** `agents/windows/Invoke-Hydra.ps1`

This is the single file a user actually runs (`pwsh -File Invoke-
Hydra.ps1`) — the Windows agent's equivalent of Linux's `__main__.py`
(Chapter 8.2).

```powershell
[CmdletBinding()]
param(
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot
```

`param([string]$OutputPath)` at the very top of a `.ps1` file (before any
other statement) declares this *entire script* as callable with named
parameters, exactly like a function — `pwsh -File Invoke-Hydra.ps1
-OutputPath C:\report.json` binds directly to this `$OutputPath`
variable. `$ErrorActionPreference = 'Stop'` is a script-wide setting
(distinct from, but conceptually related to, the per-cmdlet
`-ErrorAction Stop` seen throughout the probe files, Volume 1 §6.6) that
changes PowerShell's *default* error-handling behavior for the rest of
this script, making otherwise-non-terminating errors terminate by
default too — a defensive, broad safety net on top of the individual
`try`/`catch` blocks already present in every check. `$PSScriptRoot` is a
PowerShell automatic variable holding the directory this very script file
lives in — used immediately below to reliably locate the other files this
script needs, regardless of what directory the user happened to be sitting
in when they invoked it (directly mirroring Chapter 6.3's `Path(__file__)`
technique in Python, solving the exact same "locate files relative to my
own location, not the caller's current directory" problem, in the
PowerShell-native way).

```powershell
Import-Module (Join-Path $scriptRoot 'common/Hydra.Common.psm1') -Force
. (Join-Path $scriptRoot 'common/Signatures.ps1')
. (Join-Path $scriptRoot 'probes/Environment.ps1')
. (Join-Path $scriptRoot 'probes/Timing.ps1')
. (Join-Path $scriptRoot 'probes/Behavioural.ps1')
. (Join-Path $scriptRoot 'probes/Design.ps1')
```

`Join-Path` builds a correct, OS-appropriate file path by combining two
path segments (PowerShell's cross-platform equivalent of Python's
`pathlib`'s `/` operator, Chapter 6.3). `Import-Module ... -Force` loads
`Hydra.Common.psm1` as a real module (Chapter 9.1) — `-Force` ensures a
fresh reload even if a module with the same name happened to already be
loaded from a previous run in the same PowerShell session (relevant
during iterative development/testing, where re-running the script
repeatedly in one long-lived `pwsh` session could otherwise pick up a
stale, previously-loaded version). The four subsequent lines, each
starting with a lone `.` followed by a space, are **dot-sourcing**
(Chapter 9.2 explained this) — loading `Signatures.ps1` and all four
probe files' function definitions directly into this script's own
top-level scope, in a fixed, deliberate order (signatures before probes,
since the probe files' functions reference `$Script:...` signature
variables that must already exist by the time those functions are
actually *called*, though not necessarily by the time they're merely
*defined* — PowerShell resolves that reference at call time, not
definition time, but declaring signatures first regardless is clearer,
safer practice).

```powershell
$findings = @()
$findings += Invoke-EnvironmentChecks
$findings += Invoke-TimingChecks
$findings += Invoke-BehaviouralChecks
$findings += Invoke-DesignChecks

$report = New-HydraReport -Findings $findings
$json = $report | ConvertTo-Json -Depth 10
```

This is the Windows agent's version of Linux's `runner.py` (Chapter 8.1)
and `CHECK_MODULES` loop (Chapter 7.5) combined into one place, rather
than split across two files — `$findings = @()` starts an empty array;
each `$findings += Invoke-XChecks` (PowerShell's `+=` operator on an
array creates a *new* array with the additional elements appended — worth
noting as a subtle but real difference from Python's list `.extend()`,
Chapter 8.1, which mutates the existing list in place; PowerShell arrays
are fixed-size under the hood, so `+=` on one is always secretly building
a brand-new array each time, which is slightly less efficient for very
large collections but functionally equivalent here, since HYDRA's total
finding count per platform is small, at most a few dozen) calls one
category's `Invoke-XChecks` function (each defined at the bottom of its
respective probe file, directly analogous to Python's per-module
`run_all()`) and appends every `Finding` it returns.

`ConvertTo-Json -Depth 10` (Volume 1, §9.2's PowerShell JSON conversion)
converts the whole `$report` object into a JSON string — `-Depth 10`
overrides `ConvertTo-Json`'s otherwise-fairly-shallow *default* nesting
depth (PowerShell's JSON converter, by default, only recurses a couple of
levels deep before giving up and flattening remaining nested structure
into plain, unhelpful text) — necessary here specifically because a
`Finding`'s `evidence` field can itself be a nested object (recall
Chapter 7.3's timing-jitter check, which uses a structured evidence
object even on the Linux side; the Windows agent has equivalent nested-
object evidence too), and without raising this depth limit, that nested
detail would silently get flattened away and lost in the final JSON
output — a genuinely easy-to-miss PowerShell gotcha worth knowing in
general, beyond just this project.

```powershell
if ($OutputPath) {
    $json | Out-File -FilePath $OutputPath -Encoding utf8
    [Console]::Error.WriteLine("Wrote report to $OutputPath")
}
else {
    Write-Output $json
}

$s = $report.summary
[Console]::Error.WriteLine("HYDRA windows scan: $($s.raw_score) clean, weighted $($s.weighted_score)/100 ($($s.errored) errored, $($s.skipped) skipped)")
```

This is exactly Linux's `__main__.py` stdout/stderr discipline (Chapter
8.2), reimplemented — and it's worth being explicit about *why* it uses
`[Console]::Error.WriteLine(...)` specifically, rather than PowerShell's
own more commonly seen `Write-Host` cmdlet: this is precisely the fix for
the real, documented bug (Volume 1's summary, Chapter 18 in full) where an
earlier version of this script used `Write-Host` for exactly these same
status messages — and `Write-Host`, despite superficially looking like it
should be roughly equivalent to a plain "print to the terminal," actually
writes to a special PowerShell-specific output stream that, critically,
gets merged back into the *same* stdout stream a calling process (like
the Python CLI, Chapter 15) captures — silently corrupting the pure-JSON
stdout output this whole design depends on. `[Console]::Error.WriteLine`
reaches directly into .NET's own `System.Console` class (Volume 1, §6.4)
and writes to the real OS-level stderr stream unambiguously, sidestepping
PowerShell's own stream-abstraction layer entirely, guaranteeing the
separation Volume 1 §5.6 described actually holds.

## Chapter 12: The Android Agent, Part 1: `adb.py` and `signatures.py`

### 12.1 `adb.py` — the thin `adb` wrapper

**File:** `agents/android/hydra_android/adb.py`

Everything the Android agent does flows through this one small file — no
check anywhere in this agent talks to a device except through these four
functions.

```python
def adb_binary_available() -> bool:
    return shutil.which("adb") is not None
```

`shutil.which("adb")` (Python's standard-library equivalent of the Unix
`which` command, Volume 1 §5.2 — searches the `PATH` environment variable
for an executable with this name) returns the full path to `adb` if it's
installed and findable, or `None` if not — turned into a clean boolean
here.

```python
def device_reachable(serial: str | None) -> bool:
    if not adb_binary_available():
        return False
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += ["get-state"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and result.stdout.strip() == "device"
```

This function is the single most important one in the entire Android
agent — Chapter 13 will show it's what several checks call *explicitly*
before trusting an absent value as genuinely meaningful (this is exactly
the fix for the real bug Volume 1 §11.6 previewed, covered fully in
Chapter 18). `cmd = ["adb"]` then conditionally `+= ["-s", serial]` (only
if a specific serial was given — Volume 1 §11.6's adb concept: `-s`
targets one specific device when multiple are attached; omitting it lets
`adb` fall back to its own default-device selection when only one is
attached) builds up the command as a list (Chapter 6.1's list-of-words
`subprocess` pattern, applied identically here). `adb get-state` is a
real `adb` subcommand whose entire purpose is reporting connection state
— `"device"` specifically means "present, authorized, and ready"; other
possible answers (`"offline"`, `"unauthorized"`, or the command failing
outright) all correctly fall through to `False` here.

```python
def shell(serial: str | None, command: str, timeout: float = 10.0) -> str | None:
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += ["shell", command]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def getprop(serial: str | None, name: str) -> str | None:
    value = shell(serial, f"getprop {name}")
    if value is None:
        return None
    return value.strip() or None
```

`shell()` is the generic "run any command on the device" wrapper (Volume
1, §11.6's `adb shell` concept) — every other function in this file
(and, indirectly, nearly every Android check) is built on top of it.
`getprop()` is a thin, specific convenience wrapper around `shell()`,
specifically for the extremely common "read one system property" case
(Volume 1, §11.6) — its final line, `return value.strip() or None`, is
worth reading precisely: `value` here can't be `None` at this point (that
case already returned above), only a possibly-empty string; `.strip() or
None` converts an empty (or whitespace-only) string specifically into
`None` — meaning `getprop()`'s `None` return can mean *either* "the
device was unreachable" *or* "the device answered, but this property is
genuinely unset," collapsing what are, as Volume 1 §11.6/§4.5 explained,
two importantly *different* situations into one indistinguishable value —
which is precisely *why* certain callers (Chapter 13) have to separately
call `device_reachable()` first, rather than trusting `getprop()`'s return
value alone to tell the two apart.

```python
def file_exists(serial: str | None, path: str) -> bool | None:
    """True/False if we could check, None if the device/adb was unreachable."""
    out = shell(serial, f"[ -e {path} ] && echo YES || echo NO")
    if out is None:
        return None
    return out.strip() == "YES"
```

This function has a genuinely three-way return type: `True`, `False`, or
`None` — a clean, explicit way of representing "yes," "no," and "couldn't
determine" as three *distinct* values, rather than collapsing "no" and
"couldn't determine" together the way `getprop()`'s two-way `None`
sometimes ends up doing (a deliberately different, arguably cleaner
design than `getprop()`'s, worth noticing as a point of contrast within
the same file). The command string itself,
`f"[ -e {path} ] && echo YES || echo NO"`, is a small piece of actual
shell syntax (Volume 1, §5.3) being sent *to* the Android device's own
shell for it to execute remotely: `[ -e {path} ]` is a standard POSIX
shell file-existence test, and `&& echo YES || echo NO` is shell's
common "if the previous command succeeded, print YES, otherwise print
NO" idiom — the actual true/false answer arrives back over `adb` as
literal text, which this function then just string-compares against
`"YES"`.

### 12.2 `signatures.py`

**File:** `agents/android/hydra_android/signatures.py`

As the module's own docstring states directly, this file is
**HYDRA-original** — there is no upstream Pafish/al-khaser/VMAware
equivalent for any of it (Volume 1, §17.4/Chapter 15's Android
discussion). Its tables map directly onto the Android-specific concepts
from Volume 1 §11.6: `BUILD_PROP_EMULATOR_SIGNATURES` (goldfish/ranchu/
Genymotion/Cuttlefish build-property substrings), `QEMU_DEVICE_NODES`
(`/dev/qemu_pipe` and similar), `LIBHOUDINI_PATHS` (the four possible
install locations for the ARM-translation shim, covering both 32-bit
`/system/lib/` and 64-bit `/system/lib64/`/`/vendor/lib64/` layouts),
`X86_CPU_ABIS`, `AVD_DEFAULT_SUBNET_PREFIX`, and
`GOLDFISH_DEFAULT_TEMPERATURE_TENTHS` (a numeric constant, `250`,
representing 25.0°C in tenths-of-a-degree — the specific unit `dumpsys
battery`'s raw output uses, explained directly in the check that consumes
it, Chapter 13).

## Chapter 13: The Android Agent, Part 2: The Check Modules

### 13.1 `environment.py` — the `_prop_check` helper and the qemu-kernel-flag bug fix

**File:** `agents/android/hydra_android/checks/environment.py`

```python
def _prop_check(
    serial: str | None, check_id: str, name: str, prop: str,
    signature_list: tuple[str, ...], severity: Severity,
) -> Finding:
    description = f"getprop {prop}, checked against known emulator signatures."
    value = adb.getprop(serial, prop)
    if value is None:
        return _f.error(check_id, name, description, severity, _ADB_UNREACHABLE)
    lowered = value.lower()
    hit = next((s for s in signature_list if s in lowered), None)
    return _f.bool_check(
        check_id, name, description, severity,
        is_detected=bool(hit), evidence=f"{prop}={value!r}" + (f" (matched {hit!r})" if hit else ""),
        remediation=f"Override {prop} to a value consistent with a real, shipped device profile.",
    )
```

This is a shared internal helper (the leading underscore, Chapter 3.3's
convention) that five separate check functions in this file
(`check_build_fingerprint`, `check_hardware_prop`, `check_boot_hardware`,
`check_product_model`, `check_manufacturer`) each call with just a
different `prop` name and `signature_list` — exactly the same
"extract the shared shape into one helper, call it with different data"
principle Chapter 7.2's `_dmi_checks()` demonstrated on the Linux side,
applied here for a slightly different reason (five *separately named*
public check functions, each still needing its own distinct `check_id`/
`name` for the final report, rather than one function producing several
findings via an internal loop the way `_dmi_checks()` does).

`next((s for s in signature_list if s in lowered), None)` — `next()` is a
Python built-in that pulls the *first* item out of a generator expression
(Chapter 3.2 introduced generator expressions), with a second argument
(`None`) specifying what to return if the generator produces nothing at
all — this is a common, idiomatic Python pattern for "find the first
match, or `None` if there isn't one," functionally equivalent to (but
more compact than) `utils.any_signature_in()`'s explicit `for`/`return`
loop from Chapter 6.1 — worth noticing as a second, independently
occurring way of expressing the exact same underlying idea, since the
Android agent's own `signatures.py` doesn't actually reuse Linux's
`utils.any_signature_in` (there is no shared code between the Linux and
Android *Python* agents at all beyond `hydra_common` itself, by
deliberate design — Chapter 1 explained the boundary between what's
genuinely shared vs. platform-specific).

```python
def check_qemu_kernel_flag(serial: str | None = None) -> Finding:
    check_id, name = "android.env.qemu_kernel_flag", "ro.kernel.qemu flag"
    description = "ro.kernel.qemu is set to 1 by the goldfish/ranchu kernel; absent on real hardware."
    if not adb.device_reachable(serial):
        return _f.error(check_id, name, description, Severity.CRITICAL, _ADB_UNREACHABLE)
    value = adb.getprop(serial, "ro.kernel.qemu")
    if value is None:
        return _f.clean(check_id, name, description, Severity.CRITICAL, "ro.kernel.qemu unset")
    return _f.bool_check(
        check_id, name, description, Severity.CRITICAL,
        is_detected=value.strip() == "1",
        evidence=f"ro.kernel.qemu={value!r}",
        remediation="Clear ro.kernel.qemu in the build's default.prop / boot config.",
    )
```

This is the exact check protected by the real regression bug covered in
Volume 1 §11.6 and, in full, in Chapter 18 below — and notice it does
**not** use the shared `_prop_check` helper above, deliberately, even
though it superficially looks similar: this check needs *three*-way logic
(unreachable device / reachable-but-unset property / reachable-and-set-
to-1), while `_prop_check` only distinguishes *two* outcomes
(unreachable-or-error vs. a value to check against signatures) — the
explicit `if not adb.device_reachable(serial):` guard, checked *before*
ever calling `adb.getprop()`, is precisely what makes it possible to tell
"reachable, property genuinely absent" (correctly reported as `clean`,
via `_f.clean(...)`, since that's the *normal, expected* state on real
hardware) apart from "unreachable, so we actually know nothing at all"
(correctly reported as `error`) — a distinction that a naive
implementation using `_prop_check` directly would have silently
collapsed, exactly the way the real, historical version of this bug did.

### 13.2 What's new elsewhere in `environment.py`

- **`check_gralloc_egl()`** is the one check in this file combining
  *two* separate `getprop` reads (`ro.hardware.gralloc`,
  `ro.hardware.egl` — Volume 1's graphics-HAL concept, §11.6) into one
  combined evaluation, checking the concatenated text against *both* the
  standard emulator-signature list *and* a small, locally-defined
  fallback pair (`"swiftshader"`, `"mesa"` — two well-known
  software-only, non-hardware-accelerated graphics rendering
  implementations, whose presence is a related but distinct kind of tell
  from the goldfish/ranchu-specific signatures).
- **`check_qemu_properties_present()`** doesn't call `getprop` for one
  named property at all — instead it calls `adb.shell(serial, "getprop")`
  with *no* argument (dumping literally every system property at once)
  and filters the resulting multi-line text for any line starting with
  `"[qemu."` — a genuinely different strategy from every other check in
  this file: rather than checking a small, curated list of *known*
  interesting property *names*, it looks for the mere *existence* of
  anything under an entire property namespace prefix, catching properties
  this project's own signature list might not have anticipated by name in
  advance.

### 13.3 `behavioural.py` — parsing free-text `dumpsys` output

**File:** `agents/android/hydra_android/checks/behavioural.py`

```python
def check_battery_plausibility(serial: str | None = None) -> Finding:
    ...
    output = adb.shell(serial, "dumpsys battery")
    ...
    ac_powered = re.search(r"AC powered:\s*(true|false)", output, re.IGNORECASE)
    level = re.search(r"level:\s*(\d+)", output, re.IGNORECASE)
    if not ac_powered or not level:
        return _f.error(...)
    evidence = f"AC powered={ac_powered.group(1)} level={level.group(1)}"
    detected = ac_powered.group(1).lower() == "true" and level.group(1) == "50"
    return _f.bool_check(..., is_detected=detected, evidence=evidence, ...)
```

This is the first check module in this entire document that parses
genuinely free-form, human-oriented command output with a **regular
expression** (Volume 1, §4.10) rather than reading a clean, structured
value like a system property or a file's single-purpose contents.
`re.search(r"AC powered:\s*(true|false)", output, re.IGNORECASE)` — the
`r"..."` prefix marks a **raw string** (Python syntax where backslashes
are treated literally, not as escape sequences — essential for regex
patterns, which use backslashes heavily for their own special meaning);
`\s*` matches zero-or-more whitespace characters; `(true|false)` is a
**capture group** (parentheses in a regex mark a sub-pattern whose
specific matched text can be retrieved afterward via `.group(1)` — group
0 is always the *entire* match, group 1 is the first parenthesized
sub-pattern) matching either literal word; `re.IGNORECASE` makes the
whole match case-insensitive. `if not ac_powered or not level:` — a
`re.search` call returns `None` if no match was found anywhere in the
text (another instance of Volume 1 §4.5's "falsy `None`" convention),
so this guard specifically handles "`dumpsys battery`'s output didn't
look the way we expected at all" as its own genuine `error` case, distinct
from "the device was unreachable" (already handled earlier in the
function, not shown in this excerpt) — a third kind of failure this
particular check has to account for, specific to the fact that it's
parsing loosely-structured text rather than reading one clean, guaranteed
value.

`check_battery_temperature()` is worth a specific historical note: an
earlier draft of this function existed as two functions — a thin
`check_battery_temperature()` wrapper that did nothing but call an inner
`check_battery_temperature_for(None)` — a redundant, unnecessary
indirection that was caught and removed during development, consolidating
back down to the single, direct function you see in the real source
today, taking `serial` as a normal parameter like every other check in
this project. This is a small example of the general "no dead code, no
unnecessary abstraction" principle (Volume 1's coding-style guidance) in
practice — self-caught, without needing an external reviewer to flag it.

### 13.4 `design.py` — the last of the four Android categories

**File:** `agents/android/hydra_android/checks/design.py`

- **`check_camera_feature()`** calls `adb.shell(serial, "pm list
  features")` (Volume 1, §11.6's package-manager concept) and checks
  whether the output contains `"android.hardware.camera"` — notice the
  detection logic here is *inverted* relative to most other checks in
  this project: `is_detected=not has_camera` — the *absence* of an
  expected, normal feature declaration is itself the tell, rather than
  the *presence* of something suspicious, a meaningfully different shape
  from almost every other check in the whole codebase, worth recognizing
  as a legitimate, valid variant of the general pattern.
- **`check_avd_default_subnet()`** runs `adb shell "ip addr show"`,
  falling back to the older `"ifconfig"` command
  (`adb.shell(serial, "ip addr show") or adb.shell(serial, "ifconfig")`
  — Volume 1 §4.5's `or`-based fallback idiom, exactly like `report.py`'s
  remediation-text fallback in Chapter 3.5) if the first attempt returns
  nothing, and checks whether `signatures.AVD_DEFAULT_SUBNET_PREFIX`
  (`"10.0.2."`) appears anywhere in the resulting network-interface
  listing text — a plain substring search this time, not a full regex,
  since a literal IP-address prefix has no special regex-meaningful
  characters to worry about.

## Chapter 14: The Android Agent, Part 3: `runner.py`, `__main__.py`

### 14.1 `runner.py`

**File:** `agents/android/hydra_android/runner.py`

```python
def run_scan(serial: str | None = None) -> PlatformReport:
    findings: list[Finding] = []
    for module in CHECK_MODULES:
        findings.extend(module.run_all(serial))

    metadata = {"adb_serial": serial or "(default device)"}
    if adb.device_reachable(serial):
        model = adb.getprop(serial, "ro.product.model")
        android_version = adb.getprop(serial, "ro.build.version.release")
        if model:
            metadata["device_model"] = model
        if android_version:
            metadata["android_version"] = android_version

    return PlatformReport(platform=Platform.ANDROID, findings=tuple(findings), agent_metadata=metadata)
```

Structurally identical to Linux's `runner.py` (Chapter 8.1) for the
findings-collection part — `module.run_all(serial)` (note the extra
`serial` argument threaded through here, absent on the Linux side, since
every Android check needs to know *which* device to talk to, while every
Linux check implicitly operates on "the current host," with nothing to
select between). The `agent_metadata` construction is genuinely different
from Linux's `PlatformReport.default_metadata()` (Chapter 3.1) — rather
than calling one shared static method, this function builds Android-
specific metadata by hand: it always records which `adb_serial` was
used (falling back to the literal placeholder text `"(default device)"`
if none was specified — Volume 1's `or` idiom again, §4.5), and *only if*
the device is actually reachable, additionally attempts to enrich the
metadata with the device's real model name and Android version — wrapped
in the same `if model:`/`if android_version:` guards (rather than adding
`None` values directly into the metadata dict) because the schema
(Chapter 2) requires `agent_metadata`'s values to all be strings, and
`getprop` can return `None` — so these two guards exist specifically to
keep a `None` from ever accidentally slipping into a dict that must
validate as `additionalProperties: { "type": "string" }`.

### 14.2 `__main__.py`

**File:** `agents/android/hydra_android/__main__.py`

```python
if not adb.adb_binary_available():
    print("warning: `adb` not found on PATH -- every check will report as errored", file=sys.stderr)
elif not adb.device_reachable(args.serial):
    print(
        f"warning: no device reachable at serial={args.serial!r} (see `adb devices`) -- "
        "every check will report as errored", file=sys.stderr,
    )
```

This is the one genuinely new piece of logic compared to Linux's
`__main__.py` (Chapter 8.2) — a proactive, upfront warning, printed to
stderr *before* the scan even runs, when the agent can already tell in
advance that the whole run is doomed to produce nothing but `error`
findings (either `adb` itself isn't installed at all, or no device
answers at the requested serial). This doesn't change the scan's actual
*behavior* at all (every individual check would already, independently,
correctly report itself as `error` regardless — Volume 1's §18.3
graceful-degradation principle holds either way) — it exists purely as a
courtesy to a human running this agent interactively, so they immediately
understand *why* they're about to see an all-`error` report, rather than
needing to read through dozens of individual error messages to piece that
together themselves. The rest of the file — building the report, writing
to stdout or a file, the final summary line — is line-for-line identical
in structure to Linux's `__main__.py` (Chapter 8.2), differing only in the
one extra `-s`/`--serial` argparse flag this agent needs and Linux's does
not.

## Chapter 15: The CLI — `cli/hydra_cli/__main__.py`, Line by Line

**File:** `cli/hydra_cli/__main__.py`

This is the file behind the literal `hydra` command (Chapter 4's
`pyproject.toml` entry-point configuration is what wires it up) — the
single point where a user's typed command actually becomes "run this one
platform's agent and show me the result."

```python
_REPO_ROOT = Path(__file__).resolve().parents[2]
_WINDOWS_AGENT_SCRIPT = _REPO_ROOT / "agents" / "windows" / "Invoke-Hydra.ps1"

_PLATFORMS = ("windows", "linux", "android")
```

`.parents[2]` — `Path.parents` is an indexable sequence of every
ancestor directory of a path, from nearest to furthest;
`__file__.resolve().parents[2]` walks up exactly two levels from
`cli/hydra_cli/__main__.py` (index `0` would be `cli/hydra_cli/`, index
`1` would be `cli/`, index `2` reaches the true repository root) — the
same "locate things relative to my own file, not the current working
directory" technique from Chapters 6.3 and 11, applied once more here,
specifically so the CLI can reliably find the Windows agent's `.ps1`
script (which, unlike the Python agents, cannot simply be `import`ed —
Chapter 1 already explained why) regardless of what directory it's
launched from.

```python
def _run_windows_agent(serial: str | None) -> dict | None:
    del serial  # the Windows agent has no adb-style serial concept

    if shutil.which("pwsh") is None:
        print(
            "error: `pwsh` (PowerShell 7) not found on PATH. The Windows agent needs .NET's "
            "X86Base CPUID intrinsic, which requires PowerShell 7+ (not Windows PowerShell 5.1).\n"
            f"Run it directly instead: pwsh -File {_WINDOWS_AGENT_SCRIPT}",
            file=sys.stderr,
        )
        return None
    if not _WINDOWS_AGENT_SCRIPT.exists():
        print(f"error: Windows agent script not found at {_WINDOWS_AGENT_SCRIPT}\n...", file=sys.stderr)
        return None
```

`del serial` is a small, deliberate piece of self-documentation: the CLI's
`_run_agent` dispatcher (below) passes a `serial` argument uniformly to
every platform's runner function, but the Windows agent has no concept of
one at all (Volume 1's adb-serial concept, §11.6, is Android-specific) —
`del serial` explicitly discards the unused parameter right at the top of
the function, both silencing any linter warning about an unused variable
*and* signaling clearly to a human reader "yes, this parameter exists in
the function signature for consistency with the other two platforms'
runner calls, and yes, it is genuinely and deliberately unused here" —
the Python equivalent of the C `(void)argc;` idiom from Chapter 5.2.

The two upfront checks — `shutil.which("pwsh") is None` and `not
_WINDOWS_AGENT_SCRIPT.exists()` — are exactly the kind of clear, specific,
actionable error messages Volume 1 §18.6's CLI-design principles called
for: rather than letting a missing `pwsh` installation manifest as some
opaque, low-level `FileNotFoundError` deep inside `subprocess.run`, the
CLI checks for this specific, anticipated failure mode *first* and
explains precisely what's wrong and exactly what command to run instead —
directly analogous to Volume 1's §16.5/Chapter 2's broader theme of
explicit, honest documentation of a tool's own real limits, applied here
at the level of a single error message rather than a whole document.

```python
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_output = Path(tmp_dir) / "windows-report.json"
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-File", str(_WINDOWS_AGENT_SCRIPT), "-OutputPath", str(tmp_output)],
            capture_output=True, text=True, timeout=180, check=False,
        )
        if result.returncode != 0 or not tmp_output.exists():
            print(f"error: Windows agent failed:\n{result.stdout}\n{result.stderr}", file=sys.stderr)
            return None
        return json.loads(tmp_output.read_text(encoding="utf-8"))
```

`tempfile.TemporaryDirectory()` (Volume 1, §2.4's filesystem concept,
Python's standard-library tool for it) creates a fresh, private,
automatically-cleaned-up-afterward temporary directory (the `with`
statement, Volume 1's "context manager" idea briefly mentioned in the
Python patterns rule file, ensures the directory is deleted again the
moment this block finishes, success or failure alike) — used here as a
scratch location to have the PowerShell agent write its JSON report to a
*file*, rather than trying to capture and parse its raw stdout text
directly. This is a deliberate, meaningful choice, not an arbitrary one:
even with the careful stderr/stdout discipline Chapter 11 described,
routing through a real file, with an explicit `-OutputPath`, is a more
robust integration boundary than depending on perfectly clean stdout
capture across a process boundary and a language boundary at once —
belt-and-suspenders reliability for what is, cross-language and
cross-process, the single most failure-prone integration point in the
entire project. `["pwsh", "-NoProfile", "-File", ...]` — `-NoProfile`
tells PowerShell to skip loading the user's personal PowerShell profile
script (customizations/settings some users configure for their own
interactive sessions) — important specifically because this script is
being run *non-interactively*, as an automated subprocess, where a user's
personal profile customizations are irrelevant at best and a source of
unpredictable, environment-specific behavior at worst.

```python
def _run_agent(platform: str, serial: str | None) -> dict | None:
    if platform == "linux":
        from hydra_linux.runner import run_scan
        return run_scan().to_dict()
    if platform == "android":
        from hydra_android.runner import run_scan
        return run_scan(serial).to_dict()
    if platform == "windows":
        return _run_windows_agent(serial)
    raise AssertionError(f"unreachable: unknown platform {platform!r}")  # argparse choices guards this
```

This function is where "the user picked exactly one platform, and only
that platform's checks run" (Volume 1's §18.6 explicit design
requirement) is physically enforced in code — there is no branch here
that runs more than one platform, and no fallback/auto-detection branch
at all. The `import` statements for `hydra_linux`/`hydra_android` are
placed *inside* their respective `if` branches, rather than at the top of
the file — this is a deliberate performance/robustness choice, not
accidental: importing `hydra_linux` triggers, indirectly, the whole
Linux-agent module-loading chain (Chapter 7's check modules, which
themselves reference `cpu.py`, Chapter 6.3), and there is no reason for
running `hydra test windows` to pay that cost (or risk any Linux-specific
import-time failure) at all — each platform's real Python dependencies
are only loaded, lazily, at the exact moment they're actually needed.
`raise AssertionError(...)` for the "impossible" fourth case is a
defensive-programming pattern: `argparse`'s own `choices=_PLATFORMS`
(seen below) already guarantees `platform` can never actually be anything
other than one of the three legal values by the time this function is
even called — this final branch exists purely to satisfy a careful
reader (and this function's own internal logical completeness) that every
possible input truly is accounted for, with a message explicitly stating
*why* this branch should be provably unreachable rather than silently
doing nothing if some future change somehow broke that guarantee.

```python
def _cmd_test(args: argparse.Namespace) -> int:
    report = _run_agent(args.platform, args.serial)
    if report is None:
        return 1

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Wrote JSON report to {args.output}", file=sys.stderr)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        from hydra_common.text_format import render_platform_text
        use_color = None if not args.no_color else False
        print(render_platform_text(report, use_color=use_color, verbose=args.verbose))

    return 0
```

`if report is None: return 1` — this is precisely where a failed agent
run (Chapter 15's own `_run_windows_agent` returning `None` on any of its
several failure paths) becomes the CLI's own non-zero exit code (Volume
1, §5.5/§18.6) — the one single place this translation happens, for
every platform uniformly. `use_color = None if not args.no_color else
False` — recall from Chapter 3.6 that `render_platform_text`'s own
`use_color` parameter is three-way (`None` = auto-detect, `True`/`False`
= explicit override); this line implements exactly the `--no-color` flag:
if the flag was *not* given (`not args.no_color` is `True`), pass `None`
through (let auto-detection decide); if the flag *was* given, pass the
explicit `False` (force colors off, unconditionally, regardless of
whether the output happens to be a real terminal or not).

```python
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hydra", description="...")
    subparsers = parser.add_subparsers(dest="command", required=True)

    test = subparsers.add_parser("test", help="test one sandbox platform against its full check suite and print a score")
    test.add_argument("platform", choices=_PLATFORMS, help="which sandbox this host/device is")
    test.add_argument("-s", "--serial", default=None, help="adb device serial (android only; see `adb devices`)")
    test.add_argument("-o", "--output", default=None, help="also write the raw JSON report to this path")
    test.add_argument("--json", action="store_true", help="print raw JSON instead of the human-readable summary")
    test.add_argument("--verbose", action="store_true", help="list every check, not just detections/errors")
    test.add_argument("--no-color", action="store_true", help="disable ANSI colour in the summary output")
    test.set_defaults(func=_cmd_test)
```

`add_subparsers(dest="command", required=True)` sets up `argparse`'s
built-in mechanism for a command that itself has *sub-commands* (`hydra
test ...` vs. `hydra report ...` — a very common CLI pattern, seen in
tools like `git` (`git commit`, `git push`) or `docker` (`docker run`,
`docker build`) — Volume 1's CLI discussion, §5/§18.6, didn't cover
subparsers explicitly, but this is the standard `argparse` mechanism for
building exactly this kind of two-level command structure).
`required=True` means the bare command `hydra` with no subcommand at all
is itself an error, forcing a user to always specify `test` or `report`.
`test.add_argument("platform", choices=_PLATFORMS, ...)` — a **positional**
argument (Volume 1, §5.3 — no leading dashes), and `choices=_PLATFORMS`
is precisely what makes `hydra test macos` (or any value outside the
three legal platforms) fail immediately, with `argparse`'s own built-in
clear error message, *before* `_run_agent` (above) is ever even reached —
this is the actual, concrete enforcement point behind the "impossible"
`AssertionError` branch discussed just above: `argparse` itself is the
gate that guarantees that branch can never be reached in practice.
`action="store_true"` is `argparse`'s syntax for a plain on/off flag
(Volume 1, §5.3) — `--json`, `--verbose`, `--no-color` each become `True`
if present on the command line at all, `False` if omitted, with no
separate value needed after them (unlike `-o`/`--output`, which does take
a following value).

```python
def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
```

`test.set_defaults(func=_cmd_test)` (seen just above) is what makes this
final dispatch work so simply: rather than `main()` needing its own
`if args.command == "test": ... elif args.command == "report": ...`
chain, each subparser has already, at *definition* time, attached its own
corresponding handler function directly onto the parsed arguments
themselves — so `args.func(args)` always calls exactly the right function
for whichever subcommand was actually used, regardless of how many
subcommands this CLI might grow to have in the future (Chapter 20 revisits
this as part of "how to add a new subcommand" if HYDRA were extended
further). `main(argv: list[str] | None = None)` — accepting an optional,
explicit `argv` list (rather than always implicitly reading the real
`sys.argv`) is precisely what makes this function directly, easily
testable (Chapter 16 shows the tests calling `main(["test", "linux",
"--json"])` directly, in-process, with no need to actually spawn a real
separate subprocess for every single test case) — a small design choice
with an outsized payoff for how pleasant and fast this project's test
suite is to run.

## Chapter 16: The Tests, File by File

**Directory:** `tests/`

Volume 1 §18.1 covered `pytest`, unit vs. integration tests, regression
tests, and `monkeypatch`-based mocking conceptually. This chapter shows
each of those ideas realized in HYDRA's actual test suite, file by file.

### 16.1 `test_common.py` — testing `hydra_common` in isolation

```python
def _finding(status: Status, severity: Severity = Severity.MEDIUM, n: int = 0) -> Finding:
    return Finding(
        id=f"test.env.check_{n}", category=Category.ENVIRONMENT_ARTIFACT, platform=Platform.LINUX,
        name=f"Check {n}", description="A test check.", status=status, severity=severity,
    )


def test_score_report_all_clean_is_perfect() -> None:
    findings = [_finding(Status.CLEAN, n=i) for i in range(5)]
    summary = score_report(findings)
    assert summary["raw_score"] == "5/5"
    assert summary["weighted_score"] == 100.0
    assert summary["total"] == 5
```

`_finding(...)` is a small **test helper function** — not itself a test
(its name doesn't start with `test_`, so `pytest` won't try to run it
directly, Volume 1 §18.1), but a convenience for *building* the specific
`Finding` objects every real test in this file needs, without each test
having to repeat the same seven-argument `Finding(...)` construction by
hand. `assert` is Python's built-in assertion statement — the fundamental
building block every `pytest` test is made of: `assert condition` does
nothing at all if `condition` is true, and raises an `AssertionError`
(Volume 1, §3.4's exception concept) — which `pytest` specifically
recognizes and reports as "this test failed, at this exact line" — if the
condition is false. `test_score_report_all_clean_is_perfect` directly
verifies the specific claim from Chapter 3.2: five clean findings should
produce `"5/5"` and a perfect `100.0`.

```python
def test_score_report_weights_by_severity() -> None:
    critical = [_finding(Status.DETECTED, Severity.CRITICAL, n=0)]
    low = [_finding(Status.DETECTED, Severity.LOW, n=0)]
    critical_score = score_report(critical + [_finding(Status.CLEAN, n=1)])
    low_score = score_report(low + [_finding(Status.CLEAN, n=1)])
    assert critical_score["weighted_score"] < low_score["weighted_score"]
```

This test is worth calling out specifically because of *what it doesn't
do*: it doesn't assert any exact numeric score value at all — only a
*relative* comparison (`critical_score < low_score`). This is a
deliberate, good testing practice: it verifies the specific, meaningful
*property* the weighted-scoring feature is actually supposed to guarantee
(a critical detection must hurt more than a low-severity one, Volume 1
§18.4/Chapter 3.2's core reasoning) without over-specifying an exact
number that would make this test unnecessarily brittle against small,
legitimate future tweaks to the weight table's specific numbers.

```python
def test_platform_report_to_dict_round_trips_through_schema_shape() -> None:
    findings = (_finding(Status.CLEAN, n=0), _finding(Status.DETECTED, Severity.HIGH, n=1))
    report = PlatformReport(platform=Platform.LINUX, findings=findings, hostname="test-host")
    d = report.to_dict()
    validate_report(d)  # should not raise
    assert d["platform"] == "linux"
    assert d["summary"]["detected"] == 1
    assert json.dumps(d)  # must be JSON-serialisable
```

This test exercises three separate pieces of `hydra_common` together in
one flow — `PlatformReport` construction (Chapter 3.1), `to_dict()`
serialization, and `validate_report()` (Chapter 3.3) — verifying they
actually agree with each other end-to-end, making it closer to an
**integration test** than a pure unit test (Volume 1, §18.1's
distinction), even though it's still entirely in-process and needs no
external device/process at all. `assert json.dumps(d)` is a subtle but
real check: `json.dumps` *raises* an exception if given something it
genuinely cannot serialize (e.g. a raw Python object with no defined JSON
representation) — so this line isn't really checking the *return value*
of `json.dumps(d)` at all (any non-empty string is truthy and would pass);
it's really using the assertion as a convenient way to say "this call
must not raise" — if `to_dict()` had, say, accidentally left a raw
`datetime` object or enum member in the returned dict instead of properly
converting it to a plain string, this line would fail with a real
exception, not just a false assertion.

### 16.2 `test_linux_agent.py` — the CPUID register-order regression test, in full

```python
def test_cpuid_vendor_string_decode_order_is_ebx_ecx_edx() -> None:
    """Regression test for a real bug caught during development: ..."""
    signature = b"KVMKVMKVM\0\0\0"
    ebx = int.from_bytes(signature[0:4], "little")
    ecx = int.from_bytes(signature[4:8], "little")
    edx = int.from_bytes(signature[8:12], "little")

    result = CpuidResult(eax=0x40000000, ebx=ebx, ecx=ecx, edx=edx)

    assert result.vendor_string == "KVMKVMKVM\0\0\0"
    assert result.vendor_string in signatures.CPUID_HYPERVISOR_VENDORS
```

This test deserves careful reading, because it's a genuinely elegant
example of testing low-level bit/byte manipulation correctly. It does
**not** call the real native C helper (Chapter 5) at all — doing so would
make this test depend on having a working C compiler and real x86
hardware available, entirely unnecessary for testing this specific piece
of *decoding* logic. Instead, it works *backwards*: starting from the
known-correct answer (`signature = b"KVMKVMKVM\0\0\0"`, the literal bytes
KVM's real hypervisor-vendor string is supposed to decode to), it
manually *re-encodes* those bytes into the three separate `ebx`/`ecx`/`edx`
integers, in exactly the order `CpuidResult.vendor_string`'s real
implementation (Chapter 6.3) expects to receive them (`int.from_bytes(...,
"little")`, Volume 1 §10.5's endianness concept, is the deliberate
inverse operation of `.to_bytes(4, "little")` from Chapter 6.3) — then
constructs a `CpuidResult` with those three numbers, calls the *real*
`vendor_string` property under test, and asserts the round trip produces
back the exact original bytes. If a future edit ever swapped the register
order back to the *wrong* `ebx, edx, ecx` sequence (the real historical
bug), this test would immediately and clearly fail, because the encoding
step here was deliberately built using the *correct*, documented order —
this is precisely what makes it a genuine regression test (Volume 1,
§18.1) rather than merely "a test that happens to pass right now."

```python
def test_suspicious_hostname_check_flags_sandbox_token(monkeypatch) -> None:
    monkeypatch.setattr(design.socket, "gethostname", lambda: "malware-sandbox-01")
    monkeypatch.setenv("USER", "analyst")
    finding = design.check_suspicious_hostname_or_user()
    assert finding.status.value == "detected"
    assert "hostname" in str(finding.evidence)
```

This test is the concrete example of Volume 1 §18.1's **mocking**
concept: `monkeypatch.setattr(design.socket, "gethostname", lambda:
"malware-sandbox-01")` temporarily replaces the *real*
`socket.gethostname` function — as accessed specifically through
`design.py`'s own `socket` import (Chapter 7.4's `check_suspicious_
hostname_or_user` function calls `socket.gethostname()` internally) —
with a fake one that always returns a fixed, deliberately suspicious
string, for the duration of this one test only (`pytest`'s `monkeypatch`
fixture automatically restores the original function afterward, even if
the test itself fails partway through). `monkeypatch.setenv("USER",
"analyst")` similarly, temporarily overrides one specific environment
variable (Volume 1, §2.6) just for this test. This lets the test
deterministically force the exact scenario "hostname looks suspicious,
username does not" — a scenario that would otherwise be essentially
impossible to reliably reproduce on demand (you can't realistically
rename your real test machine's hostname just to run one test), and
verify the real check function's real logic correctly flags it.

### 16.3 `test_android_agent.py` — the device-unreachable regression test

```python
def test_qemu_kernel_flag_reports_error_when_device_unreachable(monkeypatch) -> None:
    monkeypatch.setattr(adb, "device_reachable", lambda serial: False)
    finding = environment.check_qemu_kernel_flag(serial=None)
    assert finding.status.value == "error"
    assert finding.evidence is None


def test_qemu_kernel_flag_clean_when_reachable_but_property_unset(monkeypatch) -> None:
    monkeypatch.setattr(adb, "device_reachable", lambda serial: True)
    monkeypatch.setattr(adb, "getprop", lambda serial, prop: None)
    finding = environment.check_qemu_kernel_flag(serial=None)
    assert finding.status.value == "clean"


def test_qemu_kernel_flag_detects_when_set_to_one(monkeypatch) -> None:
    monkeypatch.setattr(adb, "device_reachable", lambda serial: True)
    monkeypatch.setattr(adb, "getprop", lambda serial, prop: "1")
    finding = environment.check_qemu_kernel_flag(serial=None)
    assert finding.status.value == "detected"
```

These three tests together are the regression-test proof for Chapter
13.1's real bug fix — and notice they exhaustively cover *all three*
distinct outcomes the fixed function is specifically designed to tell
apart: device unreachable → `error`; reachable but property genuinely
unset → `clean`; reachable and set to `"1"` → `detected`. Writing all
three, together, as one deliberate group, is itself a good testing
practice worth internalizing: a bug about conflating two situations isn't
fully guarded against by testing just the *fixed* case in isolation — you
need a test proving each of the *distinct* situations the original bug
conflated now genuinely produces its own distinct, correct outcome.
`monkeypatch.setattr(adb, "getprop", lambda serial, prop: None)` — the
fake replacement function's parameter list (`serial, prop`) deliberately
matches the real `adb.getprop`'s actual signature (Chapter 12.1) exactly,
even though this fake implementation ignores both and always returns the
same fixed value — necessary because whatever code calls `adb.getprop(...)`
inside `check_qemu_kernel_flag` will call it positionally, with two
arguments, and a fake function with a mismatched parameter count would
raise its own, unrelated `TypeError` the moment it was actually called.

### 16.4 `test_windows_agent_report.py` — the one true integration test

```python
pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 (pwsh) not installed")


def test_windows_agent_produces_schema_valid_report(tmp_path) -> None:
    output_path = tmp_path / "windows-report.json"
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(_AGENT_SCRIPT), "-OutputPath", str(output_path)],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, f"agent failed:\nstdout={result.stdout}\nstderr={result.stderr}"

    report = json.loads(output_path.read_text(encoding="utf-8"))
    validate_report(report)  # raises ValidationError on any schema mismatch

    assert report["platform"] == "windows"
    ids = {f["id"] for f in report["findings"]}
    assert any(i.startswith("win.env.") for i in ids)
    assert any(i.startswith("win.timing.") for i in ids)
    assert any(i.startswith("win.behavioural.") for i in ids)
    assert any(i.startswith("win.design.") for i in ids)
```

This is the only test in the whole suite that genuinely runs a *real,
external, compiled/interpreted program from a different language* — no
mocking at all, the actual `pwsh` interpreter running the actual
`Invoke-Hydra.ps1` script (Chapter 11) end to end, exactly as a real user
would. `pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None,
...)` — applying this special module-level variable makes `pytest`
automatically skip *every* test in this file (rather than failing them)
on a machine where `pwsh` genuinely isn't installed, printing the given
`reason` instead — the correct, honest way to handle "this test's
prerequisite genuinely isn't available here" (distinct from "this test
failed," which would suggest a real problem rather than an environment
limitation). `tmp_path` is a built-in `pytest` **fixture** — a special
parameter name `pytest` automatically recognizes and supplies a value for
(here, a fresh, real, automatically-cleaned-up-afterward temporary
directory, `pytest`'s own version of Chapter 15's `tempfile.
TemporaryDirectory()` concept) — used here to give the real PowerShell
agent a genuine, real filesystem location to write its actual output
file to.

`{f["id"] for f in report["findings"]}` is a **set comprehension**
(Volume 1, §4.6 mentioned this variant briefly) — building a `set` of
every finding's ID, deduplicated and unordered, purely so the four
`assert any(i.startswith("win.env.") for i in ids)`-style lines can
efficiently spot-check that findings from *every one* of the four
detection categories genuinely exist in the real report — not merely that
*some* findings exist at all (a much weaker, less meaningful assertion
that could pass even if, say, an entire category's probe file had somehow
failed to load or run).

### 16.5 `test_cli.py` — testing the whole tool end-to-end, in-process

```python
def test_test_linux_writes_schema_valid_json(tmp_path) -> None:
    output = tmp_path / "linux.json"
    exit_code = main(["test", "linux", "-o", str(output), "--json"])
    assert exit_code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["platform"] == "linux"
    assert "summary" in report
```

This is precisely where Chapter 15's `main(argv: list[str] | None =
None)` design choice pays off directly: `main(["test", "linux", "-o",
str(output), "--json"])` calls the *real* CLI entry point function
in-process, passing a literal list of strings exactly as if they'd been
typed on a real command line — no need to actually spawn a subprocess,
launch a new Python interpreter, or do anything slow/heavyweight at all,
making this (and every other test in this file) fast enough to run
dozens of times per second as part of routine development, encouraging
frequent, cheap re-running of the whole suite (Volume 1, §18.1's TDD
workflow depends on tests being fast enough to run constantly, without
friction, or the whole discipline tends to break down in practice).

```python
def test_test_rejects_unknown_platform() -> None:
    try:
        main(["test", "macos"])
        raised = False
    except SystemExit as exc:
        raised = True
        assert exc.code != 0
    assert raised, "argparse should reject an unsupported platform choice"
```

This test verifies Chapter 15's `choices=_PLATFORMS` enforcement directly
— and notice it has to specifically `try`/`except SystemExit`, rather
than just calling `main([...])` plainly: when `argparse` rejects an
invalid argument, its default, built-in behavior is to print an error
message and call Python's own `sys.exit(...)` immediately, which
*raises* `SystemExit` (a genuine Python exception, despite its unusual
name and purpose — Volume 1, §3.4's exception mechanism, used here for
"the whole program should stop now" rather than "something specifically
went wrong") — this test has to catch that specific exception itself,
rather than the test simply crashing, in order to make its own assertion
about the *exit code* (`exc.code != 0`) that `argparse` chose. This is a
good example of a test needing to understand *exactly* how the code under
test signals failure (an exception here, not merely a return value) in
order to test it correctly at all.

```python
def test_report_aggregates_multiple_platforms(tmp_path) -> None:
    linux_report = tmp_path / "linux.json"
    android_report = tmp_path / "android.json"
    main(["test", "linux", "-o", str(linux_report), "--json"])
    main(["test", "android", "-o", str(android_report), "--json"])

    html_output = tmp_path / "unified.html"
    json_output = tmp_path / "unified.json"
    exit_code = main(["report", str(linux_report), str(android_report), "-o", str(html_output), "--json", str(json_output)])
    assert exit_code == 0
    assert html_output.exists()
    assert "HYDRA Unified Evasion-Probe Report" in html_output.read_text(encoding="utf-8")

    aggregate = json.loads(json_output.read_text(encoding="utf-8"))
    assert set(aggregate["platforms"]) == {"linux", "android"}
    assert aggregate["overall_summary"]["total"] > 0
```

This test is a genuine, full **end-to-end** exercise of the entire
pipeline this whole project is built around: it runs `hydra test linux`
for real, then `hydra test android` for real (no device attached, so
every Android finding will correctly come back as `error` — Chapter 14.2
— but the report is still schema-valid, which is precisely the point),
writes both real JSON files to a real temporary directory, then runs
`hydra report` (Chapter 3.5's `aggregate_reports`/`render_html`) against
both of them together, and finally verifies both the generated HTML
file's presence/content *and* the generated aggregate JSON's structure —
touching essentially every major piece of code covered across this entire
volume, in one single test function.

## Chapter 17: End-to-End Trace: What Actually Happens When You Run `hydra test linux`

This chapter ties every previous chapter together by tracing one single
command, one step at a time, from keystroke to terminal output — pointing
back to the exact file and chapter responsible for each step.

1. **The shell finds the `hydra` command.** Because HYDRA was installed
   with `pip install -e .` (Volume 1, §4.12), a small generated script
   named `hydra` exists somewhere on the system `PATH`, created from the
   `[project.scripts]` entry-point declaration (Chapter 4) — running it
   ultimately calls `hydra_cli.__main__.main()`.
2. **`main()` parses the command line.** `build_parser()` (Chapter 15)
   constructs the full `argparse` parser tree; `parser.parse_args(argv)`
   consumes `["test", "linux"]`, matches it against the `test` subparser,
   validates `"linux"` against `choices=_PLATFORMS`, and populates
   `args.platform = "linux"`, `args.serial = None`, `args.output = None`,
   `args.json = False`, `args.verbose = False`, `args.no_color = False`
   (every flag's declared default, since none were given).
3. **Dispatch to `_cmd_test`.** `test.set_defaults(func=_cmd_test)`
   (Chapter 15) means `args.func` is already `_cmd_test`; `main()`'s final
   line, `return args.func(args)`, calls it.
4. **`_cmd_test` calls `_run_agent("linux", None)`.** Matching the
   `if platform == "linux":` branch (Chapter 15), which lazily
   `import`s `hydra_linux.runner` for the first time.
5. **Importing `hydra_linux.runner` cascades through the whole Linux
   package.** Python's import machinery (Volume 1, §4.9) loads
   `hydra_linux/__init__.py` (Chapter 8.2, trivial — just re-exports
   `run_scan`), which needs `runner.py` (Chapter 8.1), which needs
   `hydra_linux.checks` (`checks/__init__.py`, Chapter 7.5), which in turn
   imports all four category modules (`environment.py`, `timing.py`,
   `behavioural.py`, `design.py` — Chapter 7), each of which imports
   `hydra_common` (Chapter 3, itself already loaded once and cached by
   Python for reuse), plus `cpu.py`, `signatures.py`, `utils.py`
   (Chapter 6).
6. **`run_scan()` executes.** `for module in CHECK_MODULES:
   findings.extend(module.run_all())` (Chapter 8.1) runs, in order,
   `environment.run_all()`, `timing.run_all()`, `behavioural.run_all()`,
   `design.run_all()` (Chapter 7) — each of those calling every individual
   `check_*` function in its file, in the fixed order each `run_all()`
   lists them.
7. **Inside `environment.run_all()`, `check_cpuid_hypervisor_bit()`
   executes** (Chapter 7.1, the worked example) — calling `cpu.cpuid(1)`
   (Chapter 6.3), which calls `_ensure_built()` (building the native
   binary via `make`, Chapter 5.1, the very first time this ever runs on a
   given machine — every *subsequent* run finds the binary already built
   and passes the `_is_runnable()` check immediately), then `_run("cpuid",
   "0x1", "0x0")`, which shells out to the real compiled `cpuid_rdtsc`
   binary (Chapter 5.2), which executes the real `CPUID` instruction on
   the real CPU via inline assembly, and prints its raw register values
   as plain text back to Python, which parses them into a `CpuidResult`
   (Chapter 6.3). Back in the check function, the hypervisor-present bit
   (Volume 1, §10.3) is tested, and `_f.bool_check(...)` (Chapter 3.4)
   returns a real `Finding` object.
8. **Every other check follows the same five-step shape** (Chapter 7.1)
   — reading `/proc`/`/sys` files (Chapter 6.1's `utils.read_text`),
   shelling out to commands (`utils.run`), or making a network request
   (§7.2's cloud-metadata check) — each independently wrapped so that any
   individual failure becomes an `error`/`skipped` `Finding`, never a
   crash (Volume 1, §18.3).
9. **`run_scan()` assembles the final `PlatformReport`.** All ~37
   `Finding` objects (Chapter 1's file-tour count) are collected into one
   `tuple`, combined with `PlatformReport.default_metadata()` (Chapter
   3.1), into one immutable `PlatformReport` instance.
10. **`.to_dict()` converts it to plain data.** Chapter 3.1's `to_dict()`
    method runs, which — via its local import — calls `score_report()`
    (Chapter 3.2), computing `raw_score` and `weighted_score` from the
    real collected findings.
11. **Back in `_cmd_test`:** since `args.output` is `None`, the
    file-writing branch (Chapter 15) is skipped; since `args.json` is
    `False`, the human-readable branch runs instead, importing
    `render_platform_text` (Chapter 3.6) and printing its output —
    sorted, colored (if stdout is a real terminal — `supports_color()`,
    Chapter 3.6), grouped findings, ending in the score line.
12. **`_cmd_test` returns `0`.** `main()` returns that same `0`;
    `raise SystemExit(main())` (Chapter 8.2's pattern, mirrored in the CLI
    too) turns it into the real process exit code the shell sees.

Every one of these twelve steps is fully covered, in complete file-level
detail, somewhere earlier in this volume — this trace exists specifically
to show how they chain together into one coherent, working system.

## Chapter 18: Case Studies — Real Bugs Caught During Development

Every bug in this chapter really happened during this project's actual
development, was really caught, and was really fixed — each one is
preserved today as a regression test (Chapter 16) and, in most cases, a
comment directly in the source explaining what went wrong. Studying real
bugs, in detail, is one of the highest-value things a developer can do —
more valuable, often, than studying only correct code, because bugs
reveal exactly which assumptions were wrong and why, which is precisely
the kind of judgment that's hardest to learn any other way. Each case
study below follows the same structure: **Symptom**, **Root Cause**,
**Fix**, **Lesson**.

### 18.1 The CPUID hypervisor-vendor register-order bug

**Symptom:** an early version of the hypervisor-vendor-string check
(Chapter 7.2/Chapter 6.3) would never correctly identify a real KVM guest
— it would run without error, but the decoded vendor string never matched
any entry in `CPUID_HYPERVISOR_VENDORS` (Chapter 6.2), even on a machine
genuinely running under KVM.

**Root cause:** the very first implementation of `CpuidResult.vendor_
string` (Chapter 6.3) decoded the raw register bytes in the order
`EBX, EDX, ECX` — which is the correct order for CPUID *leaf 0*'s vendor
string (Volume 1, §10.3), a much more commonly documented, more
frequently seen convention in general CPUID reference material. The
*hypervisor*-signature leaf (`0x40000000`), however, independently uses a
*different* order — `EBX, ECX, EDX` — per the separate convention
hypervisor vendors themselves settled on. Because both leaves produce a
syntactically valid-looking 12-character result either way (just the
*wrong* 12 characters, when decoded with the wrong order), this bug
produced no error, exception, or crash of any kind — it silently, quietly
decoded to meaningless garbage text that coincidentally never happened to
match a real signature, making a genuinely virtualized KVM guest
incorrectly, silently report `clean` on this specific check.

**Fix:** `CpuidResult.vendor_string`'s implementation (Chapter 6.3) was
corrected to `self.ebx.to_bytes(...) + self.ecx.to_bytes(...) +
self.edx.to_bytes(...)` — the `EBX, ECX, EDX` order. The exact same
correct order was independently, carefully replicated in the PowerShell
Windows agent's `Test-CpuidHypervisorVendor` function (Chapter 10.1's
sibling), with an explicit comment cross-referencing the Linux agent's
own bug and fix, specifically so the same mistake wouldn't get
independently reintroduced on the Windows side by someone unaware of the
Linux history.

**Regression test:** `test_cpuid_vendor_string_decode_order_is_ebx_ecx_edx`
(Chapter 16.2), which deliberately builds a `CpuidResult` from
*known-correct*, hand-encoded register values and asserts the decoded
string round-trips correctly.

**Lesson:** *a bug that produces no crash and no obviously wrong-looking
output is far more dangerous than one that does* — this bug would have
silently undermined the single most reliable check in the entire Linux
agent, indefinitely, with nothing in the tool's own behavior ever hinting
that anything was wrong. When two superficially similar operations (two
different CPUID leaves' string-decoding, here) turn out to have a subtle,
undocumented-at-a-glance difference between them, that difference deserves
an explicit code comment *and* a dedicated regression test — not just a
one-time careful reading during initial development, which is exactly how
this bug got introduced in the first place despite careful work.

### 18.2 The stale cross-architecture native binary bug

**Symptom:** while testing the Linux agent inside Docker containers
(Volume 1, §13.4) across two different container architectures (native
`linux/arm64` and emulated `linux/amd64`, via Docker's `--platform`
flag), CPUID/RDTSC-dependent checks would sometimes silently report
`skipped` inside the `amd64` container, even though that container was
genuinely running on (emulated) x86-64 hardware where CPUID absolutely
should have been available and working.

**Root cause:** the repository was mounted into both containers via a
Docker **bind mount** (making the *same* files on disk directly visible
inside multiple different containers at once, rather than each container
getting its own independent copy) — meaning a `cpuid_rdtsc` binary,
already compiled once for the host machine's *own* real architecture
(arm64, on the Apple Silicon Mac being used for development, Volume 1
§10.1), was still sitting on disk, left over, when the `amd64` container
started up and looked for it. `_ensure_built()`'s original, earlier
version (Chapter 6.3) only checked `_BINARY.exists()` before deciding
whether a rebuild was needed — a stale arm64 binary genuinely *did*
exist on disk, so the original code (incorrectly) concluded no rebuild
was necessary, and then tried to *execute* that arm64 binary directly
inside the amd64 container. Attempting to run a binary compiled for the
wrong CPU architecture fails at the operating system's own `exec()` level
(the OS refuses to even start running it at all) — which the original
code's exception handling caught and treated identically to "the primitive
is genuinely unavailable here," silently converting a completely
avoidable stale-cache problem into a false `skipped` result, with no
visible error anywhere.

**Fix:** the `_is_runnable()` function (Chapter 6.3) was added
specifically to close this gap — rather than trusting mere *file
existence* as proof a binary is usable, it actually *executes* the binary
(with no arguments) and verifies it produces the one specific,
deterministic exit code (`1`, the usage error — Chapter 5.2's `main()`)
that only a correctly-built, architecture-appropriate binary can ever
produce; a binary that's wrong for the current architecture fails at
`exec()` entirely, which `_is_runnable()` catches as an `OSError` and
correctly reports as "not runnable," triggering `_ensure_built()` to
delete and rebuild it fresh.

**Lesson:** *"the file exists" and "the file works, here, right now" are
two genuinely different, independently-checkable facts* — this is a
specific instance of Volume 1's broader §4.5 lesson about not conflating
"absence of one specific problem" with "genuine correctness," extended
here from data values to compiled binaries. Any time a program caches a
built artifact across potentially different environments (this
project's own Docker-based cross-architecture testing being an unusually
sharp, fast way to *surface* this class of bug — most projects would only
discover it much later, after a genuinely different machine tried to
reuse a stale cached build), it's worth asking explicitly: "how would I
know if this cached thing is actually wrong for *this* environment,
specifically, right now?"

### 18.3 The Android "device unreachable" vs. "property genuinely unset" conflation

**Symptom:** when no Android device/emulator was reachable at all,
`check_qemu_kernel_flag` (Chapter 13.1) would incorrectly report `clean`
— a deeply misleading result, since "clean" is supposed to specifically
mean "checked, and found nothing wrong," while in reality *nothing had
been checked at all*.

**Root cause:** `adb.getprop()`'s return value (Chapter 12.1) is `None`
in *two* genuinely different situations that its own type signature
cannot distinguish: the device is unreachable (so the property's real
value is simply unknown), or the device answered successfully but this
specific property genuinely isn't set (the normal, expected, correct
state on real, unmodified hardware). The original version of `check_
qemu_kernel_flag` called `adb.getprop()` directly and treated *any* `None`
result identically as "property unset, therefore clean" — which happens
to be the *correct* interpretation in the second case, but silently,
incorrectly wrong in the first.

**Fix:** the check was rewritten to call `adb.device_reachable(serial)`
(Chapter 12.1) *explicitly, first*, before ever calling `getprop()` at
all (Chapter 13.1's full, corrected code) — only once reachability is
independently confirmed does a subsequent `None` from `getprop()`
get treated as the genuinely-clean "property unset" case; an unreachable
device now correctly, immediately produces an `error` finding instead.

**Regression tests:** three separate tests, deliberately covering all
three distinct outcomes together (Chapter 16.3) —
`test_qemu_kernel_flag_reports_error_when_device_unreachable`,
`test_qemu_kernel_flag_clean_when_reachable_but_property_unset`, and
`test_qemu_kernel_flag_detects_when_set_to_one`.

**Lesson:** *when a lower-level function's return type conflates two
meaningfully different situations into one value (here, `None` meaning
either "don't know" or "checked, and it's absent"), every caller that
cares about the difference must resolve the ambiguity itself, explicitly,
rather than assuming the simpler of the two interpretations by default.*
This is precisely the same underlying principle as bug 18.2 above,
appearing again in a completely different part of the codebase — a good
sign that it's a genuinely general, transferable lesson, not a one-off
fluke specific to CPUID binaries.

### 18.4 PowerShell's `[string]` parameter silently coercing `$null` to `""`

**Symptom:** early testing of the Windows agent's JSON output showed
`remediation`/`error_detail` fields coming back as empty strings `""` on
`clean` findings, where the Python-side schema (Chapter 2) and every
Python-produced report instead correctly used JSON's genuine `null` for
exactly this situation.

**Root cause:** `New-HydraFinding`'s original parameter declarations
used explicit `[string]$Remediation = $null` type constraints (Chapter
9.1 covers the corrected version). PowerShell's parameter-binding system,
when a parameter is explicitly typed, automatically attempts to *convert*
whatever value is actually passed into that declared type — and
PowerShell's built-in conversion rule for turning `$null` into a `[string]`
specifically produces an empty string, not a preserved `$null` — this
conversion happens silently, with no warning or error at all, deep inside
PowerShell's own parameter-binding machinery, entirely invisible from the
function's own body.

**Fix:** the `[string]` type constraint was removed entirely from these
specific parameters (Chapter 9.1's `$Evidence = $null`, `$Remediation =
$null`, `$ErrorDetail = $null` — genuinely untyped, left as PowerShell's
generic, universal object type), letting `$null` actually stay `$null`
all the way through to the final `[PSCustomObject]` construction and,
eventually, `ConvertTo-Json`'s own correct `$null`-to-JSON-`null`
conversion.

**Lesson:** *a language's own type system can itself be a source of
silent, surprising data corruption, not just a safety net* — this is a
genuinely PowerShell-specific gotcha (Python's own type hints, Volume 1
§4.3, are unenforced and therefore *couldn't* cause this specific class of
bug, for a completely different reason: they simply never touch runtime
values at all) — a good, concrete reminder that every language has its
own specific set of sharp edges, and porting a design from one language to
another (Python's `Finding` dataclass to PowerShell's `New-HydraFinding`
function, here) requires understanding *both* languages' actual runtime
behavior in detail, not just their surface-level syntax similarity.

### 18.5 `Write-Host` silently polluting stdout with non-JSON text

**Symptom:** the Python CLI's Windows-agent integration (Chapter 15's
`_run_windows_agent`) would occasionally fail to parse the Windows
agent's JSON output at all, with a `json.JSONDecodeError` — even though
the PowerShell script itself reported success.

**Root cause:** an earlier version of `Invoke-Hydra.ps1` (Chapter 11) used
PowerShell's `Write-Host` cmdlet for its status/summary messages ("Wrote
report to ...", the final score summary). `Write-Host` looks, superficially,
like an ordinary "print this to the screen" command — but it specifically
writes to a distinct PowerShell **information stream**, which,
critically, still gets merged back into the *same* stdout file descriptor
a calling process observes when that stdout is being captured
programmatically (as `subprocess.run(..., capture_output=True)`, Chapter
15, does) — meaning these status messages ended up interleaved directly
into the same stdout text as the actual JSON report, corrupting it from
the calling Python code's point of view even though, to a human watching
the terminal directly, everything looked completely normal and
well-formatted.

**Fix:** every status/summary message was switched to
`[Console]::Error.WriteLine(...)` (Chapter 11's final version) — reaching
directly into .NET's own `System.Console` class to write unambiguously to
the real OS-level stderr stream, entirely bypassing PowerShell's own
`Write-Host`/information-stream abstraction layer.

**Lesson:** *a convenience feature designed for interactive human use
(`Write-Host`'s simple, colorful terminal output) can behave in a
genuinely surprising, non-obvious way once a script is being run
*programmatically*, by another program, rather than watched directly by a
human* — this is a specific instance of Volume 1's §5.6 stdout/stderr
discipline being violated by a tool feature that doesn't advertise, in
its own name or documentation, that it might interact unexpectedly with
stream redirection/capturing. Whenever a script is meant to be both
human-runnable *and* machine-composable (this project's stated design
goal for every agent), it's worth explicitly verifying its actual raw
stdout stays clean under real subprocess capture, not just checking that
its terminal output *looks* fine to a human eye.

### 18.6 `System.Drawing.Point` failing to compile via `Add-Type`

**Symptom:** the Windows agent's mouse-movement check (Chapter 10.2)
failed to even *compile*, with the error:
```
error CS1069: The type name 'Point' could not be found in the namespace 'System.Drawing'.
This type has been forwarded to assembly 'System.Drawing.Primitives'...
```

**Root cause:** modern .NET (the cross-platform runtime PowerShell 7 runs
on, Volume 1 §6.4) reorganized many of its older classes into smaller,
more granular assemblies (a .NET "assembly" being roughly a packaged
unit of compiled code/types, conceptually similar to a shared library,
Volume 1 §6.5's DLL concept) — `System.Drawing.Point` specifically now
actually lives in a separate assembly, `System.Drawing.Primitives`, with
only a lightweight "forwarding" reference left in the original location.
`Add-Type`'s inline C#-compilation feature (Chapter 9.1), by default,
only automatically references a fairly minimal, fixed set of common
assemblies — and `System.Drawing.Primitives` isn't among them — so a
P/Invoke declaration (Volume 1, §6.5) that tried to use the real
`System.Drawing.Point` type directly as a parameter simply failed to
compile at all, on this specific modern-.NET/PowerShell-7 combination
(even though, notably, the exact same code might well have compiled fine
under the older, Windows-only "Windows PowerShell 5.1," which resolves
this assembly reference differently — a real, environment-specific
compatibility gap).

**Fix:** rather than referencing `System.Drawing.Point` at all, a
minimal, custom `POINT` struct was declared directly inside the same
`Add-Type` block (Chapter 10.2's final version) — `public struct POINT {
public int X; public int Y; }` — an exact structural match for what the
real Win32 `GetCursorPos` API actually expects (P/Invoke only cares that
a struct's raw memory layout matches what the native function expects; it
doesn't require using any particular *named* .NET type to achieve that,
as long as the fields, types, and order line up correctly), sidestepping
the assembly-reference problem entirely by not depending on the
problematic type at all.

**Lesson:** *when a P/Invoke declaration needs a data structure "shape"
that a convenient, pre-existing named type happens to already match,
reaching for that existing type isn't always safe across different
runtime versions/environments — declaring your own minimal, purpose-built
struct, matching only the exact fields actually needed, is often the more
robust, more portable choice*, even though it's slightly more code to
write up front. This bug was specifically caught by testing the Windows
agent's real PowerShell code, for real, on macOS (Volume 1's §6.1
cross-platform PowerShell point) — a good, concrete example of why
running (not just reading) code on the actual, real target execution
environment during development surfaces problems that reading the code
carefully, or reasoning about it in the abstract, would not have caught
in advance.

### 18.7 Self-caught: a redundant wrapper function in the Android behavioral checks

**Symptom:** none, from a user's point of view — this was caught during
the project's own development, before it ever shipped, not in response to
any observed failure.

**Root cause:** an early draft of `agents/android/hydra_android/checks/
behavioural.py` (Chapter 13.3) contained a small, genuinely redundant
piece of code: a public `check_battery_temperature()` function whose
entire body was just a single call to a differently-named, near-identical
inner function, `check_battery_temperature_for(None)` — two functions
doing the exact same job, with no meaningful difference between them,
existing only because of how the code evolved incrementally during
writing.

**Fix:** consolidated back down into one single function,
`check_battery_temperature(serial: str | None = None)`, taking `serial`
as a normal, ordinary parameter exactly like every other check function
in the entire project — removing the unnecessary, dead indirection
entirely.

**Lesson:** unlike the six bugs above, this wasn't caught by a test, a
user report, or an external code review — it was caught by the person
writing the code, re-reading their own recent work with a specific
question in mind: *"does this abstraction genuinely earn its keep, or is
it just accumulated incremental cruft?"* This is worth including
specifically because most of this project's own working conventions (the
"no dead code," "no premature abstraction" principles from Volume 1
§18.5-adjacent style guidance) exist precisely to catch this *category* of
issue — and this is a real, concrete example of those principles actually
working, in practice, as ordinary day-to-day self-review discipline,
rather than only as abstract rules stated in a style guide.

## Chapter 19: Rebuild It Yourself — A Step-by-Step Guide From an Empty Folder

This chapter is the payoff for everything before it: a concrete, ordered
build sequence, starting from a genuinely empty directory, that arrives at
the complete HYDRA project. Every step names the exact file(s) to create
and points back to the chapter that explains its full content — follow
this order and every file you write will only ever depend on something
you've *already* built, never something still ahead of you.

**Step 0 — Prerequisites.** Install Python 3.10+, a C compiler (`cc`/
`gcc`/`clang` — already present on virtually every Linux/macOS system;
Volume 1 §7.3), and, if you want to test the Windows agent too,
PowerShell 7+ (`pwsh`, installable on Linux/macOS/Windows alike — Volume
1 §6.1). Create an empty directory and `git init` it (Volume 1, §8.2).

**Step 1 — The schema first.** Create `schema/hydra-report.schema.json`
exactly as described in Chapter 2. This is deliberately the very first
file, because every other file's *shape* is defined by it — writing any
agent code before the schema exists would mean designing the shape
piecemeal, ad hoc, with no single source of truth to check any of it
against.

**Step 2 — The Python packaging skeleton.** Create `pyproject.toml`
(Chapter 4) with the `[project]`, `[project.optional-dependencies]`,
`[project.scripts]`, `[build-system]`, and `[tool.setuptools]` blocks —
even though the packages it references (`hydra_common`, `hydra_linux`,
etc.) don't exist as real directories yet. This is fine: `pyproject.toml`
is just configuration, read only when you actually try to `pip install`
the project, which you won't do until Step 6.

**Step 3 — `hydra_common`, the shared foundation.** Create
`common/python/hydra_common/` and, in this exact internal order (each
depends only on the ones before it):
1. `models.py` (Chapter 3.1) — the four enums, `Finding`, `PlatformReport`.
2. `scoring.py` (Chapter 3.2) — depends on `models.py`'s `Finding`/
   `Status`/`Severity`.
3. `validation.py` (Chapter 3.3) — depends on nothing else in the
   package (deliberately dependency-free, working only against plain
   dicts).
4. `finding_factory.py` (Chapter 3.4) — depends on `models.py`.
5. `report.py` (Chapter 3.5) — depends on `models.py`, `scoring.py`,
   `validation.py`.
6. `text_format.py` (Chapter 3.6) — depends on nothing else in the
   package (also works against plain dicts, by design, mirroring
   `validation.py`'s independence).
7. `__init__.py` (Chapter 3.7) — written *last*, since it re-exports names
   from every file above it.

**Verify Step 3 immediately**, before moving on: write
`tests/test_common.py` (Chapter 16.1) now, and run it (`pip install -e
".[dev]"` then `pytest tests/test_common.py -v`). Confirming the
foundation is solid before building anything on top of it is worth the
short pause — every later step depends on this one being correct.

**Step 4 — The Linux agent's native helper.** Create
`agents/linux/native/cpuid_rdtsc.c` (Chapter 5.2) and `agents/linux/
native/Makefile` (Chapter 5.1). Verify it builds and behaves correctly
standalone, *before* writing any Python that depends on it:
```bash
cd agents/linux/native && make && ./cpuid_rdtsc cpuid 0x1 0x0 && ./cpuid_rdtsc rdtsc_jitter 100
```
On x86 hardware, this should print real register values and real timing
statistics; on non-x86 hardware, it should print the "not available on
this architecture" message and exit with code 2 (Chapter 5.2) — either
outcome is correct and expected; what matters is confirming it behaves as
designed before building the Python wrapper on top of it.

**Step 5 — The rest of the Linux agent, bottom-up.** Inside
`agents/linux/hydra_linux/`, in order:
1. `utils.py` (Chapter 6.1) — no internal dependencies.
2. `signatures.py` (Chapter 6.2) — pure data, no dependencies.
3. `cpu.py` (Chapter 6.3) — depends on the native binary from Step 4.
4. `checks/environment.py`, `checks/timing.py`, `checks/behavioural.py`,
   `checks/design.py` (Chapter 7) — each depends on `hydra_common`
   (Step 3), plus `cpu.py`/`signatures.py`/`utils.py` as needed.
5. `checks/__init__.py` (Chapter 7.5) — depends on all four check
   modules existing first.
6. `runner.py` (Chapter 8.1) — depends on `checks/__init__.py`.
7. `__main__.py` and `__init__.py` (Chapter 8.2) — depend on `runner.py`.

**Verify Step 5:** `python3 -m hydra_linux` should now print a complete,
real, schema-valid JSON report of your own machine to the terminal.
Write and run `tests/test_linux_agent.py` (Chapter 16.2) at this point.

**Step 6 — The Android agent, in the same bottom-up order.** Inside
`agents/android/hydra_android/`:
1. `adb.py` (Chapter 12.1).
2. `signatures.py` (Chapter 12.2).
3. `checks/environment.py`, `checks/timing.py`, `checks/behavioural.py`,
   `checks/design.py` (Chapter 13).
4. `checks/__init__.py`, `runner.py`, `__main__.py`, `__init__.py`
   (Chapter 14, mirroring Steps 5.5-5.7 exactly).

**Verify Step 6:** `python3 -m hydra_android` (with or without a real
device/emulator attached — either way should produce a schema-valid
report, per Chapter 14's design). Write and run `tests/test_android_agent.py`
(Chapter 16.3).

**Step 7 — The Windows agent, independently, in parallel with (or after)
Steps 4-6.** Because this agent shares no actual code with the Python
side (only the schema, from Step 1), it can genuinely be built at any
point after Step 1 — build it last if you want a working Python-only
subset sooner, or build it alongside the Python agents if you have
`pwsh` available for continuous testing throughout. Inside
`agents/windows/`:
1. `common/Signatures.ps1` (Chapter 9.2) — pure data.
2. `common/Hydra.Common.psm1` (Chapter 9.1) — depends on nothing but
   PowerShell/.NET itself.
3. `probes/Environment.ps1`, `probes/Timing.ps1`,
   `probes/Behavioural.ps1`, `probes/Design.ps1` (Chapter 10) — each
   depends on `Hydra.Common.psm1` and `Signatures.ps1` being dot-
   sourced/imported first (handled by the entry point, next).
4. `Invoke-Hydra.ps1` (Chapter 11) — the entry point tying everything
   above together.

**Verify Step 7:** `pwsh -File Invoke-Hydra.ps1` should print a complete,
real, schema-valid JSON report — this works even on macOS/Linux, per
Chapter 11's design, degrading Windows-only checks to `error`/`skipped`
gracefully rather than crashing. Write and run
`tests/test_windows_agent_report.py` (Chapter 16.4).

**Step 8 — The CLI, tying every agent together.** Create
`cli/hydra_cli/__main__.py` (Chapter 15) — this is deliberately one of
the *last* files written, since it depends on every agent (Steps 5-7)
already existing and working independently first. Update
`pyproject.toml`'s `package-dir`/`packages`/`[project.scripts]` entries
(Chapter 4) to include `hydra_cli` if you hadn't already anticipated it
in Step 2.

**Verify Step 8:** reinstall (`pip install -e ".[dev]"` again, to pick up
the new `hydra` entry point) and run `hydra test linux`, `hydra test
android`, and (if `pwsh` is available) `hydra test windows` — each should
produce the colored terminal summary described in Chapter 3.6. Write and
run `tests/test_cli.py` (Chapter 16.5).

**Step 9 — Run the complete test suite together, and check formatting.**
```bash
pytest tests/ -q
black --check .
isort --check-only .
ruff check .
```
All tests should pass; all three formatting/linting tools should report
no issues (Volume 1, §18.5). This is the point at which you have a
complete, working, tested reimplementation of the entire HYDRA project.

**Step 10 — Documentation.** Write `docs/ARCHITECTURE.md` and
`docs/CHECK_COVERAGE.md`, and per-agent `README.md` files — not because
the *code* depends on them in any way, but because a project without
documentation explaining *why* it's built the way it is quickly becomes
much harder for anyone (including your own future self) to maintain or
extend correctly — precisely the problem this two-volume document set
itself was written to solve for HYDRA specifically.

## Chapter 20: How to Extend HYDRA Yourself

Having rebuilt the project (Chapter 19), here is exactly how to extend it
— each scenario points to the precise files you'd touch and the precise
pattern to follow, drawn directly from patterns already used throughout
the real codebase.

### 20.1 Adding a new check to an existing platform/category

Say you want to add a new Linux `environment_artifact` check. Open
`agents/linux/hydra_linux/checks/environment.py` (Chapter 7):

1. If your check needs new signature data, add it to
   `agents/linux/hydra_linux/signatures.py` (Chapter 6.2) first — a new
   tuple or dict, following the existing naming convention.
2. Write a new function following the exact five-part skeleton from
   Chapter 7.1: declare `check_id`/`name` (following the
   `platform.category.check_name` convention the schema enforces,
   Chapter 2), declare `description`, gather your data (reading a file
   via `utils.read_text`, running a command via `utils.run`, or querying
   `cpu.py`), handle the "couldn't determine" case first with `_f.error(...)`
   or `_f.skipped(...)` (Chapter 3.4 — `error` for "this genuinely failed
   to run," `skipped` for "this doesn't apply on this host/architecture"),
   then compute your verdict and return `_f.bool_check(...)`.
3. Add your new function's name to that file's `run_all()` list at the
   bottom (Chapter 7.1's final structural piece).
4. Write at least one test in `tests/test_linux_agent.py` (Chapter 16.2)
   — at minimum, one test proving the `detected` path fires correctly and
   one proving the `clean` path fires correctly, using `monkeypatch`
   (Volume 1, §18.1) to force each scenario deterministically, exactly
   like Chapter 16.2's worked examples.
5. Update `docs/CHECK_COVERAGE.md` and `agents/linux/README.md`'s check
   table, and re-run `wc -l` on the check count to keep the README's
   stated total accurate.

The exact same five steps apply, with the obvious file-path substitutions,
for adding a check to any of the other eleven Windows/Android check
modules — the *pattern* never changes, only which language's syntax
you're writing it in (Chapter 10.1 for the PowerShell equivalent of step
2).

### 20.2 Adding an entirely new detection category

This is a bigger change, touching the schema (Chapter 2) — the single
source of truth every other file depends on:

1. Add the new category string to `schema/hydra-report.schema.json`'s
   `category` enum (Chapter 2).
2. Add the corresponding member to `Category` in `hydra_common/models.py`
   (Chapter 3.1) — Python side.
3. Add it to `hydra_common/scoring.py` if the new category needs its own
   severity-weighting behavior (unlikely — `SEVERITY_WEIGHT`, Chapter 3.2,
   is already category-independent by design, weighting purely by
   severity regardless of category, so this step is usually a no-op).
4. Add it to `hydra_common/validation.py`'s `_CATEGORIES` set (Chapter
   3.3) — otherwise every report using the new category would
   immediately fail validation.
5. Add the matching `[ValidateSet(...)]` entry in every PowerShell
   function in `Hydra.Common.psm1` that currently lists all four
   categories (Chapter 9.1) — there are two: `New-HydraFinding` and
   `New-HydraBoolFinding`.
6. Create the new `checks/<new_category>.py` (and `.ps1`) file in every
   platform you want to support it on, following Chapter 7.1's skeleton.
7. Add the new module to every platform's `CHECK_MODULES` tuple (Chapter
   7.5) and `Invoke-Hydra.ps1`'s `$findings +=` list (Chapter 11).
8. Update `docs/ARCHITECTURE.md`'s category list (Volume 1, Chapter 15
   covers *why* the current four categories are the ones they are — a
   genuinely new category should have an equally clear, real technical
   rationale, not just "one more bucket").

### 20.3 Adding a fourth platform

Say a future contributor wanted to add, hypothetically, a macOS agent.
Following this project's own established pattern (Chapter 1's "why this
layout" reasoning) exactly:

1. Add `"macos"` to the schema's `platform` enum (Chapter 2), and every
   Python/PowerShell mirror of that enum (`Platform` in `models.py`,
   `_PLATFORMS` in `validation.py`, `-ValidateSet` lists in the Windows
   PowerShell files).
2. Create `agents/macos/` following whichever existing agent's structure
   is the closer fit — likely mirroring the Linux agent's Python
   structure closely (Chapters 6-8), since macOS, like Linux, is a
   Unix-family OS with its own set of `/proc`/`/sys`-adjacent (though
   not identical) low-level system-introspection mechanisms, and its own
   completely different equivalent of DMI/SMBIOS data and hypervisor
   detection primitives that would need their own dedicated research
   (this is exactly the kind of "genuine domain research required, not
   just code-structure copying" step Volume 1's Chapter 12/§17
   discussion of Pafish/al-khaser/VMAware's own platform-specific
   technique catalogs was really about).
3. Wire the new agent into `cli/hydra_cli/__main__.py`'s `_PLATFORMS`
   tuple and `_run_agent()` dispatcher (Chapter 15) — exactly one new
   `if platform == "macos":` branch, mirroring the existing three.
4. Write `tests/test_macos_agent.py` following the existing test files'
   patterns (Chapter 16), and a `agents/macos/README.md` following the
   existing per-agent README structure.

### 20.4 Adding a new CLI subcommand

Following Chapter 15's `subparsers`/`set_defaults(func=...)` pattern
exactly: define a new `_cmd_whatever(args: argparse.Namespace) -> int`
function, register it with `subparsers.add_parser("whatever", ...)`,
declare its specific arguments with `.add_argument(...)`, and finish with
`whatever.set_defaults(func=_cmd_whatever)` — `main()`'s own dispatch
logic (Chapter 15's final lines) requires no changes at all to support an
arbitrary number of subcommands, by design.

## Chapter 21: Final Checklist

Use this as a self-assessment after finishing both volumes — if you can
genuinely do everything on this list without looking anything up, you
have mastered this project to the depth these two volumes set out to
reach.

**From Volume 1 (Foundations):**
- [ ] Explain, from memory, what CPUID leaf `0x40000000` returns and in
  which register order — and explain *why* that order differs from leaf
  0's.
- [ ] Explain what a VM exit is, why `CPUID` reliably triggers one under
  KVM, and why that makes `RDTSC`-based timing a meaningful detection
  signal.
- [ ] Explain the difference between a Type 1 and Type 2 hypervisor, and
  where KVM/QEMU fit into that distinction.
- [ ] Explain why SMBIOS/DMI data is such a rich detection signal, and
  why HYDRA's Windows agent reads it through two independent mechanisms.
- [ ] List all four detection categories from memory, with two concrete
  example checks each.
- [ ] Explain what Pafish, al-khaser, and VMAware each are, and precisely
  what gap none of them close that HYDRA was built to close.
- [ ] Explain the difference between `error` and `skipped` status, and
  give a real example of each from the actual codebase.

**From Volume 2 (The Source):**
- [ ] Explain why the native C helper exists at all, and reproduce its
  architecture-guard logic from memory.
- [ ] Explain the five-part check-function skeleton, and write a brand
  new, syntactically correct check function for a hypothetical new
  signature, unaided.
- [ ] Explain all seven real bugs from Chapter 18, in your own words,
  including root cause and fix for each.
- [ ] Trace, from memory, everything that happens between typing
  `hydra test linux` and seeing output, without re-reading Chapter 17.
- [ ] Given an empty folder, rebuild the project's file structure and
  dependency order from memory, matching Chapter 19's sequence.

If any of these feel shaky, that's a precise, actionable signal pointing
back to a specific chapter — not a sign you've failed at anything. Go
back, reread that one section, and come back to this checklist again.
That loop — read, build a mental model, test the model against a
checklist, patch the gaps — is, itself, the single most transferable
skill either of these two volumes has to offer. It will serve you on the
next project, too, whatever it turns out to be.

---

**End of Volume 2, and of this two-volume set.** Between Volume 1's
foundations and this volume's complete, line-by-line account of every
file in the HYDRA repository, you now have everything needed to
understand, maintain, extend, and — if you ever needed to — rebuild this
entire project from nothing, without consulting any other source. That
was the goal from the first page. Go build something.

