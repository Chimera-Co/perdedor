# Apple drivers

Reviewed 2026-11-09 against the merged Apple worktree at `d62b9a2`.
There are **116 macOS checks across 68 techniques** and **73 iOS checks across
30 techniques**. All 189 registered ids have an implemented catalog entry with
an identical technique, severity, cost and network flag. Ten additional entries
record limitations; they are not registered or reported as implemented.

| Class | macOS | iOS |
|---|---:|---:|
| analysis_tools | 15 | 3 |
| artifacts | 1 | 0 |
| container | 1 | 0 |
| cpu | 5 | 0 |
| debugger | 2 | 2 |
| emulator | 4 | 8 |
| firmware | 6 | 0 |
| guest_tools | 6 | 0 |
| hardware | 12 | 0 |
| human | 4 | 0 |
| identity | 6 | 1 |
| instrumentation | 4 | 10 |
| integrity | 0 | 22 |
| mobile_device | 2 | 4 |
| network | 11 | 7 |
| os_config | 9 | 0 |
| resources | 5 | 3 |
| timing | 3 | 3 |
| wear_and_tear | 20 | 10 |
| **Total** | **116** | **73** |

## Running

The existing package declarations and console entry points are retained.
Both agents use only the Python standard library on the driver host. No target
package, service or native helper is installed.

```sh
perdedor-macos --local --no-network -o macos-report.json
perdedor-macos --ssh user@host -i /path/to/key -p 22 --no-network
perdedor-ios --ssh root@device -i /path/to/key -p 2222 --no-network
perdedor-ios --simulator booted --no-network
perdedor-macos --list-checks --profile deep
perdedor-ios --only class:emulator --simulator DEVICE-UDID --no-network
```

SSH uses key authentication, bounded connection attempts and normal host-key
verification. Use the logged-in desktop user's SSH account for macOS user
preferences and wear-and-tear checks. A root or different user's shell does not
represent the desktop user's home directory or launchd environment. The iOS
transport adds the usual `/var/jb` bootstrap executable directories to PATH.

The standard profile excludes the slow input sampling and sleep probes. Explicit
selection or the deep profile enables them. `human.window_seconds` accepts a
finite window above zero and at most 30 seconds; `timing.sleep_seconds` accepts
1–30 seconds. Catalog `params` describe the exposed resource, age, process,
update and timing limits.

## Implementation decisions

- Automatic `CHECKS` discovery, common selection flags, `RunContext` and
  `PlatformReport` remain the public interfaces. macOS and iOS share transport,
  parsing and finding helpers; iOS adds its target and simulator handling.
- macOS covers kernel/hardware identity, I/O Registry, system profiler hardware,
  displays, USB, storage, network, power, loaded guest modules, guest tools,
  SIP/authenticated root/Gatekeeper, XProtect/MRT, analysis applications and
  processes, DYLD environment, P_TRACED, input and GUI presence, user activity
  traces, locale, network and timing. Unified Mac identifiers such as `Mac14,2`
  use the profiler's hardware family when deciding whether a battery or built-in
  camera is expected. MRT and background-task entries also report inventories;
  MRT replacement by XProtect is not treated as a missing security component.
- iOS covers rootful/rootless bootstrap and jailbreak paths, package managers,
  jailbreak applications, declared URL schemes, suspicious symlinks, root mount
  state, injection libraries, visible SpringBoard mappings, Frida/Cycript,
  debugger flags and application parents, developer and Lockdown preferences,
  proxy/trust settings, VPN-like interfaces, virtual identities, telephony,
  radio and motion services, and personal-store counts.
- File and process inspection never changes target state. There is no sandbox
  escape write test, ptrace call, fork test, code injection or native instruction
  probe. A writable root mount is a separate filesystem observation and cannot
  establish an application's ability to escape its container.
- Failed commands, unsupported formats, missing capabilities and denied reads
  return errors or skips. They do not become clean findings. Partial sysctl
  responses remain usable when only some queried keys exist on that kernel.
  Queries and directory inventories are cached per scan.
- Normal checks have a nine-second command budget; slow checks have a
  100-second budget, below the design limits. Processes run in a separate group
  and are killed on timeout; output is capped at 4 MiB. Directory results over
  5,000 entries remain unknown. Application-container scans stop at 400 entries.
- Personal data stays on the target: histories use metadata or SQL aggregates,
  contacts/messages/calls/accounts use only `SELECT count(*)`, and photographs
  use counts. Shell commands, message bodies, contact names and photo filenames
  are not reported. SQLite uses `mode=ro&immutable=1` to prevent journal/SHM
  creation. Counts describe the immutable database file snapshot and can omit
  recent WAL-only transactions; schema changes or missing sqlite3 return unknown.
- Active probes contact only a fresh random `.invalid` name or
  `169.254.169.254`. Curl ignores user configuration, disables proxy use, follows
  no redirects and has a five-second deadline. `--no-network` prevents these
  checks from executing. Passive network configuration checks still run.
- Simulator resolution requires one available, booted device and explicit data
  and runtime roots from simctl. Paths map into those roots, and traversal or
  symlinks escaping them are rejected. Failed resolution never falls back to
  host `/Applications`, `/var` or `/etc`. Simple commands use `simctl spawn`
  without assuming the runtime contains a shell. Unsupported compound commands
  and missing runtime utilities remain unknown. Simulator kernel/process views
  share the host kernel; they are not an independent physical-device observation.

## Thresholds and interpretation

`MAC_MEMSIZE` retains VMAware's inclusive 4,000,000,000-byte boundary. The
12-minute uptime boundary follows Pafish. Scarcity limits such as five third-party
applications, two folder items, 64 KiB browser histories, 150 processes,
14-day setup age, 120-day update age, ten iOS apps and twenty photos are **local
policies**, not manufacturer specifications or statistically calibrated limits.
The signature modules and catalog parameters identify them. Sparse real systems,
headless machines and freshly provisioned physical devices can trigger them.

The old Intel hyperthreading heuristic is weak on recent hardware. Performance
level count, absent peripheral services, VPN-like interfaces, missing store
metadata and user trust records also have limited discrimination. A VPN can be
legitimate; a user certificate need not be an interception certificate. Rosetta's
VirtualApple brand indicates translation and does not alone prove a VM.

The `requires` list identifies optional privileged or interactive checks. Other
requirements depend on transport: local macOS or SSH for macOS; SSH with an
appropriate bootstrap, or a booted Simulator with Xcode command-line tools, for
iOS. Missing utilities are never installed automatically.

## Source mappings and coverage

Mappings use the `equivalents_key` in `catalog/upstreams.json` and exact names
from the checked-in inventories. Tests reject unknown keys and misspellings.
For applicable freeRASP conditions, both callback and Flutter names are listed,
for example `onPrivilegedAccess` and `privilegedAccess`.

An equivalent marks the same observable condition, not complete implementation
of every branch of a composite upstream API. For example, jailbreak artifact
checks represent branches of IOSSecuritySuite's three jailbreak APIs; they do not
perform its write, fork or Objective-C checks. P_TRACED is observed on visible
processes, not by injecting the upstream SDK into an application. URL declarations
are not claimed as successful `canOpenURL` registration tests. Receipt absence is
not mapped as proof of an unofficial installer. Hook-library presence is not
mapped as proof that a selected function was patched.

Repository-wide coverage output after this change:

| Inventory | Total | Covered | Planned | Not feasible | Missing | Covered |
|---|---:|---:|---:|---:|---:|---:|
| VMAware v2.8.2 | 81 | 62 | 5 | 3 | 11 | 76.5% |
| IOSSecuritySuite 2.3.0 | 12 | 10 | 0 | 2 | 0 | 83.3% |
| freeRASP Android v19.3.0 | 22 | 14 | 0 | 2 | 6 | 63.6% |
| freeRASP Flutter v8.2.4 | 22 | 14 | 0 | 3 | 5 | 63.6% |

These are whole-repository inventory figures, including existing Windows,
Linux and Android mappings, not Apple-only percentages. The macOS mappings cover
all six Mac-specific VMAware names: `HWMODEL`, `MAC_MEMSIZE`, `MAC_IOKIT`,
`IOREG_GREP`, `MAC_SIP`, `MAC_SYS`, plus applicable CPU observations.
`MAC_UTM` is absent from the pinned inventory and is not invented as an equivalent;
UTM/QEMU devices, processes and strings are covered directly. `THREAD_COUNT`
is compiled out on Apple in the reviewed source and is not claimed as a macOS
implementation match.

Primary implementation references:

- [VMAware pinned source](https://github.com/NotRequiem/VMAware/blob/a3cc54f7da798819d305fd1415daf1b8cd140c70/src/vmaware.hpp): Mac-specific conditions and memory boundary.
- [Check Point macOS chapter](https://evasions.checkpoint.com/src/MacOS/macos.html): sysctl/ioreg observations and the obsolete hyperthreading caveat. The generic inventory names are used only for matching conditions.
- [IOSSecuritySuite](https://github.com/securing/IOSSecuritySuite/tree/7436aea705a6c7ad6013edaaeaf051667cdd4beb/IOSSecuritySuite): JailbreakChecker, EmulatorChecker, DebuggerChecker, ReverseEngineeringToolsChecker, ProxyChecker and ModesChecker.
- [DTTJailbreakDetection `isJailbroken`](https://github.com/thii/DTTJailbreakDetection/blob/master/Sources/DTTJailbreakDetection/DTTJailbreakDetection.m): historical jailbreak paths. No unlisted inventory name is added.
- [freeRASP Flutter Threat enum](https://github.com/talsec/Free-RASP-Flutter/blob/48c6fc061ac22bcf3986421ee109dba67969d47d/lib/src/enums/threat.dart), [Android callbacks](https://github.com/talsec/Free-RASP-Android/blob/e105f3253e5a861812e07a813f0dcd761bc647df/FreeRASPDemoApp/app/src/main/java/com/aheaditec/talsec/demoapp/TalsecApplication.kt), [iOS release source](https://github.com/talsec/Free-RASP-iOS/tree/e4abfe069a930b77ca90405c7bbf6923596e8b00). Binary-only internal detection logic is not assumed.
- [Apple debugger QA1361](https://developer.apple.com/library/archive/qa/qa1361/_index.html), [sysctl](https://developer.apple.com/library/archive/documentation/Darwin/Reference/ManPages/man8/sysctl.8.html), [ioreg](https://developer.apple.com/library/archive/documentation/Darwin/Reference/ManPages/man8/ioreg.8.html), [XProtect](https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web), [background task inventory](https://support.apple.com/guide/deployment/manage-login-items-background-tasks-depdca572563/web).
- [Apple Simulator limitations](https://developer.apple.com/library/archive/documentation/IDEs/Conceptual/iOS_Simulator_Guide/TestingontheiOSSimulator/TestingontheiOSSimulator.html), [CoreMotion](https://developer.apple.com/documentation/coremotion), [CoreTelephony](https://developer.apple.com/documentation/coretelephony), [Corellium iOS](https://support.corellium.com/devices/ios), [Corellium SSH](https://support.corellium.com/features/connect/ssh), [OWASP resilience guidance](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-1/).
- [Objective-See tools](https://objective-see.org/tools.html), [SQLite immutable URI semantics](https://www.sqlite.org/uri.html#uriimmutable), [curl command semantics](https://curl.se/docs/manpage.html).

Malware research informs the choice of signals, without assigning unsupported
family-specific equivalences:

- [BANSHEE](https://www.elastic.co/security-labs/threat-command/beyond-the-wail) describes debugger status, virtual hardware identity and Russian-language checks. These correspond to the tracer, profiler and locale observations here.
- [RustBucket](https://www.sentinelone.com/blog/bluenoroff-how-dprks-macos-rustbucket-seeks-to-evade-analysis-and-detection/) describes a variant querying system_profiler; its later variant differs. The driver measures the shared hardware surface, not a universal RustBucket predicate.
- [Atomic/AMOS, Poseidon and Cthulhu](https://unit42.paloaltonetworks.com/macos-stealers-growing/), [Cuckoo](https://www.iru.com/threats/cuckoo), [MacStealer](https://www.uptycs.com/blog/threat-research-report-team/macstealer-command-and-control-c2-malware), [EvilQuest/ThiefQuest](https://objective-see.org/blog/blog_0x59.html), [XLoader](https://www.sentinelone.com/blog/xloaders-latest-trick-new-macos-variant-disguised-as-signed-officenote-app/), and [KANDYKORN](https://www.elastic.co/security-labs/threat-command/elastic-catches-dprk-passing-out-kandykorn) provide broader target, tooling and runtime context. Payload execution, credential prompts, exfiltration and sample-specific activation are not replicated. No unverified blacklist of allegedly targeted serial numbers is retained.

## Verification

Tests use the maintainer-specified interpreter and worktree-local imports:

```sh
PYTHONPATH=$(ls -d agents/*/ common/python cli | tr '\n' ':') ../linux/.venv/bin/python -m pytest -q
make -C native test
make -C native -j2 win64 win32
../linux/.venv/bin/ruff check .
../linux/.venv/bin/black --check .
../linux/.venv/bin/isort --check-only .
```

Final results (all exit 0):

```text
pytest: 194 passed in 11.94s
make -C native test:
  baremetal-desktop, docker, qemu-kvm, virtualbox, wsl2, xen-hvm fixtures: ok
  lowlevel: guard, statistics, stub, branch, classifier, PE and procfs fixtures passed
  lowlevel: 30 CPU/timing findings validated
  windows logic: SMBIOS, ACPI, EDID, identity and motion fixtures passed
  core tests: all passed
  Linux --list-checks: exit 0
make -C native -j2 win64 win32: both static Windows binaries built, no warnings
ruff check .: All checks passed!
black --check .: 96 files would be left unchanged.
isort --check-only .: Skipped 3 files; exit 0
macos: 116/116 registered IDs match; no orphan implemented entries
ios: 73/73 registered IDs match; no orphan implemented entries
git diff --check: exit 0
uv build --wheel: perdedor-2.0.0-py3-none-any.whl built
isolated wheel smoke: 116 macOS / 73 iOS checks, import and fake scan passed
```

The initial `python -m pip wheel` attempt could not run because the shared
interpreter has no pip; `uv build --wheel` succeeded instead. The isolated local
smoke used `PERDEDOR_CATALOG` pointing at this checkout. CI builds the bundled
catalog using `scripts/build_dist.sh`. Setuptools emitted the existing project
license-table deprecation notice; the project metadata was not changed.

Coverage commands used the same local `PYTHONPATH` and
`../linux/.venv/bin/perdedor coverage --tool vmaware`, `--tool iossecuritysuite`,
and `--tool freerasp`. Each exited 0 and printed the inventory figures above.
The catalog totals were 1,009 implemented checks out of 1,034 entries.

The eight fixture scenarios are Apple Silicon bare metal, VirtualMac2,1,
VMware Fusion, Parallels, UTM/QEMU, a rootless jailbroken iPhone, Corellium and
Simulator. Their provenance explicitly identifies them as **reconstructed,
sanitized command-output examples**, not recordings made on hardware here.
Tests assert both positive and negative findings, matching registrations and
inventory names, selection/network exclusion, unknown/permission handling,
SSH argument construction, process flags, bounded waits/output, aggregate-only
SQL, proxy enable flags and Simulator root resolution/confinement.

The `apple-macos` CI job uses the existing pinned action SHAs on `macos-15`.
It builds the sdist and catalog-bundled wheel with the existing distribution
script, runs Apple/catalog tests, installs the wheel into a separate environment,
and runs `perdedor-macos --local --no-network` outside the checkout. It validates
report schema, exact selected ids, technique agreement and successful hardware,
CPU-count, memory and uptime observations. Reports and the wheel are artifacts.
The job has not run from this Linux environment and no workflow was published.

## Limits and real-target validation

No Apple SDK, physical Mac/iPhone, simulator runtime, SSH target or Corellium
instance was available. The native tests execute the Linux binary, not macOS
code. The Python wheel smoke validates packaging/imports and a fake scan, not
Apple command compatibility. Wine is unavailable.

Real-target validation must cover:

1. Intel and Apple Silicon profiler schemas, localized output, unified Mac
   identifiers, SIP/Gatekeeper/XProtect variants, kext/system-extension lists,
   TCC/Full Disk Access denial, read-only filesystem metadata and GUI-user scope.
2. Virtualization.framework, Fusion, Parallels and UTM identities, loaded devices,
   thermal services, real versus translated CPU strings, and timing under load.
3. iOS bootstrap utility variants, rootless redirects, accessibility of launchd,
   IORegistry/baseband/motion-service markers, developer/Lockdown preferences,
   SpringBoard mappings and P_TRACED flags. Motion services do not enumerate
   sensors or collect physical samples.
4. Personal-store schemas, immutable/WAL count limitations, trust-store records,
   application URL declarations versus actual registration and receipt provenance.
5. simctl JSON roots and executable availability for installed Xcode runtimes,
   shared-host process/kernel observations, and secure path mapping across
   runtime symlinks. Simulator does not reproduce a physical device's peripherals.
6. Scarcity and timing thresholds against representative real devices. Scores
   should not be interpreted as calibrated probability of virtualization.

Catalog limitations cover app integrity, runtime function hooks, sandbox writes,
app device binding, passcode state, actual sensor samples, authenticated store
origin, raw CPUID, VM-exit cycle timing and fan RPM. Six proposals separate
approximate vocabulary mappings without modifying the shared technique catalog.

## Changed files

The list below describes the remaining uncommitted Apple change only. Previously
committed package registration in `pyproject.toml` is retained without alteration.

- `.github/workflows/ci.yml`
- `agents/ios/perdedor_ios/__main__.py`
- `agents/ios/perdedor_ios/checks/behavioural.py`
- `agents/ios/perdedor_ios/checks/design.py`
- `agents/ios/perdedor_ios/checks/environment.py`
- `agents/ios/perdedor_ios/checks/platform_extra.py`
- `agents/ios/perdedor_ios/checks/timing.py`
- `agents/ios/perdedor_ios/device.py`
- `agents/ios/perdedor_ios/signatures.py`
- `agents/macos/perdedor_macos/__main__.py`
- `agents/macos/perdedor_macos/checkkit.py`
- `agents/macos/perdedor_macos/checks/behavioural.py`
- `agents/macos/perdedor_macos/checks/design.py`
- `agents/macos/perdedor_macos/checks/environment.py`
- `agents/macos/perdedor_macos/checks/platform_extra.py`
- `agents/macos/perdedor_macos/checks/timing.py`
- `agents/macos/perdedor_macos/parsing.py`
- `agents/macos/perdedor_macos/runner.py`
- `agents/macos/perdedor_macos/signatures.py`
- `agents/macos/perdedor_macos/target.py`
- `agents/macos/perdedor_macos/transport.py`
- `catalog/checks/ios-extended.json`
- `catalog/checks/ios-limitations.json`
- `catalog/checks/macos-extended.json`
- `catalog/checks/macos-limitations.json`
- `docs/notes/apple.md`
- `research/proposed-techniques-apple.json`
- `tests/fixtures/ios/corellium.json`
- `tests/fixtures/ios/rootless.json`
- `tests/fixtures/ios/simulator.json`
- `tests/fixtures/macos/apple_silicon.json`
- `tests/fixtures/macos/parallels.json`
- `tests/fixtures/macos/utm.json`
- `tests/fixtures/macos/virtualmac.json`
- `tests/fixtures/macos/vmware.json`
- `tests/test_ios_agent.py`
- `tests/test_macos_agent.py`
