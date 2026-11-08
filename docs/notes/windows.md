# Windows system checks

The Windows agent is native C++17 built with MinGW-w64, in two builds: `perdedor-windows-x64.exe`
and `perdedor-windows-x86.exe`. It needs no PowerShell, .NET or extra runtime, and runs on Windows 10
and 11 (x64, and x86/WOW64).

The low-level CPU, timing, debugger and instrumentation probes are described in
[lowlevel.md](lowlevel.md). This note covers everything else.

## What is implemented

| Catalog file | Entries | Status |
|---|---|---|
| `windows-core.json` (v1 ids, kept stable) | 30 | 30 implemented |
| `windows-system.json` | 361 | 361 implemented |
| `windows-lowlevel.json` | 50 | 41 implemented, 5 not_feasible, 4 planned |

`windows-system.json` by class:

| Class | Entries | What it looks at |
|---|---|---|
| artifacts | 91 | Files, registry keys and values, device and driver objects, pipes, window classes and event-log sources of VirtualBox, VMware, Xen, QEMU, Hyper-V, Parallels, Virtual PC, Sandboxie, Cuckoo and Wine. |
| hardware | 67 | PnP and ghost devices, PCI vendor ids, disks, adapters, audio, displays (EDID), pointing devices, sensors, fans, TPM. |
| firmware | 41 | Raw SMBIOS (strings, the VM bit, missing types, memory devices without a speed), ACPI tables (OEM and creator ids), BIOS dates and serials, registry firmware strings. |
| wear_and_tear | 41 | Browser history and cookies, recent files, aged user files, event-log age, installed programs, fonts, DNS cache, prefetch, update history. |
| os_config | 25 | Activation, test signing, hypervisor launch type, boot and debug options, update age. |
| identity | 23 | User, computer and domain names, default serials and UUIDs, sample file names and paths. |
| container | 19 | Windows container, Docker and WSL artefacts. |
| network | 14 | MAC OUIs, analysis subnets, cloud metadata, DNS sinkholes, TLS interception certificates. |
| guest_tools, analysis_tools | 12 + 12 | Guest-tool services and processes, debugger and monitor processes, injected DLLs. |
| human | 8 | Mouse movement and clicks, straight-line and teleporting motion, keyboard and foreground activity. |
| resources, emulator | 7 + 1 | Cores, memory, disk and screen size; Wine. |

### Upstream coverage

From `perdedor coverage` on 9 Nov 2026, over the Windows and Linux catalogs together:

| Source | Covered | Feasible covered |
|---|---|---|
| Pafish v0.6 | 96.6 % | 96.6 % |
| InviZzzible | 85.8 % | 85.8 % |
| al-khaser v1.1.0 | 74.6 % | 77.6 % |
| VMAware v2.8.2 | 69.1 % | 70.0 % |
| systemd-detect-virt v262.2 | 100 % | 100 % |

What is still missing, by source:

- **al-khaser:** mostly anti-disassembly, anti-dumping and code-injection demonstrations, and delays
  driven by timer APIs. The demonstrations test an analyst's tools rather than the sandbox.
- **VMAware:** mostly macOS techniques, and MSR or exception probes that need a kernel driver.
- **InviZzzible:** Cuckoo-monitor behaviour checks (hook integrity, PID reuse, untracked processes).
  These do not apply to an agentless DRAKVUF setup.

## Design decisions

- **Pure logic separated from Win32.** Parsing and matching live in `src/windows/system_logic.cpp`,
  which uses no Windows headers. It holds:
  - the SMBIOS, ACPI and EDID parsers;
  - the vendor and OUI tables, and the analysis subnets;
  - the default serial and UUID rules, hash-named files and BIOS dates;
  - the mouse-motion model.

  `tests/windows_logic_tests.cpp` runs this code on the Linux host against synthetic QEMU,
  VirtualBox, VMware, Xen and Dell blobs, so the parsers are tested without Windows.
- **Unavailable is not clean.** An API failure, an access denial or a timeout is reported as
  `error` or `skipped`, with the reason, never as `not_detected`. The one exception: a certificate
  store that does not exist (`ERROR_FILE_NOT_FOUND`) counts as empty, because a fresh profile has
  no such store.
- **Bounded runtime.** Every enumeration has a cap:
  - blobs up to 16 MiB, at most 4,096 rows and 10,000 entries;
  - time budgets of 8 s for WMI, 25 s for slow WMI classes, 8 s for device scans and 4 s for tree
    scans.

  When a cap is hit, counts are reported as lower bounds.
- **Thresholds are policy, not facts.** The minimums are compatibility defaults carried over from
  the v1 probes, and they are tunable:
  - 2 CPUs, 4 GiB of RAM and a 60 GiB disk;
  - 20 programs, 100 fonts and 40 processes;
  - 5 files older than 7 days, and 20 KiB of browser history.

  They are not statistically validated VM classifiers.
- **Interactive checks are opt-in.** The mouse, keyboard and foreground checks wait up to 30 s
  (90 s at most) for input. They carry `requires: ["interactive"]`, so automated runs skip them.

## What CHIMERA can and cannot fix

| Layer | Effort | What it covers |
|---|---|---|
| Guest image | 1–2 | User and computer names, installed programs, browser use, aged files, fonts, processes. Remove guest tools and troubleshooting tools, then re-check the explorer and Defender state before each snapshot commit. |
| VM configuration | 1 | vCPUs, memory, disk size, MAC OUI and the emulated device models in `xl.cfg`. |
| Firmware | 3–4 | SMBIOS strings, the VM bit, memory-device speeds and ACPI OEM ids. `firmware_override` with host-derived tables covers SMBIOS. The ACPI ids and the Xen platform PCI device (vendor 5853) need firmware or device-model work. |

Not fixable by configuration: the hypervisor CPUID leaves while Viridian is on, and timing (see
[lowlevel.md](lowlevel.md)).

## Verification

- **Host tests.** `make -C native test` includes `test-windows-logic`, which runs the SMBIOS, ACPI,
  EDID, identity and motion fixtures, compiled with `-Werror`.
- **Builds.** `make -C native win64 win32` builds both agents without warnings.
- **Wine crash test** (9 Nov 2026) with the x64 agent: `--list-checks` lists 422 checks.

  | Profile | Findings | Clean | Detected | Skipped | Error |
  |---|---|---|---|---|---|
  | `--profile quick --no-network` | 264 | 205 | 20 | 39 | 0 |
  | `--profile deep --no-network` (51 s) | 428 | 284 | 74 | 69 | 1 |

  The single error is `win.design.windows_activation`, because Wine's WMI does not provide
  `SoftwareLicensingProduct`. The detections are Wine's own artefacts, which is expected.

  Wine is not Windows: this run shows only that the agent survives without a crash or hang. It says
  nothing about detection accuracy.
- **Catalog consistency.** `pytest` checks that every registered id is catalogued with the same
  technique, and that every implemented entry is emitted by an agent.

## Needs validation on a real target

- **Real Windows.** Run the standard and deep profiles on real Windows 10 and 11, both bare metal and
  the CHIMERA Xen guest, and on WOW64 with the x86 build. The CI runners (windows-2022 and
  windows-2025) are Azure VMs, so detections are expected there.
- **Wear-and-tear thresholds.** Calibrate them against a few real workstations before relying on
  them for scoring.
