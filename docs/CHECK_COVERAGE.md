# Check Coverage vs. Pafish / al-khaser / VMAware

HYDRA's goal is to be "a tool like them" (Pafish, al-khaser, VMAware) but
usable from one CLI across Windows, Linux, and Android. This document maps
HYDRA's check catalog back to those three tools' technique classes, and
states plainly which parts of their catalogs are **not** implemented and why
-- in the same spirit as the CHIMERA KVM hardening report's own per-flag
justification sections, so no claim here is taken on faith.

## Coverage by technique class

| Technique class | Pafish | al-khaser | VMAware | HYDRA |
|---|---|---|---|---|
| CPUID hypervisor-present bit | Yes | Yes | Yes | `{linux,win}.env.cpuid_hypervisor_bit` |
| CPUID hypervisor vendor string | Yes | Yes | Yes | `{linux,win}.env.cpuid_hypervisor_vendor` |
| CPUID processor brand string ("QEMU Virtual CPU") | Yes | -- | Yes | `{linux,win}.env.cpu_brand_string` |
| SMBIOS/DMI vendor strings (via OS-level API) | -- | Yes | Yes | `linux.env.dmi_*` (11 fields), `win.env.smbios_vendor` |
| Raw SMBIOS firmware table scan | -- | -- | Yes | `win.env.smbios_firmware_table_raw` (`GetSystemFirmwareTable('RSMB',...)`) |
| Registry key artifacts (VBox/VMware/Xen/Wine/Sandboxie) | Yes (subset) | Yes (~40+ keys) | Yes | `win.env.registry_artifacts` (~30 keys, data-driven table in `Signatures.ps1`) |
| Guest driver files on disk | Yes | Yes | Yes | `win.env.artifact_files`, `linux.env.guest_agent_binaries` |
| PCI/PnP vendor ID enumeration | -- | Yes | Yes | `linux.env.pci_virtio_devices`, `win.env.pnp_virtual_devices` |
| Loaded kernel/guest driver modules | -- | Yes | Yes | `linux.env.guest_kernel_modules`, `win.env.guest_services` |
| SCSI/disk vendor strings | Yes (QEMU SCSI key) | Yes | Yes | `linux.env.scsi_device_vendor`, `linux.env.block_device_vendor` |
| MAC address OUI | -- | Yes | Yes | `linux.design.mac_oui`, `win.design.mac_oui` |
| RDTSC/timing-based VM-exit detection | Yes | Yes (timing subsection) | -- | `linux.timing.rdtsc_cpuid_jitter` (real RDTSC via native helper), `win.timing.cpuid_qpc_jitter` (QPC heuristic -- see below) |
| Low uptime (`GetTickCount`) | Yes | -- | -- | `{linux,win,android}.timing.low_uptime` |
| Low core count / RAM / disk size | -- | -- | Yes | `{linux,win}.env.low_core_count`, `low_ram`, `small_disk` |
| Analysis-tool process blacklist | -- | Yes (~40 tools) | -- | `{linux,win}.design.analysis_tools_running` (expanded lists in `signatures.py`/`Signatures.ps1`) |
| Blacklisted hook/hypervisor DLLs loaded | -- | Yes | Yes | `win.design.blacklisted_dlls` |
| VM guest-tool window class detection | -- | Yes | Yes | `win.design.window_class_artifacts` |
| Username/hostname blacklist (exact + substring) | -- | Yes | -- | `{linux,win}.design.exact_sandbox_username`, `suspicious_hostname_or_user` |
| `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` | -- | Yes | -- | `win.design.debugger_present`, `remote_debugger_present`, `managed_debugger_attached` |
| Mouse cursor movement / human-interface check | -- | Yes | -- | `win.behavioural.mouse_movement` |
| Font count | -- | Yes | -- | `{linux,win}.behavioural.font_count` |
| Shell/browser history, aged files, installed package count ("wear and tear") | -- | -- | -- | `{linux,win}.behavioural.*` (HYDRA-original, modelled on Miramirkhani et al., not any of the three tools) |
| Android build fingerprint / goldfish-ranchu / libhoudini / telephony / sensors | -- | -- | -- | `android.*` (HYDRA-original -- **this is the actual gap HYDRA exists to close**; none of the three tools support Android at all) |
| `systemd-detect-virt` cross-check | -- | -- | -- | `linux.env.systemd_detect_virt` (HYDRA-original) |
| Container/WSL/cloud-metadata detection | -- | -- | partial (some cloud checks) | `{linux,win}.env.container_or_wsl`, `cloud_metadata_reachable` (HYDRA-original) |

## Explicitly out of scope (and why)

These are real al-khaser/VMAware technique classes that HYDRA does **not**
implement. Listed here so no reader assumes silent coverage -- the same
transparency principle as CHIMERA KVM report Section 5 ("Remaining
Detections -- Per-Flag Justification").

- **Hardware breakpoint / debug-register scanning, PEB `BeingDebugged`
  flag, `NtGlobalFlag` heap-flag inspection, trap-flag single-stepping,
  `NtSetInformationThread(ThreadHideFromDebugger)` self-debugging tricks.**
  These are genuine anti-debug techniques (al-khaser's "Debugger Detection"
  section has ~39 checks; HYDRA implements 3 of the highest-signal, lowest-
  complexity ones). The rest require either unmanaged/unsafe native code
  well beyond a P/Invoke declaration, or direct `ntdll.dll` internals that
  are not part of any documented, stable API. Out of scope for a
  PowerShell-based agent; a genuine native (C/C++) Windows agent is the
  natural upgrade path if this class becomes a priority.
- **DLL injection detection, anti-dumping, code-injection technique
  detection.** al-khaser's "DLL Injection Detection" and "Anti-Dumping"
  sections test whether the *analysis platform itself* can detect injection
  techniques used against the running process -- this is a different
  problem class from "does this environment look like a sandbox" and is
  arguably out of HYDRA's stated scope (a sandbox-evasion probe, not an
  injection-technique test suite).
- **Self-deletion / execution-artifact checks, generic "file dropped and
  re-executed" tricks.** These test sandbox *behavioural capture*
  correctness (does the sandbox notice a sample deleting itself), not
  environment detection -- out of scope for a self-test probe.
- **True cycle-accurate RDTSC on Windows.** .NET does not expose an RDTSC
  intrinsic (only `X86Base`/SSE/AVX/etc. via
  `System.Runtime.Intrinsics.X86`). `win.timing.cpuid_qpc_jitter` uses
  `Stopwatch`/QPC as a heuristic approximation instead -- documented
  explicitly in `agents/windows/probes/Timing.ps1`. A native helper
  (mirroring `agents/linux/native/cpuid_rdtsc.c`) is the upgrade path.
- **Android on-device native instrumentation.** All Android checks run
  over `adb shell`/`getprop`/`dumpsys` from the analyst host rather than an
  installed on-device agent (see `agents/android/README.md` for the
  rationale). This covers the large majority of build-fingerprint/property/
  file-based checks but cannot reach anything that requires code running
  inside a target app's process.
- **Live-malware-validated thresholds.** Every numeric threshold in this
  codebase (low RAM/disk/core-count, minimum package count, minimum font
  count, RDTSC jitter cycles, etc.) is a documented heuristic based on
  public literature and the CHIMERA KVM report's own empirical
  measurements -- not independently re-validated against a labelled corpus
  of real sandbox-evasive malware. Treat a "detected" finding as a real
  signal and a "clean" finding as "no known public technique fired," not as
  a guarantee against a specific malware family, exactly as CHIMERA's own
  Chapter 9 states for its VMAware/Pafish/al-khaser verification.

## Android: no upstream baseline exists

Unlike Windows/Linux, there is no Pafish/al-khaser/VMAware equivalent for
Android to diff against -- this is the specific, named gap the CHIMERA
synopsis identifies HYDRA as being built to close. The Android check list in
this document's coverage table is therefore HYDRA-original, built from the
technique classes documented in the academic literature cited in the CHIMERA
synopsis (Gajrani et al., Vidas & Christin, Alzaylaee et al.) rather than
ported from an existing tool's source.
