# HYDRA Windows Agent

Self-contained PowerShell 7 agent -- no external modules, no compilation.
CPUID is read directly via the .NET `System.Runtime.Intrinsics.X86.X86Base`
intrinsic (available in PowerShell 7 / .NET 5+), so no P/Invoke or native
helper is needed on this platform.

## Run

```powershell
pwsh -File .\Invoke-Hydra.ps1                                   # prints JSON to stdout
pwsh -File .\Invoke-Hydra.ps1 -OutputPath C:\hydra\report.json  # writes to a file
```

Run from an elevated prompt inside the golden image itself, before it is
frozen -- not the disposable overlay -- so a clean result describes what
actually ships.

## Checks

30 checks total. See [docs/CHECK_COVERAGE.md](../../docs/CHECK_COVERAGE.md)
for the full per-check mapping back to Pafish/al-khaser/VMAware, and for
which deeper anti-debug techniques (hardware breakpoints, PEB flags,
trap-flag single-stepping) are explicitly out of scope for this agent.

| Category | Checks |
|---|---|
| `environment_artifact` | Win32_ComputerSystem/Win32_BIOS vendor strings, CPUID hypervisor-present bit, CPUID hypervisor vendor string, CPU brand string ("QEMU Virtual CPU"-class), Win32_PnPEntity vendor-ID scan, guest-integration services (VBoxService/VMware Tools/qemu-ga/Xen/Parallels), ~30 hypervisor/sandbox registry key artifacts (VBox/VMware/Xen/Wine/Sandboxie), ~13 guest driver/tool file paths on disk, raw SMBIOS firmware table scan (`GetSystemFirmwareTable('RSMB',...)`, catches vendor strings that survive WMI-level spoofing), low core count, low RAM, small disk, cloud instance-metadata reachability |
| `timing` | Low uptime (`Environment.TickCount64`, Pafish-class), QPC-around-CPUID jitter (heuristic RDTSC approximation -- see `probes/Timing.ps1` header for why this isn't a raw TSC cycle count) |
| `behavioural_interaction` | Browser history presence, filesystem "wear and tear" age, installed program count, installed font count, running process count, mouse cursor movement (al-khaser Human Interface check) |
| `design_specific` | Analysis tooling in the process list, suspicious hostname/username (substring), exact-match username blacklist (al-khaser style), NIC MAC OUI, blacklisted hook/hypervisor DLLs loaded in-process, hypervisor guest-tool window-class detection (`FindWindow`), `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, managed (.NET) debugger attached |

## Report format

`common/Hydra.Common.psm1` builds the exact same JSON shape as
`hydra_common` on the Python side (see `schema/hydra-report.schema.json`) --
verified by round-tripping a Windows-produced report through the Python
validator in `tests/test_windows_agent_report.py`.

## Tested against

Syntax- and logic-validated by running the full agent under `pwsh` on
macOS/Linux during development: every Windows-only cmdlet
(`Get-CimInstance`, `Get-Service`) and environment variable
(`%LOCALAPPDATA%`, `%USERPROFILE%`, `HKLM:`) is guarded so the agent
completes and emits a valid report even off-platform, rather than crashing
mid-scan. On real Windows those same guards simply never trigger.
