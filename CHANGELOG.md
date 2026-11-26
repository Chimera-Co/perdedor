# Changelog

Releases follow [docs/RELEASING.md](docs/RELEASING.md): patch releases keep the report format, minor releases
may add checks and fields, major releases change the format or the score's meaning.

## Unreleased

- 18 Windows environment checks from the coverage backlog (#5 section 1): hypervisor exception quirks (single
  step, MOV SS interrupt shadow, CPUID step), EPT hook timing, Gamarue volume serial, TPM measured boot, UEFI
  variables, CPU topology, Office and Windows Sandbox, Defender emulator, VMware mutexes, Cuckoo/CAPE agent
  artefacts, Azure metadata, hosting provider (only against `--param network.ip_info_host`), NetValidateName.

- 21 Windows timing checks from the coverage backlog (#5 section 1): sleep, timer, wait, ICMP, QPC, .NET and
  kernel-tick delay checks (al-khaser, Check Point, InviZzzible, capa, VMAware CLOCK) with bounded waits and robust
  statistics. `timing.external_time_tampering` only runs against a host given with `--param timing.time_server`.

- `linux.env.acpi_boot_logo` implemented: CRC-32C of the ACPI BGRT boot logo against the TianoCore EDK2 and
  Hyper-V digests VMAware publishes; skipped without a BGRT table or without root.

- Native Linux agents for i686 and aarch64 (#6 section 1), static like x86_64. On ARM the x86 instruction probes
  (descriptor tables, VMware backdoor, VirtualPC opcode, hypercalls, emulation quirks) report `skipped` instead
  of running; CPUID-based probes already skipped through `x86::available()`. CI builds both, runs a quick scan
  with each (aarch64 under qemu-user), and releases them.

- Sandbox integration contract (#6 section 3, docs/INTEGRATION.md): native agents take `--report` and
  `--progress FILE`; the progress file has one JSON event per line (begin, start/end per probe with its budget
  and outcome, done or failed), flushed to disk after every line, so a host can tell where a frozen guest
  stopped. `perdedor_common.driver` is the reference host driver (stage, run, collect, read progress, score).

- Hardening planner (#5 section 6): `perdedor plan` names each step's layer (hypervisor, firmware, device
  model, guest OS, user profile, monitor, network) and where its recipe goes; `--markdown` writes a reviewable
  change list and `--previous` reports what improved or regressed since an earlier report. Perdedor never
  applies a fix.
- Self-test (#5 section 5): `perdedor selftest` runs the native Linux agent against two fake filesystem roots
  (25 file-based checks in a known detected and a known clean state) and scores three recorded reports that
  must land in the pass, warn and fail bands; `tests/selftest/expected.json` holds every expected result and
  any deviation fails. CI runs it after the native build. No malware, no network.

## v2.1.0 (2026-11-27)

- Coverage triage: every upstream technique Perdedor does not check has a recorded decision (implement,
  covered by an equivalent, or out of scope with a reason) (#7).
- Versioned reports with `perdedor history`, `perdedor compare` and `perdedor gate`, so a sandbox change can be
  checked against the previous scan and fail a pipeline when exposure drops (#8).
- Upstream review of 2026-11-23: seven more upstream techniques mapped; the watcher falls back cleanly when
  GitHub returns 403; `github_pat_` tokens are redacted from logs (#9).
- Bare-metal baselines: `perdedor baseline record/list/show`, and a net exposure score that discounts checks
  which also fire on the physical reference machine. Net exposure is never lower than raw exposure (#10).
- Linux: `linux.behavioural.desktop_session` (an X/Wayland/desktop session process is running) and
  `linux.behavioural.active_sessions` (USER_PROCESS records in utmp, what `who` lists). Together with
  `linux.timing.rdtsc_cpuid_vmexit`, which already records the raw RDTSC/CPUID statistics, PERDEDOR now covers
  every check of CHIMERA's separate Linux VM check and CPUID timing harness, so CHIMERA can retire both (#11).
- `design.analysis_tools_running` and `design.analysis_tool_cmdline` also name `drakshell`, `chimera-agent` and
  `sandbox-agent`.

## v2.0.1 (2026-11-09)

- Every agent, `perdedor test`, `perdedor report` and the HTML report now headline the exposure score
  (`perdedor-exposure-2`) instead of v1's severity-weighted pass rate. The weighted score stays in the JSON
  for older consumers.
- `win.env.enclosure_serial` no longer counts a blank chassis asset tag as a detection. Consumer firmware
  often leaves it empty (the Acer laptop CHIMERA runs on does), so bare metal failed the check too. A
  placeholder or vendor string in either field is still a detection.
- Releases include `perdedor-deploy-vX.Y.Z.tar.gz`: the tagged tree with the native agents in
  `native/build/`, for hosts that run scans from a checkout. See [docs/RELEASING.md](docs/RELEASING.md).
- Docs site: top navigation tabs (the menu is visible on every page), formulas rendered with MathJax,
  list formatting fixed. New READMEs for the native agents and the Android, macOS and iOS drivers. The v1
  PowerShell and shell agents are marked as legacy fallbacks.

## v2.0.0 (2026-11-09)

- Native C++17 agents for Windows (x64, x86) and Linux; Python drivers for Android, macOS and iOS.
- A catalog of 1,034 checks (1,009 implemented) mapped to 131 techniques and 91 malware families, with
  equivalents for al-khaser, Pafish, VMAware, InviZzzible, Check Point, capa and CAPE.
- The exposure score: the share of documented evasive families expected to run normally, with an interval,
  a trust grade, per-class detail and a hardening plan ordered by gain.
- `perdedor coverage` and the upstream watcher report what each upstream project checks that Perdedor does not.
