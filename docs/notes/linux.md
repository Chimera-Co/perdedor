# Linux native agent

The static `perdedor-linux-x86_64` binary now carries the whole Linux check set in C++
(`native/src/linux/`), so a Linux guest needs neither Python nor any other runtime. The frozen
Python agent (`agents/linux`) stays in the tree for comparison runs only.

## What is implemented

160 check ids in 147 probes (`--list-checks`), every one catalogued with a matching technique:
125 new entries in `catalog/checks/linux-system.json`, and the 35 v1 ids in
`catalog/checks/linux-core.json` keep their ids and signature lists. The v1 entries outside the
CPU, timing and debugger classes now carry severity, cost, a fix (`how`, `chimera`), equivalents
and references.

| Class | New ids |
|---|---|
| container (Docker, Podman, LXC, Kubernetes, nspawn, gVisor, WSL, firejail/bwrap, OpenVZ, chroot, namespaces, capabilities, seccomp) | 19 |
| hardware (PCI ids and subsystems, USB, input, disks, NIC, GPU, EDID, sound, hwmon, thermal, power, cpufreq, caches, DIMMs) | 19 |
| firmware (every DMI field, serials and UUID, raw SMBIOS strings, SMBIOS VM bit, BIOS signature, ACPI tables and device ids, boot mode, Secure Boot, TPM) | 15 |
| wear and tear (history age, recents, browsers, XDG files, system and log age, journal, wtmp, known hosts, ARP, desktop entries, thumbnails, cron) | 14 |
| artifacts (/sys/hypervisor, /proc/xen, device nodes, fw_cfg, ioports/iomem, kernel and boot logs, kernel command line, device tree, /proc/sysinfo) | 11 |
| identity (sandbox host and user lists, CI runners, environment, sample path and name, parent process, locale guardrails) | 11 |
| network (default subnets, resolver, route, DNS sinkhole, simulated internet, adapters, proxy, interception CA) | 8 |
| os_config (root, AppArmor, lockdown, ASLR, Yama, autologin, sudo) | 7 |
| analysis tools (processes, binaries, packages, listening ports, core_pattern, monitoring services) | 6 |
| timing (clock source in use and registered, UTC, NTP, future file times) | 5 |
| guest tools (paravirtual buses, processes, services, packages) | 4 |
| cpu (from /proc/cpuinfo, without executing CPUID) | 2 |
| emulator, human, integrity, resources | 1 each |

One more technique is catalogued as `planned`: the ACPI BGRT boot-logo comparison (VMAware
`BOOT_LOGO`). It needs a vetted set of reference digests and root access.

Native coverage of the Linux catalog is 160 of 162 implemented entries (98.8 %). The two
remaining ids, `linux.env.cpu_brand_string` and `linux.timing.rdtsc_cpuid_jitter`, are CPU checks
that belong to the shared x86 probes in `native/src/common/`.

## Design decisions

- **Fixture root.** Every file read goes through `linuxutil::Root`, which honours `PERDEDOR_ROOT`
  (or `--param root=`). It walks the path one component at a time with `openat(O_NOFOLLOW)` and
  resolves symlinks inside the root, so a fixture can never escape to the host.
- **Honest negatives.** A check reports `clean` only after a complete inspection. A missing optional
  interface gives `skipped`, and a permission failure or malformed input gives `skipped` or `error`
  with the reason.
- **Evidence.** Evidence holds counts, matched signature strings and the first few items only; user
  files are counted and dated, never read.
- **Power supply.** A desktop or server chassis without any power supply is normal. The check flags
  a portable chassis without a battery, or an unknown chassis with no supply at all (the VM
  default). The chassis lists come from DSP0134 table 17.
- **Equivalents.** The `equivalents` use the names in the committed upstream inventories (VMAware
  enum names, systemd `VIRTUALIZATION_*` values), so `perdedor coverage` counts them.

## Verification

- `make -C native test` builds the agent, runs the core tests and `test-linux`. `test-linux` runs
  the agent against six fixture trees (`native/tests/fixtures/linux/*.json`): QEMU/KVM, VirtualBox,
  Xen HVM, Docker, WSL2 and a bare-metal desktop. Each tree asserts which ids must and must not be
  detected.
- `pytest` passes 139 tests, including the catalog consistency tests.
- `scripts/verify_native_agent.py --platform linux --profile deep`:
  - all 160 checks are in the catalog;
  - the source registry matches the binary;
  - an unprivileged real run on a Xen dom0 host completes in 3.2 s with no errors.
- `make -C native win64 win32` still builds without warnings.

## Limitations and what needs a real target

- **CPUID checks.** The `env.cpuid_*` probes execute CPUID, so fixtures cannot pin them; the fixture
  test leaves them out.
- **Root-only checks.** Checks that need root (raw SMBIOS, DMI serials, ACPI OEM ids, DIMMs, kernel
  log, USB debugfs) skip when run unprivileged. Run the agent as root in the guest for full
  coverage.
- **CHIMERA guest.** The agent has not yet run inside CHIMERA's Debian 12 Xen HVM guest. Run it
  there before a release to confirm the Xen-specific verdicts (/sys/hypervisor, xen clocksource,
  paravirtual buses) against the real guest image.
