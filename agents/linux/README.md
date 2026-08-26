# PERDEDOR Linux Agent

Pure-stdlib Python 3.10+ agent, plus a tiny native helper for CPUID/RDTSC
(the two primitives Python cannot reach on its own).

## Run

```bash
python3 -m perdedor_linux                      # prints JSON report to stdout
python3 -m perdedor_linux -o linux-report.json  # writes to a file
```

The native helper (`native/cpuid_rdtsc`) is built automatically on first run
via `make` if a C compiler is present; if it can't be built (no compiler, or
a non-x86 host) the CPUID/RDTSC-dependent checks report `skipped` rather
than failing the whole scan.

## Checks

37 checks total. See [docs/CHECK_COVERAGE.md](../../docs/CHECK_COVERAGE.md)
for the full per-check mapping back to Pafish/al-khaser/VMAware.

| Category | Checks |
|---|---|
| `environment_artifact` | 11 DMI fields (sys/product/product_family/product_sku/product_version/bios vendor+version/board vendor+name/chassis vendor+asset_tag) against known hypervisor vendor strings, CPUID hypervisor-present bit, CPUID hypervisor vendor string, CPU brand string ("QEMU Virtual CPU"-class), PCI virtio/QEMU/VMware/VirtualBox/Xen vendor IDs, guest-integration kernel modules, guest agent binaries on disk, SCSI device vendor string, block device vendor/model strings, `systemd-detect-virt` cross-check, low core count, low RAM, small disk, container/WSL detection, cloud instance-metadata reachability, known sandbox-framework (Cuckoo/INetSim) marker paths |
| `timing` | Low system uptime (Pafish-class), RDTSC-around-CPUID VM-exit jitter (native helper) |
| `behavioural_interaction` | Shell history depth, filesystem "wear and tear" age, installed package count, installed font count, running process count |
| `design_specific` | Analysis tooling in the process list (~26 tools), suspicious hostname/username (substring), exact-match username blacklist (al-khaser style), NIC MAC OUI |

## Tested against

Verified inside real Linux containers (`docker run python:3.12-slim`, both
`linux/arm64` and `linux/amd64`) as well as gracefully degrading (all
checks report `error`/`skipped`, never crash) when run directly on macOS
during development.
