# Framework Self-Test (`perdedor selftest`)

The self-test suite provides deterministic, offline verification that PERDEDOR produces the expected check statuses and exposure scores. It runs without live guest VMs, network probes, or malware samples.

## Components

The self-test framework consists of three parts under `tests/selftest/`:

1. **Fake filesystem roots for the native agent** (`tests/selftest/roots/`):
   - `linux-detected`: contains minimal synthetic files in `/sys`, `/proc`, `/etc`, and `/run` that trigger known detections for purely file-based checks.
   - `linux-clean`: contains clean reference files where every selected check reports `clean`.
   - The native Linux binary reads from these roots via its root override parameter (`--param root=<dir>`), implemented using `perdedor::linuxutil::Root(ctx)`.

2. **Recorded report fixtures** (`tests/selftest/reports/`):
   - `report-pass.json`: a clean report where all catalogued techniques pass, scoring 100.0 (in the `pass` band, $\ge 90.0$).
   - `report-warn.json`: a report exposing a single detection (`cpu.brand_string`), scoring 88.6 (in the `warn` band, $70.0 \le S < 90.0$).
   - `report-fail.json`: a report exposing multiple detections (`cpu.hypervisor_bit` and `cpu.brand_string`), scoring 63.4 (in the `fail` band, $< 70.0$).

3. **Expected results specification** (`tests/selftest/expected.json`):
   - Maps each self-test case to its expected check statuses (`detected`, `clean`, or `skipped`).
   - Maps report fixtures to their expected score bands (`pass`, `warn`, or `fail`) and score ranges.

## Covered Checks

The native self-test targets 25 deterministic, file-based checks:

| Area | Checks | Files Read |
|---|---|---|
| SMBIOS / DMI | `linux.env.dmi_sys_vendor`<br>`linux.env.dmi_product_name`<br>`linux.env.dmi_product_version`<br>`linux.env.dmi_bios_vendor`<br>`linux.env.dmi_board_vendor`<br>`linux.env.dmi_board_name`<br>`linux.env.dmi_chassis_vendor`<br>`linux.env.dmi_chassis_type`<br>`linux.env.dmi_modalias` | `/sys/class/dmi/id/*`<br>`/sys/devices/virtual/dmi/id/modalias` |
| Hardware / CPU | `linux.env.cpuinfo_virtual_model`<br>`linux.env.cpuinfo_hypervisor_flag` | `/proc/cpuinfo` |
| Guest Integration | `linux.env.guest_kernel_modules`<br>`linux.env.kernel_cmdline`<br>`linux.env.proc_xen`<br>`linux.env.qemu_fw_cfg` | `/proc/modules`<br>`/proc/cmdline`<br>`/proc/xen`<br>`/sys/firmware/qemu_fw_cfg` |
| Containers / Sandboxes | `linux.env.dockerenv`<br>`linux.env.podman_containerenv`<br>`linux.env.cgroup_container` | `/.dockerenv`<br>`/run/.containerenv`<br>`/proc/self/cgroup` |
| Host & Environment | `linux.design.suspicious_hostname_or_user`<br>`linux.design.exact_sandbox_username`<br>`linux.design.sandbox_hostname_list`<br>`linux.design.aslr_disabled` | `/etc/hostname`<br>`/proc/self/environ`<br>`/proc/sys/kernel/randomize_va_space` |
| Timing & Behaviour | `linux.timing.low_uptime`<br>`linux.timing.clock_source`<br>`linux.behavioural.active_sessions` | `/proc/uptime`<br>`/sys/devices/system/clocksource/...`<br>`/run/utmp` |

Probes involving CPUID instructions, cycle timers (RDTSC), process injection, or network traffic are intentionally excluded from the fake-root fixture tests.

## Running the Self-Test

Run the self-test using the CLI:

```bash
perdedor selftest
```

To specify an explicit path to the native agent binary:

```bash
perdedor selftest --agent native/build/perdedor-linux-x86_64
```

If the native binary is not available (for example, in a pure Python development environment without toolchains):

```bash
# Exits 0 and reports the native test as skipped:
perdedor selftest --allow-skip
```

### Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | All executed self-test cases matched expected statuses and score bands. |
| `1` | One or more deviations detected (status mismatch, missing check, or score band error). |
| `2` | Native agent binary was not found and `--allow-skip` was not specified. |

## Continuous Integration

The `native-build` job in `.github/workflows/ci.yml` runs:

```bash
perdedor selftest --agent native/build/perdedor-linux-x86_64
```

immediately after compiling the static Linux agent binary, ensuring that any regression in check paths, signatures, or scoring algorithms fails the build.
