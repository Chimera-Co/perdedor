# PERDEDOR Android Agent

Python3 agent that drives the target device over `adb` from the analyst
host, rather than shipping an on-device APK.

## Why adb instead of an on-device app

CHIMERA's own PERDEDOR design doc (Ch.8) describes on-device agents for every
platform. For Android specifically, most of the checks that matter here --
build-fingerprint properties, device nodes, installed packages, sensor
lists, telephony properties -- are readable over `adb shell` /
`adb shell getprop` /`dumpsys` without installing anything on the guest.
That keeps v1 simple and buildable without the Android SDK/Gradle toolchain.
Native framework instrumentation (CHIMERA Ch.7.4, "Native Framework
Instrumentation") is the natural on-device upgrade path if a check is ever
needed that adb genuinely cannot reach.

## Run

```bash
adb devices                                          # find the serial
python3 -m perdedor_android -s emulator-5554             # prints JSON to stdout
python3 -m perdedor_android -s emulator-5554 -o report.json
```

If `adb` isn't installed, or no device is reachable at the given serial,
every check reports `error` with a clear reason rather than the scan
failing outright -- the emitted report is always schema-valid.

## Checks

22 checks total. No Pafish/al-khaser/VMAware equivalent exists for Android --
see [docs/CHECK_COVERAGE.md](../../docs/CHECK_COVERAGE.md) for why this
entire agent's check list is PERDEDOR-original rather than ported from an
upstream tool.

| Category | Checks |
|---|---|
| `environment_artifact` | Build fingerprint, `ro.hardware`, `ro.boot.hardware` (incl. Cuttlefish), product model, manufacturer/brand, graphics HAL (gralloc/EGL) implementation, any `qemu.*` system property present, `ro.kernel.qemu`, goldfish/ranchu device nodes, libhoudini ARM-translation shim, CPU ABI (x86 translation-layer requirement) |
| `timing` | Low uptime |
| `behavioural_interaction` | Third-party installed package count, battery-state plausibility, battery temperature plausibility |
| `design_specific` | `ro.build.characteristics`, telephony/RIL identity, sensor count, camera hardware feature declaration, `ro.build.tags` test-keys, default AVD NAT subnet (10.0.2.0/24), device name plausibility |

## Tested against

Unit-tested with `adb` mocked out (`tests/test_android_agent.py`), plus a
live smoke test against `adb` present with no device attached, confirming
every check degrades to `error` cleanly rather than crashing the scan.
