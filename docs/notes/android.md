# Android driver implementation notes

177 registered checks; all 22 v1 ids and techniques remain. Counts by class:
analysis_tools 6, artifacts 2, container 1, cpu 4, debugger 1, emulator 62,
firmware 1, hardware 3, identity 2, instrumentation 8, integrity 30,
mobile_device 24, network 12, resources 4, timing 1, wear_and_tear 16.
Four additional catalog entries document capabilities unavailable to this host driver.

The earlier draft's property, vendor, kernel, hardware and user-activity checks
were retained and corrected. Root, Magisk/KernelSU/APatch, instrumentation,
package ecosystems, device policy, certificates and native probes complete the
host-visible surface. Registrations carry category, severity, cost and selection
metadata. Every implemented id has a matching catalog technique and concrete fix.

## Use and design

Run `python -m perdedor_android -s SERIAL --no-network -o report.json`.
Use `--only class:integrity`, `--only tag:native`, `--skip PATTERN`, and
`--param android.pid=1234 android.package=com.example.app` for target-specific checks.
`--param native.binary=/absolute/path` overrides the repository's static binary.
Native checks have slow cost and run under the deep profile or explicit selection.
The current native sources register two CPU checks and no timing checks; the driver
runs `--only class:cpu,class:timing --no-network` and tests pin that registration set.
It validates static ELF64 x86_64, allocates a private temporary directory, pushes,
runs under a device timeout, and deletes the file and directory in a finally block.
Cleanup failure is an error with the exact path for operator recovery. A disconnected
device can prevent cleanup; no host program can guarantee deletion in that case.

The transport caches repeated reads per scan. The adb serial stays in ctx.target;
tests inject a transport separately. Command failures, permission denials and unknown
provider responses produce error/skipped findings. File tests check parent traversal
permissions; a detected visible marker remains useful even if another path is hidden.
Each ordinary check has a nine-second budget, including its sequential shell reads.
Native execution has a sixty-second device timeout plus bounded transfer and cleanup.
No root command, settings mutation, service installation or credential operation runs.

Personal content is never included in reports. Content-provider queries project only
`_id`, and evidence contains counts. Subscriber evidence contains signature names and
counts, not real identifiers. Device identity properties remain available as evidence
where needed to verify an emulator signature. A raw adb dump can contain sensitive
values in host memory; do not enable external adb output logging on personal devices.

Local scarcity thresholds are conservative policy choices, not universal hardware
limits or claims from cited reports: 3 user apps, 3 sensors, 4 cores, 2048 MiB RAM,
16 GiB data storage, 720-pixel short side, 1 account, 5 contacts/messages/calls,
10 photos, 2 saved networks, 1 paired device, 10 used packages, 2 everyday apps,
7 days of install spread, 10 boots, and 600 seconds uptime. The settings/resource
checks expose overrides where useful. Sensor activity uses five identical existing
samples and is not proof of emulation. Desktops, tablets, stationary phones, devices
without Google services and privacy-conscious users can trigger weak findings.
Numeric emulator defaults come from the source-linked signature tables. Fingerprint
comparison ignores legitimate differences in build dates/versions between partitions.
Unknown subscriber strings are never assumed to be IMEIs or checked with Luhn.

## Sources reviewed

- [anti-emulator FindEmulator.java](https://github.com/strazzere/anti-emulator/blob/master/AntiEmulator/src/diff/strazzere/anti/emulator/FindEmulator.java): hasPipes, hasQEmuFiles, hasGenyFiles, hasQEmuDrivers, hasQEmuProps, hasEmulatorBuild, isOperatorNameAndroid.
- [framgia EmulatorDetector.java](https://github.com/framgia/android-emulator-detector/blob/master/library/src/main/java/com/framgia/android/emulator/EmulatorDetector.java): checkBasic, checkFiles, checkQEmuProps, checkTelephony, checkIp.
- [CalebFenton Detector.java](https://github.com/CalebFenton/AndroidEmulatorDetect/blob/d8855d8311dbe2bcaeaef0e3fc19c5f59feb4f27/app/src/main/java/org/cf/emulatordetect/Detector.java): build, telephony, files and eth0 observations.
- [reveny source](https://github.com/reveny/Android-Emulator-Detection/blob/294912d599756bc67aadac7fb64001981b27559c/emulatordetection/src/main/jni/EmulatorDetection.cpp) and its EmulatorData.hpp: vendor markers, mounts, CPU architecture and translation.
- [RootBeer](https://github.com/scottyab/rootbeer/blob/master/rootbeerlib/src/main/java/com/scottyab/rootbeer/RootBeer.java): exact package, su, dangerous-property and mount-check names in catalog equivalents.
- [DetectFrida](https://github.com/darvincisec/DetectFrida/blob/86a88feb9988b0d279c648dc8144c39cb128736d/app/src/main/c/native-lib.c): detect_frida_threads. Memory/disk comparison and named-pipe internals are not claimed as implemented.
- [Magisk internals](https://topjohnwu.github.io/Magisk/details.html), [KernelSU modules](https://kernelsu.org/guide/module.html), [APatch](https://github.com/bmax121/APatch), [Frida Android](https://frida.re/docs/android/).
- [freeRASP threats](https://docs.talsec.app/freerasp/wiki/threat-detection): host-visible root, emulator, hook, debugger, installation, passcode, developer and VPN signals. Its private implementation is not reproduced or assigned invented function equivalents.
- [Android CDD](https://source.android.com/docs/compatibility/cdd), [adb](https://developer.android.com/tools/adb), [verified boot](https://source.android.com/docs/security/features/verifiedboot/boot-flow), [emulator networking](https://developer.android.com/studio/run/emulator-networking), [Play Integrity](https://developer.android.com/google/play/integrity).
- [Cerberus](https://www.threatfabric.com/blogs/cerberus-a-new-banking-trojan-from-the-underworld): motion/step-dependent activation supports sensor coverage; we do not reproduce its activation logic.
- [TeaBot](https://www.cleafy.com/cleafy-labs/a-stealthy-threat-uncovered-teabot-on-google-play-store): build identity and operator country checks support those observations.
- [SharkBot](https://www.cleafy.com/cleafy-labs/sharkbot-a-new-generation-of-android-trojan-is-targeting-banks-in-europe) and [ToxicPanda](https://www.bitsight.com/blog/toxicpanda-android-banking-malware-2025-study): emulator/analysis checks motivate property, file and CPU coverage. No unsupported family-specific threshold is attributed to these reports.

## Verification on Linux

An existing .venv was present; `uv venv .venv` reported that it already existed.
`uv pip install --python .venv/bin/python -e '.[dev]'` succeeded. Tests used
`PYTHONPATH=$PWD/common/python:$PWD/cli:$PWD/agents/android`.

- `.venv/bin/python -m pytest -q tests`: **70 passed in 12.14s**.
- `make -C native test`: **core tests: all passed**; Linux list-checks exited 0.
- Catalog tests and the Android registry/native mapping regression passed.
- `ruff check .`: **All checks passed!**
- `black --check .`: **51 files would be left unchanged.**
- `isort --check-only .`: exit 0 (**Skipped 2 files**, ignored environment directories).
- Stock `make -C native win64 win32` initially failed because this MinGW header
  does not define RRF_SUBKEY_WOW6464KEY at the configured Windows version.
  Both architectures compiled without warnings using
  `make -C native win64 win32 CXXSTD='-std=c++17 -DRRF_SUBKEY_WOW6464KEY=0x00010000'`.
  No Windows source was changed. Wine is unavailable.

Formatting-only changes in existing Linux/shared Python files were necessary for
the binding whole-tree checks. Their behavior is unchanged.

## Limitations and target validation

The five fixtures are representative, sanitized command-output records for ranchu
AVD, Genymotion, BlueStacks/Nox-like, Android-x86 and a plausible phone. They are
explicitly labelled reconstructed fixtures, not new physical-device captures.
They test key detections, clean controls, unknown states, privacy, registry parity,
selection, caching, ABI rejection and cleanup on upload/run/report failures.

Validate all command formats, timeouts and permission behavior on actual Android
versions, particularly modern SELinux restrictions, rootless access, multi-user
storage, sensor dumps, root hiding and iphonesubinfo transactions. Host shell access
does not measure an application's exact visibility. Subsystem/driver presence is
not a guarantee of an emulator; corporate VPNs, accessibility services and user CAs
are legitimate. Network probes use random `.invalid` domains and bounded DNS/HTTP;
DNS failure alone cannot distinguish NXDOMAIN from an offline resolver.

App tampering, app data migration/device binding, keystore attestation, obfuscation,
inline hooks and application-level debugger APIs require an app context or trusted
baseline. These are documented gaps, not clean verdicts. The first four subscriber
transactions may not expose phone number/IMSI on a particular release; unavailable
identifiers are skipped. Provider records are counts only and often denied.

This is not a claim to replicate every variant of Anubis, Hydra, Octo/Exobot,
Xenomorph, Anatsa, Godfather, Chameleon, Brokewell, Crocodilus or SpyNote.
Family-specific behavior needs versioned sample validation. Renamed/hidden root
and instrumentation components remain a limitation of read-only host observations.

## Changed files

- `agents/android/perdedor_android/__main__.py`
- `agents/android/perdedor_android/adb.py`
- `agents/android/perdedor_android/checks/_base.py`
- `agents/android/perdedor_android/checks/_parsers.py`
- `agents/android/perdedor_android/checks/behavioural.py`
- `agents/android/perdedor_android/checks/design.py`
- `agents/android/perdedor_android/checks/device_hw.py`
- `agents/android/perdedor_android/checks/emulator_files.py`
- `agents/android/perdedor_android/checks/emulator_props.py`
- `agents/android/perdedor_android/checks/environment.py`
- `agents/android/perdedor_android/checks/kernel_hw.py`
- `agents/android/perdedor_android/checks/native.py`
- `agents/android/perdedor_android/checks/network.py`
- `agents/android/perdedor_android/checks/security.py`
- `agents/android/perdedor_android/checks/software.py`
- `agents/android/perdedor_android/checks/telephony.py`
- `agents/android/perdedor_android/checks/timing.py`
- `agents/android/perdedor_android/checks/user_data.py`
- `agents/android/perdedor_android/runner.py`
- `agents/android/perdedor_android/signatures.py`
- `agents/linux/perdedor_linux/__main__.py`
- `agents/linux/perdedor_linux/checks/behavioural.py`
- `agents/linux/perdedor_linux/checks/design.py`
- `agents/linux/perdedor_linux/checks/environment.py`
- `agents/linux/perdedor_linux/checks/timing.py`
- `catalog/checks/android-core.json`
- `catalog/checks/android-extended.json`
- `catalog/checks/android-limitations.json`
- `common/python/perdedor_common/catalog.py`
- `common/python/perdedor_common/registry.py`
- `docs/notes/android.md`
- `research/proposed-techniques-android.json`
- `tests/fixtures/android/android_x86.json`
- `tests/fixtures/android/avd.json`
- `tests/fixtures/android/bluestacks_nox.json`
- `tests/fixtures/android/genymotion.json`
- `tests/fixtures/android/phone.json`
- `tests/test_android_agent.py`
- `tests/test_catalog.py`
- `tests/test_linux_agent.py`
