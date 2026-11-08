# Android driver implementation notes

197 registered checks; all 22 v1 ids and techniques remain. Counts by class:
analysis_tools 6, artifacts 2, container 1, cpu 16, debugger 1, emulator 62,
firmware 1, hardware 3, identity 2, instrumentation 8, integrity 30,
mobile_device 24, network 12, resources 4, timing 9, wear_and_tear 16.
22 of the cpu/timing checks come from the native helper (see below).
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
The driver remaps the 22 low-level probes that only native code can run: the cpu and
timing registrations in `native/src/common/*.cpp` and `native/src/linux/lowlevel_*.cpp`
(CPUID leaves and consistency, descriptor tables, VMware backdoor and opcode probes,
RDTSC/CPUID exit cost, TSC stability, sleep acceleration, timer resolution, syscall
latency). Kernel and file-based Linux checks are not remapped, because the adb checks
read the same data. It runs `--only class:cpu,class:timing --no-network`, keeps only
the remapped ids, and a regression test keeps the table equal to the native source.
On the host the helper finishes this selection in about 11 s.
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

## Upstream coverage

From `perdedor coverage` on 9 Nov 2026:

| Source | Covered |
|---|---|
| strazzere/anti-emulator | 10 of 13 (76.9 %) |
| scottyab/rootbeer | 12 of 17 (70.6 %) |
| freeRASP (Android and Flutter callbacks) | 14 of 22 (63.6 %) |

The freeRASP mapping links a threat callback to the checks that observe the same
condition from adb, for example `onPrivilegedAccess` to the su, Magisk, KernelSU and
mount checks. The callbacks left unmapped need an app context: app integrity,
device binding, obfuscation, screenshots, screen recording, malware, time spoofing
and unsecured Wi-Fi. RootBeer's unmapped items are its aggregate `isRooted*` results
and its native-library loading checks. anti-emulator's unmapped items are the QEMU
breakpoint checks (`checkQemuBreakpoint`, `qemuBkpt`) and `hasEmulatorAdb`.

## Verification on Linux

- `pytest`: 156 passed, including the Android fixtures for a ranchu AVD, Genymotion,
  BlueStacks/Nox-like, Android-x86 and a plausible phone, registry parity,
  selection, caching, ABI rejection and helper cleanup on push, run, report and
  cleanup failures.
- `make -C native test` passes; `ruff`, `black --check` and `isort --check-only` are
  clean.
- No Android device or emulator was attached, so none of this ran on a real target.

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
