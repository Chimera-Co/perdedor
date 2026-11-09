# Android driver

Tests an Android device or emulator from the analyst host over `adb`. Nothing is installed on the
device and no setting is changed. 197 checks: emulator properties and files, vendor emulators
(Genymotion, BlueStacks, Nox, LDPlayer and others), root and Magisk/KernelSU/APatch,
instrumentation (Frida, Xposed), device integrity, sensors, telephony and other mobile-device
signals, wear and tear, network and resources.

On x86 devices it also pushes the static native Linux agent to a private temporary directory for
22 CPU and timing probes (CPUID, descriptor tables, RDTSC exit cost, sleep acceleration), and deletes
it afterwards.

## Run

```bash
adb devices                                         # find the serial
perdedor test android -s emulator-5554              # run, then show the exposure score
python3 -m perdedor_android -s emulator-5554 --no-network -o report.json
perdedor score report.json && perdedor plan report.json
```

Selection works as in every agent: `--profile quick|standard|deep`, `--only class:integrity`,
`--skip PATTERN`, `--param android.package=com.example.app`, `--no-network`, `--list-checks`.
The native probes have slow cost: they run under `--profile deep` or when selected (`--only tag:native`).

If `adb` is missing or the device is unreachable, every check reports `error` with the reason; the
report is still valid.

## Privacy

Reports hold counts and signatures, never personal content: content-provider queries project only
row ids, and subscriber evidence names the matching signature, not the identifier. Do not enable
raw adb logging when testing a personal device.

Details, thresholds and sources: [docs/notes/android.md](../../docs/notes/android.md).
