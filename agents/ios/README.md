# iOS driver

Tests an iOS device or the iOS Simulator from the analyst host. 73 checks: Simulator and
virtual-device (Corellium) signatures, jailbreak artifacts and tools, instrumentation (Frida,
Substrate), debugging and integrity state, device identity and wear and tear. It only reads;
nothing is installed.

```bash
python3 -m perdedor_ios --ssh root@device -p 2222 -o report.json     # jailbroken or Corellium device, via iproxy
python3 -m perdedor_ios --simulator booted -o report.json            # on a Mac with Xcode
perdedor test ios -- --simulator booted
perdedor score report.json
```

Options: `--ssh USER@HOST` or `--simulator UDID|booted`, `-i KEY`, `-p PORT`, `--ssh-option OPT`,
`-o FILE`, and the usual selection options.

A stock (not jailbroken) device cannot be inspected from outside; the checks that would need it are
catalogued with that reason. Tested against recorded fixtures; not yet validated on hardware.
Details: [docs/notes/apple.md](../../docs/notes/apple.md).
