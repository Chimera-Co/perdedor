# macOS driver

Tests a Mac or a macOS virtual machine, either on the machine it runs on or from the analyst host
over ssh (key authentication only). 116 checks: virtual hardware model and firmware, hypervisor
and guest tools (Apple Virtualization, VMware Fusion, Parallels, UTM/QEMU, VirtualBox), System
Integrity Protection and security settings, analysis tools, instrumentation, wear and tear,
network and resources. It only reads; nothing is installed.

```bash
python3 -m perdedor_macos --local -o report.json
python3 -m perdedor_macos --ssh analyst@mac-vm -i ~/.ssh/id_ed25519 -o report.json
perdedor test macos -- --ssh analyst@mac-vm            # run and score in one step
perdedor score report.json
```

Options: `--local` or `--ssh USER@HOST`, `-i KEY`, `-p PORT`, `--ssh-option OPT` (repeatable),
`-o FILE`, and the usual selection options (`--profile`, `--only`, `--skip`, `--param`,
`--no-network`, `--list-checks`).

Tested against recorded fixtures and in CI on macOS 15 runners; not yet validated on Apple-silicon
virtual machines. Details: [docs/notes/apple.md](../../docs/notes/apple.md).
