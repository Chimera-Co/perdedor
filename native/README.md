# Native agents (Windows and Linux)

One C++17 code base, three statically linked executables with no runtime dependencies:

| File | Target | Checks |
|---|---|---|
| `perdedor-windows-x64.exe` | Windows 7 and later, 64-bit | 432 Windows checks |
| `perdedor-windows-x86.exe` | Windows 7 and later, 32-bit (also runs under WOW64) | the same, minus 64-bit-only probes |
| `perdedor-linux-x86_64` | Linux x86-64, any distribution; also Android-x86 | 189 Linux checks |

These are the default agents in v2. The v1 PowerShell and Python agents in `agents/windows` and
`agents/linux` remain only as a fallback (`perdedor test ... --engine legacy`).

## Run

Copy the executable into the guest and run it. The report is JSON (schema:
`schema/perdedor-report.schema.json`).

```bash
./perdedor-linux-x86_64 --profile standard -o report.json
perdedor-windows-x64.exe --only "class:cpu" "class:timing" -o report.json
```

| Option | Meaning |
|---|---|
| `-o FILE` | Write the report here (default: stdout) |
| `--profile quick\|standard\|deep` | Cheap checks only, the default set, or everything including slow probes |
| `--only PAT...` / `--skip PAT...` | Id globs (`win.timing.*`) or `class:`, `category:`, `technique:`, `cost:`, `tag:` selectors |
| `--param KEY=VALUE...` | Tune a threshold |
| `--no-network` | Leave out every check that sends traffic |
| `--list-checks` | Print the checks this build has, with their metadata |
| `--args-file FILE` | Read arguments from a file, one per line (how CHIMERA passes the operator's choices) |
| `--pretty`, `--version` | Indent the JSON; print the version |

The agent prints a one-line count when it finishes. The exposure score needs the catalog, which
lives on the analyst host: `perdedor score report.json`, then `perdedor plan report.json`.

## Layout

| Path | Contents |
|---|---|
| `src/core/` | Check registry, selection, per-check watchdog, JSON writer, command line |
| `src/common/` | Checks compiled into both platforms: CPUID, RDTSC and other instruction and timing probes |
| `src/windows/` | SMBIOS, ACPI, EDID, registry, WMI, devices, wear and tear, identity, network, debugger and instrumentation probes |
| `src/linux/` | DMI, `/proc` and `/sys`, containers, `systemd-detect-virt` parity, low-level probes |
| `tests/` | Unit tests, fixtures (SMBIOS/ACPI/EDID dumps), low-level smoke tests |

## Build and test

```bash
make -C native            # every target whose compiler is installed (g++, x86_64/i686-w64-mingw32-g++)
make -C native linux      # or win64, win32
make -C native test       # parser, timing-statistics and fixture tests
```

CI builds all three and runs them on Windows Server 2022 and 2025 (x64 and WOW64) and on Linux,
validating each report against the schema and the catalog.

## Safety rules for probes

- Read only. No settings change, nothing installed, nothing left behind.
- Every check runs under a watchdog with a budget set by its cost class; a probe that hangs is
  reported as an error and abandoned, never allowed to stall the scan.
- Instruction tricks that can fault are run under a guard; ones that can crash or wedge a guest
  (for example VMAware's `EIP_OVERFLOW` on Xen) are catalogued as not feasible and never executed.
- A probe that could not look reports `error` or `skipped` with the reason. Unknown is never clean.

See [docs/DESIGN-V2.md](../docs/DESIGN-V2.md) for how to add a check and
[docs/notes/lowlevel.md](../docs/notes/lowlevel.md) for the low-level probes.
