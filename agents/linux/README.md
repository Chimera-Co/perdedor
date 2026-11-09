# Linux agent, v1 (Python), legacy

> **v2 uses the native agent** (`native/`, `perdedor-linux-x86_64`): 189 checks in one static
> binary, including CPUID, RDTSC and other low-level probes. This Python agent is kept as a
> fallback and receives no new checks.

It runs 37 checks with the Python 3.10+ standard library:

```bash
python3 -m perdedor_linux -o report.json
```

or `perdedor test linux --engine legacy`. Score the report with `perdedor score report.json`.
Its checks are a subset of the native agent's, with the same ids.
