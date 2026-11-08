# Low-level probes (CPU, timing, debugger, instrumentation)

These are the checks only native code can run: CPUID and instruction behaviour, RDTSC timing,
debugger artefacts and in-process instrumentation. They live in `native/src/common/` (shared by
both builds) and in `native/src/{linux,windows}/lowlevel_*`.

## What is implemented

| Platform | Catalogued | Implemented | cpu | timing | debugger | instrumentation | Other statuses |
|---|---|---|---|---|---|---|---|
| Linux (`linux-lowlevel.json` + v1 ids) | 30 | 29 | 12 | 8 | 5 | 5 | 1 not_feasible |
| Windows (`windows-lowlevel.json` + v1 ids) | 50 | 41 | 13 | 9 | 19 | 9 | 5 not_feasible, 4 planned |

### CPU

- Hypervisor bit and vendor leaf (v1 ids kept).
- A scan of the hypervisor leaf range 0x40000000–0x4001FF00 in steps of 0x100. This finds Xen's
  leaves when Viridian relocates them to 0x40000100, which `cpuidmon -s` does not mask.
- Hyper-V/Viridian enlightenment leaves.
- Brand string, and vendor-versus-brand consistency.
- Feature-bit consistency (hypervisor bit versus leaf range, OSXSAVE/XSAVE, x2APIC, TSC-deadline,
  invariant TSC, VMX/SVM visibility).
- Topology consistency (leaves 4/0xB/0x1F against the OS core count) and cache descriptors.
- SIDT/SGDT/SLDT/STR/SMSW. The report notes their low discrimination on modern 64-bit kernels.
- Guarded probes: the VMware backdoor port (0x5658, commands 0x0A and 0x14), the VirtualPC opcode,
  VMCALL/VMMCALL behaviour, and emulator flag quirks.

### Timing

- **RDTSC around CPUID (VM-exit cost).** Reports min, median, p90, trimmed mean and MAD over 100,000
  iterations, plus al-khaser's 10-round average over N trials. The `measurement` field carries the
  same fields as CHIMERA's former cpuid-timing harness (`rdtsc_rdtsc`, `rdtsc_cpuid_rdtsc`,
  `alkhaser_style_avg10`, `alkhaser_style_detected` as "k/n"), so that harness is no longer needed.
- CPUID leaf-timing differences, and RDTSC/RDTSCP availability.
- TSC frequency stability against the monotonic clock.
- Sleep acceleration: several sleep methods, each measured by four independent clocks, with a long
  variant in the deep profile.
- Timer-resolution plausibility.
- On Windows, the Locky-style ratio and the uptime check.

### Debugger

- **Windows:** the documented and PEB/heap/NtQuery* artefacts, KUSER_SHARED_DATA, hardware
  breakpoints, the exception tricks (INT3, INT 2D, ICEBP, trap flag, CloseHandle), the
  ThreadHideFromDebugger round trip and the parent process.
- **Linux:** TracerPid, a PTRACE_TRACEME self-test in a forked child, the /proc status flags,
  software breakpoints at function entries, a debugger parent and the gdb terminal environment.

### Instrumentation

- **Windows:**
  - inline-hook scan of the ntdll syscall stubs (x64 and WOW64 shapes) and of selected exports;
  - in-memory `.text` of ntdll and kernelbase compared with the on-disk image;
  - IAT/EAT redirection, unexpected modules, AppInit/AppCert DLLs, and EtwEventWrite patches;
  - the system-call latency side channel.
- **Linux:**
  - LD_PRELOAD and /etc/ld.so.preload;
  - tool libraries in /proc/self/maps;
  - kprobes/uprobes and eBPF state visible without root, and perf_event_paranoid;
  - the same syscall latency side channel (failing `open` against `getpid`).

## Design decisions

- **Guarded execution.** Every instruction that can fault runs under `guard.hpp`:
  - on Linux, per-thread `sigsetjmp`/`siglongjmp` for SIGILL/SIGSEGV/SIGBUS/SIGTRAP;
  - on Windows, a vectored exception handler that records the code and resumes at a recovery point,
    because MinGW has no `__try`.

  The tests run UD2 and an invalid read under the guard and assert that it recovers.
- **EIP_OVERFLOW is never executed.** VMAware's EIP_OVERFLOW crashed CHIMERA's Xen guest during the
  DRAKVUF scans, so it is catalogued as `not_feasible` on both platforms with that reason.
- **Research-grade checks.** The syscall latency side channel and the leaf-timing ratio carry
  `research` tiers, moderate confidence and tunable thresholds. Their thresholds are local policy,
  not hardware boundaries, and the catalog says so.
- **Bounded runtime.** Timing loops are bounded by an iteration cap (1,000,000), a sampling budget
  (4 s) and a clock-poll cap, so a frozen or patched clock cannot hang the agent.
- **Operator parameters.** Every threshold an operator can tune is listed in the catalog entry's
  `params` (name, default, meaning):
  - `timing.*`: `iterations`, `trials`, `vmexit_cycles`, `leaf_ratio`, `sleep_ms`, `long_sleep_ms`,
    `tsc_windows`, `tsc_drift_fraction`, `resolution_ns`, `locky_ratio`;
  - `instrumentation.*`: `latency_ratio`, `min_latency_ns`, `iterations`.
- **Proposed technique keys.** Five keys are proposed in `research/proposed-techniques-lowlevel.json`:
  cache descriptors, timer resolution, software breakpoints, import/export redirection and
  hypervisor enlightenments.

## What CHIMERA can and cannot fix

- **CPUID.** `cpuidmon -s` masks leaf 1 and 0x40000000. The leaf-range scan and the enlightenment
  check show whether relocated Xen or Viridian leaves still leak; disable Viridian
  (`viridian=0`) or extend the mask.
- **Timing.** VM-exit cost and TSC behaviour are fixable only at the hypervisor (TSC offsetting and
  scaling, exit-cost compensation), and only partially. A DRAKVUF-traced syscall costs
  microseconds more; that is inherent to breakpoint-based introspection and can be reduced, not
  removed.
- **Debugger and instrumentation.** These checks pass on CHIMERA by design, because DRAKVUF is
  agentless and adds no in-guest hooks. They guard against in-guest tooling creeping into the
  image.

## Verification

- `make -C native test` runs:
  - the core tests;
  - `lowlevel_tests`: guard, statistics, stub and branch parsers, classifier, PE and procfs
    fixtures;
  - the Linux fixture test;
  - a smoke run of `--only class:cpu,class:timing` that validates the measurement and confidence
    contract of every low-level id.
- `make -C native win64 win32` builds the agent and the low-level unit tests for both Windows
  architectures without warnings, under `-Werror` for the tests.
- Under Wine, the low-level unit tests pass. The Windows agent ran the cpu, timing, debugger and
  instrumentation classes (48 findings) without a crash or hang. Wine is not Windows, so this is a
  crash test only.
- `pytest` passes 139 tests, including the catalog consistency tests.

## Needs validation on a real target

- **Timing thresholds and the syscall side channel.** Calibrate them on the CHIMERA host, inside
  the Windows 10 and Debian 12 guests, with DRAKVUF attached and detached, before giving them more
  weight.
- **Windows debugger and hook checks.** Confirm them on real Windows 10/11 x64 and on WOW64 (CI
  runs the agent on windows-2022 and windows-2025).
- **Planned and not_feasible Windows entries.** Each carries the reason it was deferred.
