# Sandbox integration contract

How a sandbox (or any harness) runs PERDEDOR inside a guest and reads the result. CHIMERA is the first user;
nothing here is specific to it.

## The contract in one paragraph

Copy **one file**, the native agent for the guest's platform, into the guest. Run it:

```text
perdedor-windows-x64.exe --profile standard --report C:\perdedor\report.json --progress C:\perdedor\progress.jsonl
perdedor-linux-x86_64     --profile standard --report /tmp/perdedor/report.json --progress /tmp/perdedor/progress.jsonl
```

Read `report.json` back. If the run did not finish, read `progress.jsonl`: it says which probe was running.
The agent needs no interpreter, shell, service, network or installed runtime. It works when started by an
out-of-guest injector (DRAKVUF), over SSH or WinRM, or by hand.

## Command line

| Option | Meaning |
|---|---|
| `--report FILE` (also `-o`, `--output`) | where the JSON report goes (stdout if absent) |
| `--progress FILE` | where the progress events go (none if absent) |
| `--profile quick\|standard\|deep` | how expensive a selection to run; `deep` adds slow and interactive probes |
| `--only PATTERN`, `--skip PATTERN` | id globs (`win.timing.*`) or `class:`, `category:`, `technique:`, `cost:`, `tag:` |
| `--param KEY=VALUE` | probe parameters, including the watchdog budgets below |
| `--no-network` | skip every probe that needs the network |
| `--seed N` | fixes the (shuffled) probe order, for reproducible runs |
| `--args-file FILE` | read the arguments from a file, one per line (for injectors with short command lines) |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the report was written |
| 1 | the report or progress file could not be written |
| 2 | bad arguments (usage printed on stderr) |
| anything else, or no exit | the process was killed or the guest stopped: read `progress.jsonl` |

A probe that fails or exceeds its budget does not change the exit code: it becomes an `error` finding in the
report.

## Probe budgets

Every probe runs on its own thread under a watchdog. When the budget runs out the probe is abandoned, reported
as `error` ("exceeded its watchdog budget"), and the scan continues. Defaults by the probe's cost:

| Cost | Budget | Override |
|---|---|---|
| fast | 10 s | `--param watchdog.fast_s=N` |
| medium | 45 s | `--param watchdog.medium_s=N` |
| slow | 240 s | `--param watchdog.slow_s=N` |

A probe that crashes or freezes the whole guest (as opposed to hanging its own thread) cannot be caught from
inside. The progress file is what localises it, and `--skip <id>` leaves it out of the next run.

## Progress file

One JSON object per line, written in order and flushed to disk (fsync / `_commit`) after every line, so the
file survives a guest that freezes right after. Every event carries `t_ms`, milliseconds since the agent began.

| Event | Fields | When |
|---|---|---|
| `begin` | `version`, `platform`, `scan_id`, `profile`, `total`, `report` | once, before the first probe |
| `start` | `probe`, `index`, `total`, `budget_s` | before each probe |
| `end` | `probe`, `index`, `ms`, `outcome` (`ok`, `timed_out`, `raised`), `findings` | after each probe |
| `done` | `exit_code`, `findings`, `detected`, `errored` | once, after the report was written |
| `failed` | `reason`, `exit_code` | instead of `done` when the report could not be written |

Reading it:

- `done` present: the scan finished; use the report.
- a `start` without its `end`, and no `done`: the scan stopped inside that probe. If it stopped long after
  `t_ms + budget_s`, the probe froze more than its own thread.
- only `begin`: the agent stopped before the first probe.
- the last line may be cut off if the guest stopped mid-write; ignore a line that is not valid JSON.

## Reference driver

`perdedor_common.driver` implements the host side: stage, run, collect, read the progress, score.

```python
from perdedor_common.driver import LocalTransport, run_scan, score

result = run_scan(LocalTransport(), "perdedor-linux-x86_64", "/tmp/perdedor", profile="standard")
if result.ok:
    print(score(result.report))
else:
    print(result.progress.state, result.progress.stuck)   # e.g. "stopped in a probe", "win.env.ept_hook_timing"
```

A sandbox supplies its own transport: an object with `put(local, remote)`, `run(argv, timeout) -> exit code`
and `get(remote, local) -> bool`, over whatever channel reaches its guest.
