"""Reference driver for sandboxes (issue #6, section 3): stage the native agent, run it, collect the report and
read its progress file. The contract it implements is docs/INTEGRATION.md.

A sandbox supplies a :class:`Transport` for its guest channel (CHIMERA: the DRAKVUF injector and its guest agent;
others: SSH, WinRM, a shared folder). :class:`LocalTransport` runs the agent on this machine, for tests and for
scanning the host itself.

    from perdedor_common.driver import LocalTransport, run_scan
    result = run_scan(LocalTransport(), "native/build/perdedor-linux-x86_64", "/tmp/perdedor", profile="quick")
    result.report          # the agent's JSON report (None if it never finished)
    result.progress.stuck  # the probe that was running when the scan stopped, if it stopped early
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Protocol

REPORT_NAME = "report.json"
PROGRESS_NAME = "progress.jsonl"

# Exit codes of the native agent (docs/INTEGRATION.md)
EXIT_OK = 0
EXIT_IO_ERROR = 1
EXIT_USAGE = 2


@dataclass
class Progress:
    """What a progress file says: how far the scan got, and where it stopped if it did not finish."""

    total: int | None = None
    started: int = 0
    finished: int = 0
    done: bool = False
    failed: str | None = None
    exit_code: int | None = None
    stuck: str | None = None  # probe with a start and no end: running when the file stopped growing
    stuck_budget_s: float | None = None
    timed_out: list[str] = field(default_factory=list)
    raised: list[str] = field(default_factory=list)
    slowest: list[tuple[str, float]] = field(default_factory=list)
    last_t_ms: float | None = None
    scan_id: str | None = None

    @property
    def state(self) -> str:
        if self.done:
            return "done"
        if self.failed:
            return "failed"
        if self.stuck:
            return "stopped in a probe"
        if self.total is None:
            return "not started"
        return "between probes"


def parse_progress(lines: Iterable[str]) -> Progress:
    """Read progress JSON lines. A torn last line (the guest froze mid-write) is ignored."""
    p = Progress()
    open_probe: dict[str, dict] = {}
    durations: list[tuple[str, float]] = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            ev = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        p.last_t_ms = ev.get("t_ms", p.last_t_ms)
        kind = ev.get("event")
        if kind == "begin":
            p.total = ev.get("total")
            p.scan_id = ev.get("scan_id")
        elif kind == "start":
            p.started += 1
            open_probe[ev.get("probe")] = ev
        elif kind == "end":
            p.finished += 1
            probe = ev.get("probe")
            open_probe.pop(probe, None)
            if ev.get("outcome") == "timed_out":
                p.timed_out.append(probe)
            elif ev.get("outcome") == "raised":
                p.raised.append(probe)
            if isinstance(ev.get("ms"), (int, float)):
                durations.append((probe, float(ev["ms"])))
        elif kind == "done":
            p.done = True
            p.exit_code = ev.get("exit_code")
        elif kind == "failed":
            p.failed = ev.get("reason") or "failed"
            p.exit_code = ev.get("exit_code")
    if open_probe and not p.done:
        last = list(open_probe.values())[-1]
        p.stuck = last.get("probe")
        p.stuck_budget_s = last.get("budget_s")
    p.slowest = sorted(durations, key=lambda d: -d[1])[:5]
    return p


def read_progress(path: str | Path) -> Progress:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return parse_progress(f)
    except OSError:
        return Progress()


class Transport(Protocol):
    """A guest channel. Paths on the guest side are strings in the guest's own syntax."""

    def put(self, local: Path, remote: str) -> None:
        """Copy the local file to the guest path."""

    def run(self, argv: list[str], timeout: float) -> int:
        """Run argv in the guest; return its exit code (-1 if it did not finish within timeout)."""

    def get(self, remote: str, local: Path) -> bool:
        """Copy the guest file to the local path; False if it does not exist or cannot be read."""


class LocalTransport:
    """Runs the agent on this machine (tests, or scanning the host itself)."""

    def put(self, local: Path, remote: str) -> None:
        Path(remote).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(local, remote)
        os.chmod(remote, 0o700)

    def run(self, argv: list[str], timeout: float) -> int:
        try:
            return subprocess.run(
                argv, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
            ).returncode
        except subprocess.TimeoutExpired:
            return -1

    def get(self, remote: str, local: Path) -> bool:
        try:
            shutil.copy2(remote, local)
            return True
        except OSError:
            return False


@dataclass
class ScanResult:
    exit_code: int
    report: dict | None
    progress: Progress
    report_path: Path | None
    progress_path: Path | None

    @property
    def ok(self) -> bool:
        return self.exit_code == EXIT_OK and self.report is not None and self.progress.done


def guest_join(guest_dir: str, name: str) -> str:
    """Join a guest path in the guest's syntax (a drive letter or backslash means Windows)."""
    if "\\" in guest_dir or (len(guest_dir) > 1 and guest_dir[1] == ":"):
        return str(PureWindowsPath(guest_dir) / name)
    return str(PurePosixPath(guest_dir) / name)


def agent_argv(
    agent: str,
    report: str,
    progress: str,
    *,
    profile: str = "standard",
    only: Iterable[str] = (),
    skip: Iterable[str] = (),
    params: dict[str, Any] | None = None,
    network: bool = True,
) -> list[str]:
    """The agent command line of the contract."""
    argv = [agent, "--profile", profile, "--report", report, "--progress", progress]
    for pattern in only:
        argv += ["--only", pattern]
    for pattern in skip:
        argv += ["--skip", pattern]
    for key, value in (params or {}).items():
        argv += ["--param", f"{key}={value}"]
    if not network:
        argv.append("--no-network")
    return argv


def run_scan(
    transport: Transport,
    agent: str | Path,
    guest_dir: str,
    *,
    out_dir: str | Path | None = None,
    profile: str = "standard",
    only: Iterable[str] = (),
    skip: Iterable[str] = (),
    params: dict[str, Any] | None = None,
    network: bool = True,
    timeout: float = 1800,
) -> ScanResult:
    """Stage the agent in `guest_dir`, run it, and fetch the report and the progress file.

    The progress file is fetched even when the run failed or timed out, so the caller can see which probe was
    running. `out_dir` (default: a new temporary directory) receives both files."""
    agent = Path(agent)
    remote_agent = guest_join(guest_dir, agent.name)
    remote_report = guest_join(guest_dir, REPORT_NAME)
    remote_progress = guest_join(guest_dir, PROGRESS_NAME)
    out = Path(out_dir) if out_dir else Path(tempfile.mkdtemp(prefix="perdedor-run-"))
    out.mkdir(parents=True, exist_ok=True)
    transport.put(agent, remote_agent)
    argv = agent_argv(
        remote_agent,
        remote_report,
        remote_progress,
        profile=profile,
        only=only,
        skip=skip,
        params=params,
        network=network,
    )
    code = transport.run(argv, timeout)
    local_progress = out / PROGRESS_NAME
    local_report = out / REPORT_NAME
    progress = read_progress(local_progress) if transport.get(remote_progress, local_progress) else Progress()
    report = None
    if transport.get(remote_report, local_report):
        try:
            report = json.loads(local_report.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            report = None
    return ScanResult(
        exit_code=code,
        report=report,
        progress=progress,
        report_path=local_report if report is not None else None,
        progress_path=local_progress if local_progress.exists() else None,
    )


def score(report: dict, baseline: Any = None) -> dict | None:
    """The exposure headline of a report (None if it cannot be scored)."""
    from .exposure import headline

    return headline(report, baseline=baseline)
