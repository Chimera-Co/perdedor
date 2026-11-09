"""How the Apple drivers reach a target: the local Mac, a Mac or iOS device over
ssh, or an iOS Simulator on the local Mac.

Nothing is installed on the target. Every probe is a standard command run
through ``/bin/sh -c`` (ssh runs it through the remote login shell, so the
command is wrapped in ``sh -c`` there too). Filesystem primitives
(existence, stat, directory listing, bounded reads) are implemented on top of
``run`` so the fake transport used by the tests can answer them from a
dictionary instead of a real filesystem.

A transport failure (ssh unreachable, command timed out) returns ``None`` so
the check reports ``error``; a command that ran and failed returns a
``CommandResult`` with a non-zero return code so the check can tell "absent"
from "could not look".
"""

from __future__ import annotations

import json
import os
import re
import shlex
import signal
import subprocess
import tempfile
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

# One command never blocks a scan for longer than this (seconds). Commands
# that legitimately take longer (system_profiler on a large machine, the
# sleep probe) pass their own timeout.
DEFAULT_TIMEOUT = 8.0
# ssh: fail fast instead of prompting, and drop dead connections.
SSH_OPTIONS = (
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "ServerAliveInterval=5",
    "-o",
    "ServerAliveCountMax=2",
    "-o",
    "LogLevel=ERROR",
)
# Directory listings and file reads are capped so a huge directory or file
# cannot stall the scan or flood the report.
MAX_LIST_ENTRIES = 5000
MAX_READ_BYTES = 262144


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclass(frozen=True)
class PathInfo:
    """``kind`` is ``file``, ``dir`` or ``link``; ``target`` is set for links."""

    path: str
    kind: str
    size: int | None = None
    mtime: int | None = None
    target: str | None = None


@dataclass(frozen=True)
class Listing:
    """Directory listing. ``entries`` is None when the directory could not be
    read; ``error`` then says why (missing, permission denied, TCC)."""

    entries: tuple[str, ...] | None
    error: str | None = None


def _q(path: str) -> str:
    return shlex.quote(path)


class Transport:
    """Base class: subclasses implement ``_exec``. The filesystem helpers
    below are expressed as POSIX shell so they work on macOS, on a
    jailbroken iOS device (rootful or rootless) and on Corellium."""

    name = "base"
    deadline = None

    def _exec(self, command: str, timeout: float) -> CommandResult | None:
        raise NotImplementedError

    def device_path(self, path: str) -> str:
        """Where a target path lives for this transport (identity except for
        the simulator, whose filesystem is a directory tree on the host)."""
        return path

    def describe(self) -> dict[str, str]:
        return {"transport": self.name}

    def run(self, command: str, *, key: str = "", timeout: float = DEFAULT_TIMEOUT) -> CommandResult | None:
        """Run ``command``. ``key`` names the probe for the fake transport."""
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
            if timeout <= 0:
                return None
        return self._exec(command, timeout)

    # -- filesystem primitives -------------------------------------------------

    def exists(self, paths: Sequence[str]) -> set[str] | None:
        if not paths:
            return set()
        mapped = {self.device_path(p): p for p in paths}
        script = (
            'for p in "$@"; do parent=${p%/*}; '
            'while [ "$parent" != "" ]; do '
            '[ -d "$parent" ] && { [ ! -x "$parent" ] || [ ! -r "$parent" ]; } && exit 77; parent=${parent%/*}; done; '
            'if [ -e "$p" ] || [ -L "$p" ]; then printf "%s\\n" "$p"; fi; done'
        )
        command = f"sh -c {_q(script)} _ " + " ".join(_q(p) for p in mapped)
        result = self.run(command, key="exists")
        if result is None or not result.ok:
            return None
        return {mapped[line] for line in result.stdout.splitlines() if line in mapped}

    def stat(self, paths: Sequence[str]) -> dict[str, PathInfo] | None:
        if not paths:
            return {}
        mapped = {self.device_path(p): p for p in paths}
        # BSD stat first (macOS, iOS), GNU stat as fallback (some bootstraps).
        script = (
            'for p in "$@"; do parent=${p%/*}; '
            'while [ "$parent" != "" ]; do '
            '[ -d "$parent" ] && { [ ! -x "$parent" ] || [ ! -r "$parent" ]; } && exit 77; parent=${parent%/*}; done; '
            'if [ -L "$p" ]; then k=link; elif [ -d "$p" ]; then k=dir; elif [ -e "$p" ]; then k=file; '
            "else continue; fi; "
            'm=$(stat -f %m "$p" 2>/dev/null || stat -c %Y "$p" 2>/dev/null); '
            's=$(stat -f %z "$p" 2>/dev/null || stat -c %s "$p" 2>/dev/null); '
            't=""; [ "$k" = link ] && t=$(readlink "$p"); '
            'printf "%s\\t%s\\t%s\\t%s\\t%s\\n" "$p" "$k" "$s" "$m" "$t"; done'
        )
        command = f"sh -c {_q(script)} _ " + " ".join(_q(p) for p in mapped)
        result = self.run(command, key="stat")
        if result is None or not result.ok:
            return None
        out: dict[str, PathInfo] = {}
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 5 or parts[0] not in mapped:
                continue
            original = mapped[parts[0]]
            out[original] = PathInfo(
                path=original,
                kind=parts[1],
                size=_int_or_none(parts[2]),
                mtime=_int_or_none(parts[3]),
                target=parts[4] or None,
            )
        return out

    def listdir(self, path: str) -> Listing | None:
        device = self.device_path(path)
        script = (
            'if [ ! -d "$1" ]; then echo "__PERDEDOR_MISSING__"; exit 0; fi; '
            'ls -1A "$1" 2>&1 || echo "__PERDEDOR_DENIED__"'
        )
        result = self.run(f"sh -c {_q(script)} _ {_q(device)}", key="listdir")
        if result is None or not result.ok:
            return None
        if re.search(r"(?i)permission denied|operation not permitted", result.stdout + result.stderr):
            return Listing(None, "permission denied")
        lines = result.stdout.splitlines()
        if lines and lines[0] == "__PERDEDOR_MISSING__":
            return Listing(None, "missing")
        if lines and lines[-1] == "__PERDEDOR_DENIED__":
            return Listing(
                None, "permission denied (on macOS: grant Full Disk Access to the ssh/terminal process)"
            )
        if len(lines) >= MAX_LIST_ENTRIES:
            return Listing(None, "directory listing truncated")
        return Listing(tuple(lines))

    def read_text(self, path: str, max_bytes: int = MAX_READ_BYTES) -> str | None:
        """Bounded read; None if the file is missing or unreadable."""
        result = self.run(f"head -c {int(max_bytes)} {_q(self.device_path(path))}", key="read")
        if result is None or not result.ok:
            return None
        return result.stdout


def _int_or_none(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# Hard output cap as well as a timeout: large ioreg trees cannot exhaust memory.
MAX_OUTPUT_BYTES = 4 * 1024 * 1024


def _subprocess(argv: list[str], timeout: float) -> CommandResult | None:
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            proc = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
                return None
            if stdout.tell() + stderr.tell() > MAX_OUTPUT_BYTES:
                return CommandResult(75, "", "command output exceeded limit")
            stdout.seek(0)
            stderr.seek(0)
            return CommandResult(
                proc.returncode,
                stdout.read().decode(errors="replace"),
                stderr.read().decode(errors="replace"),
            )
    except (OSError, subprocess.SubprocessError):
        return None


class LocalTransport(Transport):
    """The machine this process runs on (``--local``)."""

    name = "local"

    def _exec(self, command: str, timeout: float) -> CommandResult | None:
        return _subprocess(["/bin/sh", "-c", command], timeout)


@dataclass
class SshTransport(Transport):
    """``ssh [-i key] [-p port] user@host -- sh -c '<command>'``. Key-based,
    non-interactive authentication only (BatchMode)."""

    destination: str
    identity: str | None = None
    port: int | None = None
    extra_options: tuple[str, ...] = ()
    path_prefix: str = ""
    name = "ssh"

    def __post_init__(self):
        if not re.fullmatch(r"(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9_][A-Za-z0-9_.:-]*", self.destination):
            raise ValueError("invalid SSH destination")
        if self.port is not None and not 1 <= self.port <= 65535:
            raise ValueError("SSH port must be 1..65535")

    def argv(self, command: str) -> list[str]:
        argv = ["ssh", *SSH_OPTIONS, *self.extra_options]
        if self.identity:
            argv += ["-i", self.identity]
        if self.port:
            argv += ["-p", str(self.port)]
        remote = f"{self.path_prefix}{command}" if self.path_prefix else command
        argv += ["--", self.destination, f"sh -c {_q(remote)}"]
        return argv

    def _exec(self, command: str, timeout: float) -> CommandResult | None:
        result = _subprocess(self.argv(command), timeout)
        # ssh itself returns 255 when the connection fails.
        if result is not None and result.returncode == 255 and not result.stdout:
            return None
        return result

    def describe(self) -> dict[str, str]:
        doc = {"transport": "ssh", "destination": self.destination}
        if self.port:
            doc["port"] = str(self.port)
        return doc


@dataclass
class FakeTransport(Transport):
    """Answers from a fixture instead of a machine.

    ``commands`` maps a probe key (the ``key=`` passed to ``run``) to stdout,
    or to ``{"rc": int, "stdout": str, "stderr": str}``; a key absent from the
    fixture behaves like a missing command (rc 127). ``fs`` maps absolute
    paths to ``{"kind": "file|dir|link", "size": n, "mtime": t, "target": p,
    "entries": [...], "text": "...", "denied": bool}``. ``unreachable`` makes
    every call fail like a dead ssh connection.
    """

    commands: Mapping[str, Any] = field(default_factory=dict)
    fs: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    unreachable: bool = False
    calls: list[tuple[str, str]] = field(default_factory=list)
    # Transport mode represented by the fixture ("ssh", "local",
    # "simulator") and, for the simulator, the simctl device record.
    mode: str = "fake"
    device: dict = field(default_factory=dict)
    name = "fake"

    @classmethod
    def from_fixture(cls, path) -> FakeTransport:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        meta = doc.get("transport", {})
        return cls(
            commands=doc.get("commands", {}),
            fs=doc.get("fs", {}),
            mode=meta.get("mode", "fake"),
            device=meta.get("device", {}),
        )

    def run(self, command: str, *, key: str = "", timeout: float = DEFAULT_TIMEOUT) -> CommandResult | None:
        self.calls.append((key, command))
        if self.unreachable:
            return None
        answer = self.commands.get(key)
        if answer is None:
            return CommandResult(127, "", f"{key}: command not found")
        if isinstance(answer, str):
            return CommandResult(0, answer, "")
        if answer.get("unreachable"):
            return None
        return CommandResult(int(answer.get("rc", 0)), answer.get("stdout", ""), answer.get("stderr", ""))

    def _entry(self, path: str) -> Mapping[str, Any] | None:
        entry = self.fs.get(path)
        if entry is not None:
            return entry
        # A path below a listed directory's entries exists implicitly.
        parent, _, leaf = path.rstrip("/").rpartition("/")
        parent_entry = self.fs.get(parent or "/")
        if parent_entry and leaf in parent_entry.get("entries", ()):
            return {"kind": "file"}
        return None

    def exists(self, paths: Sequence[str]) -> set[str] | None:
        if self.unreachable:
            return None
        if any((self._entry(p) or {}).get("denied") for p in paths):
            return None
        return {p for p in paths if self._entry(p) is not None}

    def stat(self, paths: Sequence[str]) -> dict[str, PathInfo] | None:
        if self.unreachable:
            return None
        if any((self._entry(p) or {}).get("denied") for p in paths):
            return None
        out = {}
        for p in paths:
            entry = self._entry(p)
            if entry is None:
                continue
            out[p] = PathInfo(
                path=p,
                kind=entry.get("kind", "file"),
                size=entry.get("size"),
                mtime=entry.get("mtime"),
                target=entry.get("target"),
            )
        return out

    def listdir(self, path: str) -> Listing | None:
        if self.unreachable:
            return None
        entry = self.fs.get(path.rstrip("/") or "/")
        if entry is None or entry.get("kind", "dir") != "dir":
            return Listing(None, "missing")
        if entry.get("denied"):
            return Listing(
                None, "permission denied (on macOS: grant Full Disk Access to the ssh/terminal process)"
            )
        return Listing(tuple(entry.get("entries", ())))

    def read_text(self, path: str, max_bytes: int = MAX_READ_BYTES) -> str | None:
        if self.unreachable:
            return None
        entry = self.fs.get(path)
        if entry is None or entry.get("denied") or "text" not in entry:
            return None
        return entry["text"][:max_bytes]


def join_paths(prefixes: Iterable[str], paths: Iterable[str]) -> list[str]:
    """Every path under every prefix (``""`` = as given), order preserved,
    duplicates removed. Used for rootful + rootless (/var/jb) jailbreak paths."""
    out: list[str] = []
    for path in paths:
        for prefix in prefixes:
            # /var and /private/var hold user data and are not relocated by a
            # rootless bootstrap, so they are only checked as given.
            if prefix and path.startswith(("/var/", "/private/var/")):
                continue
            candidate = f"{prefix.rstrip('/')}{path}" if prefix else path
            if candidate not in out:
                out.append(candidate)
    return out
