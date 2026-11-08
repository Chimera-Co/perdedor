"""adb transport and a cached view of one device.

The Android agent runs on the analyst host and drives the target (a real
phone, an emulator, or CHIMERA's Android-x86 guest) over adb; nothing is
installed on the device. Two layers live here:

* ``AdbTransport`` runs ``adb -s SERIAL shell ...`` / ``push`` and reports
  the exit status. Tests replace it with a fake transport that answers from
  recorded outputs (tests/fixtures/android/).
* ``Device`` caches everything a scan reads more than once (the property
  dump, ``settings list``, package lists, ``ps``, mounts, path existence) so
  a full scan costs a few dozen adb round trips instead of several hundred.

Every read fails soft: ``None`` means "could not look" and the calling check
reports ``error`` or ``skipped``, never ``clean``.

The module-level helpers (``shell``, ``getprop``, ``file_exists``,
``device_reachable``) are the v1 API and are kept for callers outside the
check modules.
"""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

DEFAULT_TIMEOUT = 8.0  # seconds per adb shell call; dumpsys on a slow emulator can take several seconds


@dataclass(frozen=True)
class ShellResult:
    returncode: int
    stdout: str
    stderr: str = ""


class Transport(Protocol):
    """What a check needs from a device connection."""

    def reachable(self) -> bool: ...

    def shell(self, command: str, timeout: float = DEFAULT_TIMEOUT) -> ShellResult | None: ...

    def push(self, local: str, remote: str, timeout: float = 60.0) -> bool: ...


def adb_binary_available() -> bool:
    return shutil.which("adb") is not None


class AdbTransport:
    """``adb`` CLI transport. ``serial=None`` uses adb's default device."""

    def __init__(self, serial: str | None = None, adb: str = "adb") -> None:
        self.serial = serial
        self.adb = adb
        self._reachable: bool | None = None

    def _base(self) -> list[str]:
        cmd = [self.adb]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd

    def reachable(self) -> bool:
        if self._reachable is None:
            self._reachable = _device_state(self._base()) == "device"
        return self._reachable

    def shell(self, command: str, timeout: float = DEFAULT_TIMEOUT) -> ShellResult | None:
        try:
            result = subprocess.run(
                self._base() + ["shell", command],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return ShellResult(result.returncode, result.stdout.replace("\r\n", "\n"), result.stderr)

    def push(self, local: str, remote: str, timeout: float = 60.0) -> bool:
        try:
            result = subprocess.run(
                self._base() + ["push", local, remote],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return result.returncode == 0


def _device_state(base: list[str]) -> str | None:
    if shutil.which(base[0]) is None:
        return None
    try:
        result = subprocess.run(base + ["get-state"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


# --------------------------------------------------------------------------- parsers

_PROP_LINE = re.compile(r"^\[([^\]]+)\]: \[(.*)\]$")


def parse_getprop(text: str) -> dict[str, str]:
    """Parse ``getprop`` output (``[key]: [value]``; values may span lines)."""
    props: dict[str, str] = {}
    key: str | None = None
    buf: list[str] = []
    for line in text.splitlines():
        if key is None:
            match = _PROP_LINE.match(line)
            if match:
                props[match.group(1)] = match.group(2)
                continue
            start = re.match(r"^\[([^\]]+)\]: \[(.*)$", line)
            if start:
                key, buf = start.group(1), [start.group(2)]
        else:
            if line.endswith("]"):
                buf.append(line[:-1])
                props[key] = "\n".join(buf)
                key, buf = None, []
            else:
                buf.append(line)
    return props


def parse_settings(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip():
            out[key.strip()] = value.strip()
    return out


def parse_packages(text: str) -> list[str]:
    return [line.split(":", 1)[1].strip() for line in text.splitlines() if line.startswith("package:")]


def parse_ps(text: str) -> list[dict[str, str]]:
    """Parse ``ps -A -o PID,USER,NAME`` (toybox) or legacy toolbox ``ps``."""
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return []
    header = lines[0].split()
    rows = []
    for line in lines[1:]:
        parts = line.split()
        if not parts:
            continue
        if header[:3] == ["PID", "USER", "NAME"]:
            if len(parts) >= 3:
                rows.append({"pid": parts[0], "user": parts[1], "name": " ".join(parts[2:])})
        elif "PID" in header and len(parts) >= 2:
            # toolbox: USER PID PPID VSIZE RSS WCHAN PC S NAME
            pid_idx = header.index("PID")
            rows.append(
                {"pid": parts[pid_idx] if pid_idx < len(parts) else "", "user": parts[0], "name": parts[-1]}
            )
    return rows


def parse_proc_net_tcp(text: str) -> list[tuple[str, int]]:
    """Return (local_ip_hex, port) of LISTEN sockets (state 0A) in /proc/net/tcp{,6}."""
    out = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4 or parts[3] != "0A":
            continue
        ip_hex, _, port_hex = parts[1].partition(":")
        try:
            out.append((ip_hex, int(port_hex, 16)))
        except ValueError:
            continue
    return out


def shell_quote(value: str) -> str:
    return shlex.quote(value)


EXISTS_SCRIPT_PREFIX = "for p in "


def exists_script(paths: Sequence[str]) -> str:
    """One shell round trip that tests many paths: prints ``1 PATH`` / ``0 PATH``."""
    quoted = " ".join(shell_quote(p) for p in paths)
    return (
        f"{EXISTS_SCRIPT_PREFIX}{quoted}; do "
        'if [ -e "$p" ] || [ -L "$p" ]; then echo "1 $p"; '
        "else parent=${p%/*}; denied=0; "
        'while [ "$parent" != "" ]; do '
        '[ -d "$parent" ] && [ ! -x "$parent" ] && denied=1; '
        "parent=${parent%/*}; done; "
        'if [ "$denied" = 1 ]; then echo "? $p"; else echo "0 $p"; fi; fi; done'
    )


# --------------------------------------------------------------------------- device view


class Device:
    """Cached, read-only view of one device. All methods return ``None`` when
    the information could not be collected."""

    def __init__(self, transport: Transport, path_universe: Iterable[str] = ()) -> None:
        self.t = transport
        self._cache: dict[Any, Any] = {}
        self._exists: dict[str, bool | None] = {}
        self._universe = tuple(dict.fromkeys(path_universe))
        self.calls = 0
        self.deadline: float | None = None

    # -- primitives ---------------------------------------------------------
    def reachable(self) -> bool:
        if "reachable" not in self._cache:
            try:
                self._cache["reachable"] = bool(self.t.reachable())
            except Exception:  # noqa: BLE001 - a broken transport means unreachable
                self._cache["reachable"] = False
        return self._cache["reachable"]

    def run(self, command: str, timeout: float = DEFAULT_TIMEOUT) -> ShellResult | None:
        """Uncached shell call (for commands whose output changes, e.g. timing)."""
        if not self.reachable():
            return None
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
            if timeout <= 0:
                return None
        self.calls += 1
        try:
            return self.t.shell(command, timeout)
        except Exception:  # noqa: BLE001
            return None

    def sh(self, command: str, timeout: float = DEFAULT_TIMEOUT, *, any_rc: bool = False) -> str | None:
        """Cached shell call; stdout when the command exited 0 (or always with ``any_rc``)."""
        key = ("sh", command, any_rc)
        if key not in self._cache:
            result = self.run(command, timeout)
            failed = result is not None and re.search(
                r"(?i)permission deni(?:ed|al)|securityexception|unknown command|not found|cannot access",
                result.stdout + result.stderr,
            )
            if result is None or failed or (result.returncode != 0 and not any_rc):
                self._cache[key] = None
            else:
                self._cache[key] = result.stdout
        return self._cache[key]

    def push(self, local: str, remote: str, timeout: float = 60.0) -> bool:
        if not self.reachable():
            return False
        try:
            return bool(self.t.push(local, remote, timeout))
        except Exception:  # noqa: BLE001
            return False

    # -- properties ---------------------------------------------------------
    def props(self) -> dict[str, str] | None:
        if "props" not in self._cache:
            text = self.sh("getprop")
            self._cache["props"] = parse_getprop(text) if text else None
        return self._cache["props"]

    def prop(self, name: str) -> str | None:
        """Property value, '' if unset; None if the property dump failed."""
        props = self.props()
        if props is None:
            return None
        return props.get(name, "")

    def sdk(self) -> int | None:
        value = self.prop("ro.build.version.sdk")
        try:
            return int(value) if value else None
        except ValueError:
            return None

    def settings(self, namespace: str) -> dict[str, str] | None:
        key = ("settings", namespace)
        if key not in self._cache:
            text = self.sh(f"settings list {namespace}")
            self._cache[key] = parse_settings(text) if text is not None else None
        return self._cache[key]

    def setting(self, namespace: str, name: str) -> str | None:
        values = self.settings(namespace)
        if values is None:
            return None
        return values.get(name, "")

    # -- files --------------------------------------------------------------
    def exists(self, paths: Iterable[str]) -> dict[str, bool | None] | None:
        wanted = list(dict.fromkeys(paths))
        missing = [p for p in wanted if p not in self._exists]
        if missing:
            batch = list(dict.fromkeys(missing + [p for p in self._universe if p not in self._exists]))
            text = self.sh(exists_script(batch), any_rc=True)
            if text is None:
                return None
            for line in text.splitlines():
                flag, _, path = line.partition(" ")
                if flag in ("0", "1", "?") and path:
                    self._exists[path] = None if flag == "?" else flag == "1"
            if any(p not in self._exists for p in wanted):
                return None
        return {p: self._exists[p] for p in wanted}

    def existing(self, paths: Iterable[str]) -> list[str] | None:
        found = self.exists(paths)
        if found is None:
            return None
        present = [p for p, value in found.items() if value]
        return present if present or all(v is not None for v in found.values()) else None

    def read(self, path: str, timeout: float = DEFAULT_TIMEOUT) -> str | None:
        """File contents, or None when the file is missing or unreadable."""
        text = self.sh(f"cat {shell_quote(path)} 2>/dev/null", timeout)
        if text is None or text == "":
            return None
        return text

    def listdir(self, path: str) -> list[str] | None:
        text = self.sh(f"ls -1a {shell_quote(path)} 2>/dev/null")
        if text is None:
            return None
        return [name for name in text.splitlines() if name and name not in (".", "..")]

    # -- system services ----------------------------------------------------
    def features(self) -> set[str] | None:
        if "features" not in self._cache:
            text = self.sh("pm list features")
            self._cache["features"] = (
                {line.split(":", 1)[1].split("=")[0].strip() for line in text.splitlines() if ":" in line}
                if text is not None
                else None
            )
        return self._cache["features"]

    def packages(self, kind: str = "all") -> list[str] | None:
        flag = {"all": "", "system": " -s", "third_party": " -3"}[kind]
        key = ("packages", kind)
        if key not in self._cache:
            text = self.sh(f"pm list packages{flag}")
            self._cache[key] = parse_packages(text) if text is not None else None
        return self._cache[key]

    def processes(self) -> list[dict[str, str]] | None:
        if "ps" not in self._cache:
            text = self.sh("ps -A -o PID,USER,NAME")
            if not text or "PID" not in text:
                text = self.sh("ps")
            self._cache["ps"] = parse_ps(text) if text else None
        return self._cache["ps"]

    def dumpsys(self, service: str, timeout: float = 8.0) -> str | None:
        text = self.sh(f"dumpsys {service}", timeout)
        if text is None or text.strip() == "" or text.startswith("Can't find service"):
            return None
        return text

    def mounts(self) -> str | None:
        return self.read("/proc/mounts") or self.sh("mount")

    def listening_ports(self) -> list[tuple[str, int]] | None:
        if "listen" not in self._cache:
            rows: list[tuple[str, int]] = []
            seen_any = False
            for path in ("/proc/net/tcp", "/proc/net/tcp6"):
                text = self.read(path)
                if text:
                    seen_any = True
                    rows += parse_proc_net_tcp(text)
            if not seen_any:
                text = self.sh("netstat -tln")
                if text:
                    seen_any = True
                    for line in text.splitlines():
                        parts = line.split()
                        if len(parts) >= 4 and parts[0].startswith("tcp") and ":" in parts[3]:
                            addr, _, port = parts[3].rpartition(":")
                            if port.isdigit():
                                rows.append((addr, int(port)))
            self._cache["listen"] = rows if seen_any else None
        return self._cache["listen"]


# --------------------------------------------------------------------------- v1 helpers


def device_reachable(serial: str | None) -> bool:
    return AdbTransport(serial).reachable()


def shell(serial: str | None, command: str, timeout: float = 10.0) -> str | None:
    """Run `adb shell <command>`; return stdout (stripped) or None on any failure."""
    result = AdbTransport(serial).shell(command, timeout)
    if result is None or result.returncode != 0:
        return None
    return result.stdout.strip()


def getprop(serial: str | None, name: str) -> str | None:
    value = shell(serial, f"getprop {name}")
    if value is None:
        return None
    return value.strip() or None


def file_exists(serial: str | None, path: str) -> bool | None:
    """True/False if we could check, None if the device/adb was unreachable."""
    out = shell(serial, f"[ -e {shell_quote(path)} ] && echo YES || echo NO")
    if out is None:
        return None
    return out.strip() == "YES"
