"""A probed machine: a transport plus a per-scan cache, so commands that many
checks share (``sysctl``, ``ps``, ``ioreg``, ``system_profiler``) run once.

Check functions receive ``ctx.target`` (a :class:`Target`). They call the
methods below, never ``subprocess`` directly, so every check runs unchanged
against a real Mac, an ssh target, the iOS Simulator and the test fakes.
"""

from __future__ import annotations

import plistlib
import re
import shlex
import time
from collections.abc import Sequence
from typing import Any
from urllib.parse import quote

from . import parsing
from .transport import CommandResult, Listing, PathInfo, Transport

# sysctl names read in one call. Unknown names are skipped by sysctl itself
# (Intel-only machdep.cpu.features on Apple Silicon, macOS-only names on iOS).
SYSCTL_NAMES = (
    "hw.model",
    "hw.machine",
    "hw.memsize",
    "hw.ncpu",
    "hw.physicalcpu",
    "hw.logicalcpu",
    "hw.nperflevels",
    "hw.l2cachesize",
    "hw.l3cachesize",
    "hw.cachelinesize",
    "hw.optional.arm64",
    "hw.targettype",
    "machdep.cpu.brand_string",
    "machdep.cpu.features",
    "machdep.cpu.vendor",
    "kern.hv_vmm_present",
    "kern.hv_support",
    "kern.boottime",
    "kern.bootargs",
    "kern.osproductversion",
    "kern.osversion",
    "kern.ostype",
    "kern.osrelease",
    "kern.version",
    "kern.hostname",
    "sysctl.proc_translated",
    "security.mac.amfi.developer_mode_status",
)


class Target:
    def __init__(self, transport: Transport, *, platform: str = "macos") -> None:
        self.transport = transport
        self.platform = platform
        self.deadline = None
        self._cache: dict[str, Any] = {}

    # -- commands ----------------------------------------------------------------

    def run(
        self, key: str, command: str, *, timeout: float = 8.0, cache: bool = True
    ) -> CommandResult | None:
        cache_key = f"run:{key}:{command}"
        if cache and cache_key in self._cache:
            return self._cache[cache_key]
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
            if timeout <= 0:
                return None
        result = self.transport.run(command, key=key, timeout=timeout)
        if cache:
            self._cache[cache_key] = result
        return result

    def out(self, key: str, command: str, *, timeout: float = 8.0) -> str | None:
        """stdout of a command that succeeded; None if it failed or the target
        is unreachable (use :meth:`run` to tell the two apart)."""
        result = self.run(key, command, timeout=timeout)
        if result is None or not result.ok:
            return None
        if re.search(r"(?i)permission denied|operation not permitted", result.stdout + result.stderr):
            return None
        return result.stdout

    def reachable(self) -> bool:
        result = self.run("echo", "echo perdedor-ok")
        if result is None or not result.ok or "perdedor-ok" not in result.stdout:
            return False
        if self.transport.name == "local":
            return self.out("uname_s", "uname -s") == "Darwin\n"
        return True

    # -- shared probes -------------------------------------------------------------

    def sysctl(self) -> dict[str, str] | None:
        if "sysctl" not in self._cache:
            result = self.run("sysctl", "sysctl " + " ".join(SYSCTL_NAMES) + " 2>/dev/null")
            self._cache["sysctl"] = (
                None
                if result is None or not result.stdout.strip()
                else (parsing.parse_sysctl(result.stdout) or None)
            )
        return self._cache["sysctl"]

    def processes(self) -> list[parsing.Process] | None:
        if "ps" not in self._cache:
            result = self.run("ps", "ps -axww -o pid=,ppid=,flags=,comm=")
            self._cache["ps"] = (
                None if result is None or not result.ok else (parsing.parse_ps(result.stdout) or None)
            )
        return self._cache["ps"]

    def launchd_labels(self) -> list[str] | None:
        if "launchctl" not in self._cache:
            result = self.run("launchctl_list", self.launchctl_command())
            self._cache["launchctl"] = (
                None if result is None or not result.ok else parsing.parse_launchctl_list(result.stdout)
            )
        return self._cache["launchctl"]

    def launchctl_command(self) -> str:
        return "launchctl list"

    def profiler(self, data_type: str, *, timeout: float = 60.0) -> Any:
        """``system_profiler -json -detailLevel mini <type>`` parsed, or None."""
        key = f"profiler:{data_type}"
        if key not in self._cache:
            text = self.out(
                f"system_profiler_{data_type}",
                f"system_profiler -json -detailLevel mini -timeout 8 {shlex.quote(data_type)} 2>/dev/null",
                timeout=timeout,
            )
            doc = parsing.load_json(text)
            self._cache[key] = doc if isinstance(doc, dict) and isinstance(doc.get(data_type), list) else None
        return self._cache[key]

    def ioreg(self, key: str, args: str) -> str | None:
        return self.out(f"ioreg_{key}", f"ioreg {args}", timeout=30.0)

    def env_value(self, name: str) -> str | None:
        """Value of a launchd (session) environment variable, or None."""
        text = self.out(f"getenv_{name}", f"launchctl getenv {shlex.quote(name)}")
        if text is None:
            return None
        return text.strip()

    # -- filesystem ------------------------------------------------------------------

    def exists(self, paths: Sequence[str]) -> set[str] | None:
        return self.transport.exists(list(paths))

    def stat(self, paths: Sequence[str]) -> dict[str, PathInfo] | None:
        return self.transport.stat(list(paths))

    def listdir(self, path: str) -> Listing | None:
        key = f"ls:{path}"
        if key not in self._cache:
            self._cache[key] = self.transport.listdir(path)
        return self._cache[key]

    def read_text(self, path: str, max_bytes: int = 262144) -> str | None:
        return self.transport.read_text(path, max_bytes)

    def home(self) -> str | None:
        if "home" not in self._cache:
            text = self.out("home", 'printf "%s" "$HOME"')
            self._cache["home"] = text.strip() if text else None
        return self._cache["home"]

    def describe(self) -> dict[str, str]:
        return self.transport.describe()

    def read_plist(self, path):
        mapped = self.transport.device_path(path)
        text = self.out("plist:" + path, "plutil -convert xml1 -o - " + shlex.quote(mapped))
        if text is None:
            return None
        try:
            return plistlib.loads(text.encode())
        except (ValueError, plistlib.InvalidFileException):
            return None

    def sqlite_count(self, path, table):
        # Fixed table names chosen by each check; no arbitrary SQL parameter.
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", table):
            return None
        mapped = self.transport.device_path(path)
        # Immutable mode forbids journal/SHM creation. Counts reflect the database
        # file snapshot and may omit recent WAL-only transactions.
        # https://www.sqlite.org/uri.html#uriimmutable
        query = f'SELECT count(*) FROM "{table}";'
        text = self.out(
            "count:" + path + ":" + table,
            "sqlite3 -readonly "
            + shlex.quote("file:" + quote(mapped, safe="/") + "?mode=ro&immutable=1")
            + " "
            + shlex.quote(query),
        )
        return int(text.strip()) if text and text.strip().isdigit() else None
