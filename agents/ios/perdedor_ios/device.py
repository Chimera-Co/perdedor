"""iOS targets: a jailbroken device or a Corellium virtual device over ssh, or
an iOS Simulator on the local Mac.

The Simulator is not a separate machine: its processes are macOS processes on
the host kernel, and its filesystem is two directory trees on the host (the
runtime root for the read-only system, the device data directory for
``/var/mobile`` and ``/private/var``). :class:`SimulatorTransport` therefore runs
kernel-level probes (``sysctl``, ``ps``) on the host -- which is exactly what an
app inside the Simulator sees -- maps device paths onto the two trees, and uses
``xcrun simctl spawn`` / ``xcrun simctl getenv`` for what lives inside the
simulated launchd.
"""

from __future__ import annotations

import os
import posixpath
import re
import shlex
from dataclasses import dataclass, field

from perdedor_macos import parsing
from perdedor_macos.target import Target
from perdedor_macos.transport import CommandResult, LocalTransport, SshTransport, Transport

# Rootless bootstraps (Dopamine, palera1n rootless) keep their binaries in
# /var/jb; Procursus rootful installs use the standard paths.
JB_PATH = (
    "PATH=$PATH:/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:/usr/sbin:/sbin; export PATH; "
)


def ios_ssh(
    destination: str,
    identity: str | None = None,
    port: int | None = None,
    extra_options: tuple[str, ...] = (),
) -> SshTransport:
    """ssh transport for jailbroken devices / Corellium (default port 22,
    or 2222 for iproxy-forwarded USB devices)."""
    return SshTransport(
        destination, identity=identity, port=port, extra_options=extra_options, path_prefix=JB_PATH
    )


@dataclass
class SimulatorTransport(LocalTransport):
    udid: str
    data_path: str | None = None
    runtime_root: str | None = None
    device: dict = field(default_factory=dict)
    name = "simctl"

    def __post_init__(self):
        if self.udid != "booted" and not re.fullmatch(
            r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", self.udid
        ):
            raise ValueError("simulator must be a UDID or 'booted'")

    def resolve(self) -> bool:
        if getattr(self, "_resolved", False):
            return bool(self.data_path and self.runtime_root)
        self._resolved = True
        devices = parsing.load_json(self._out("xcrun simctl list devices --json"))
        runtimes = parsing.load_json(self._out("xcrun simctl list runtimes --json"))
        if not isinstance(devices, dict) or not isinstance(runtimes, dict):
            return False
        matches = []
        for runtime_id, entries in devices.get("devices", {}).items():
            for entry in entries:
                if (
                    entry.get("state") == "Booted"
                    and entry.get("isAvailable", True)
                    and (self.udid == "booted" or entry.get("udid") == self.udid)
                ):
                    matches.append({**entry, "runtime": runtime_id})
        if len(matches) != 1:
            return False
        self.device = matches[0]
        self.udid = self.device["udid"]
        if not re.fullmatch(r"[0-9A-Fa-f-]{36}", self.udid):
            return False
        data = self.device.get("dataPath")
        runtime = next(
            (r for r in runtimes.get("runtimes", []) if r.get("identifier") == self.device["runtime"]), {}
        )
        root = runtime.get("runtimeRoot")
        if not root and runtime.get("bundlePath"):
            root = runtime["bundlePath"] + "/Contents/Resources/RuntimeRoot"
        if not all(
            isinstance(p, str) and p.startswith("/") and posixpath.normpath(p) != "/" for p in (data, root)
        ):
            return False
        self.data_path, self.runtime_root = posixpath.normpath(data), posixpath.normpath(root)
        self.device["runtime_version"] = runtime.get("version", "")
        return True

    def _out(self, command: str) -> str | None:
        result = LocalTransport._exec(self, command, 8.0)
        return result.stdout if result is not None and result.ok else None

    def _mapped_path(self, path: str) -> str:
        if not self.resolve():
            raise ValueError("simulator roots unavailable; host paths are never substituted")
        if not path.startswith("/") or ".." in path.split("/"):
            raise ValueError("device path must be absolute without parent traversal")
        # CoreSimulator data contains Library, Media, Containers and Documents
        # directly. /var/containers is Data/Containers, not host /private/var.
        for prefix in ("/private/var/mobile", "/var/mobile"):
            if path == prefix or path.startswith(prefix + "/"):
                return self.data_path + path[len(prefix) :]
        for prefix in ("/private/var/containers", "/var/containers"):
            if path == prefix or path.startswith(prefix + "/"):
                return self.data_path + "/Containers" + path[len(prefix) :]
        for prefix in ("/private/var", "/var"):
            if path == prefix or path.startswith(prefix + "/"):
                return self.data_path + "/private/var" + path[len(prefix) :]
        return self.runtime_root + path

    def device_path(self, path: str) -> str:
        candidate = self._mapped_path(path)
        resolved = os.path.realpath(candidate)
        roots = [os.path.realpath(self.data_path), os.path.realpath(self.runtime_root)]
        if not any(os.path.commonpath([resolved, root]) == root for root in roots):
            raise ValueError("simulator symlink leaves the device roots")
        return candidate

    def run(self, command, *, key="", timeout=8.0):
        if not self.resolve():
            return None
        if key == "echo":
            return CommandResult(0, "perdedor-ok\n")
        if key in ("exists", "stat", "listdir", "read") or key.startswith(("plist:", "count:")):
            # These commands already contain paths scoped by device_path().
            return super().run(command, key=key, timeout=timeout)
        if command.startswith("xcrun simctl "):
            return super().run(command, key=key, timeout=timeout)
        # Simulator runtimes do not necessarily contain a shell. Spawn simple
        # commands directly and report unsupported compound probes as unknown.
        if any(token in command for token in (";", "|", "&&", "$", "`")):
            return CommandResult(127, "", "compound command unavailable in simulator")
        words = shlex.split(command.replace(" 2>/dev/null", ""))
        if not words:
            return CommandResult(127, "")
        return super().run(self.spawn(shlex.join(words)), key=key, timeout=timeout)

    def spawn(self, command: str) -> str:
        return f"xcrun simctl spawn {shlex.quote(self.udid)} {command}"

    def describe(self) -> dict[str, str]:
        self.resolve()
        doc = {"transport": "simctl", "udid": self.udid}
        for key in ("name", "deviceTypeIdentifier", "runtime", "runtime_version", "state"):
            if self.device.get(key):
                doc[key] = str(self.device[key])
        return doc


class IosTarget(Target):
    def __init__(self, transport: Transport) -> None:
        super().__init__(transport, platform="ios")

    @property
    def mode(self) -> str:
        """``simulator``, ``ssh`` or ``local``."""
        if isinstance(self.transport, SimulatorTransport):
            return "simulator"
        return getattr(self.transport, "mode", self.transport.name)

    @property
    def is_simulator(self) -> bool:
        return self.mode == "simulator"

    def device_record(self) -> dict:
        """simctl device record (name, deviceTypeIdentifier, runtime...);
        empty for ssh targets."""
        if isinstance(self.transport, SimulatorTransport):
            self.transport.resolve()
            return dict(self.transport.device)
        return dict(getattr(self.transport, "device", {}) or {})

    def _udid(self) -> str:
        return str(self.device_record().get("udid") or getattr(self.transport, "udid", "booted"))

    def launchctl_command(self) -> str:
        if self.is_simulator:
            return f"xcrun simctl spawn {shlex.quote(self._udid())} launchctl list"
        return "launchctl list"

    def env_value(self, name: str) -> str | None:
        if not self.is_simulator:
            return super().env_value(name)
        command = f"xcrun simctl getenv {shlex.quote(self._udid())} {shlex.quote(name)}"
        text = self.out(f"simctl_getenv_{name}", command)
        return text.strip() if text and text.strip() else None

    def mount_table(self) -> str | None:
        return self.out("mount", "mount")
