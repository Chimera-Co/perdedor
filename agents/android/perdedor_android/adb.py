"""Thin wrapper around the `adb` CLI.

The Android agent runs on the analyst host and drives the target device (a
real ARM phone, or CHIMERA's own qemu-system-aarch64 guest) over adb, rather
than shipping an on-device APK -- see docs/ARCHITECTURE.md for why this is
the pragmatic v1 architecture and what the on-device path would look like.

Every function fails soft (returns None) so a single unreachable device
degrades every dependent check to `error`/`skipped` instead of crashing the
whole scan -- consistent with the Linux/Windows agents.
"""

from __future__ import annotations

import shutil
import subprocess


def adb_binary_available() -> bool:
    return shutil.which("adb") is not None


def device_reachable(serial: str | None) -> bool:
    if not adb_binary_available():
        return False
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += ["get-state"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and result.stdout.strip() == "device"


def shell(serial: str | None, command: str, timeout: float = 10.0) -> str | None:
    """Run `adb shell <command>`; return stdout (stripped) or None on any failure."""
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += ["shell", command]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def getprop(serial: str | None, name: str) -> str | None:
    value = shell(serial, f"getprop {name}")
    if value is None:
        return None
    return value.strip() or None


def file_exists(serial: str | None, path: str) -> bool | None:
    """True/False if we could check, None if the device/adb was unreachable."""
    out = shell(serial, f"[ -e {path} ] && echo YES || echo NO")
    if out is None:
        return None
    return out.strip() == "YES"
