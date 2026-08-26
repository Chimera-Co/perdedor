"""Category 2 (Ch.3.2.2): timing-based detection, Android side.

Genuine RDTSC-class measurement isn't meaningful here: an ARM guest under
TCG full-system emulation has no forced-VM-exit CPUID analogue reachable
from adb shell, and CHIMERA's own Android track has not yet reached live
timing validation (CERT report Ch.7, "Remaining Work Plan"). This module
covers what *is* reachable today -- boot-to-probe uptime -- and is the
natural place to add a genuine timing probe once the on-device agent
(CERT report Ch.8 forward plan) exists.
"""

from __future__ import annotations

from perdedor_common import FindingFactory
from perdedor_common.models import Category, Finding, Platform, Severity

from .. import adb

_PLATFORM = Platform.ANDROID
_CATEGORY = Category.TIMING
_f = FindingFactory(category=_CATEGORY, platform=_PLATFORM)
_LOW_UPTIME_SECONDS = 600.0


def check_uptime(serial: str | None = None) -> Finding:
    check_id, name = "android.timing.low_uptime", "System uptime"
    description = "Low uptime suggests the emulator was booted specifically for this analysis run."
    raw = adb.shell(serial, "cat /proc/uptime")
    if raw is None:
        return _f.error(
            check_id,
            name,
            description,
            Severity.LOW,
            "adb command failed or no device reachable at the given serial",
        )
    try:
        uptime_seconds = float(raw.split()[0])
    except (ValueError, IndexError):
        return _f.error(check_id, name, description, Severity.LOW, f"unparseable /proc/uptime: {raw!r}")
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.LOW,
        is_detected=uptime_seconds < _LOW_UPTIME_SECONDS,
        evidence=f"{uptime_seconds:.0f}s",
        remediation=f"Boot the emulator and idle for >= {_LOW_UPTIME_SECONDS:.0f}s before detonating a sample.",
    )


def run_all(serial: str | None = None) -> list[Finding]:
    return [check_uptime(serial)]
