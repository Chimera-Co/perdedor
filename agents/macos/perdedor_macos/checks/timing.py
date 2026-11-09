"""Timing tells on macOS: uptime, time zone and bounded sleep observations."""

from __future__ import annotations

import math
import time

from perdedor_common.models import Platform, Severity
from perdedor_common.registry import RunContext

from .. import parsing
from .. import signatures as sig
from ..checkkit import UNREACHABLE, Fail, Meta, Result, Skip, Verdict, build, sysctl_value
from ..target import Target

P = Platform.MACOS
# Time zones a default image or a UTC-configured host leaves behind.
DEFAULT_TIME_ZONES = ("UTC", "GMT", "Etc/UTC", "Etc/GMT", "Universal", "Zulu")
# Sleep window used by the acceleration probe (seconds), overridable with
# timing.sleep_seconds. Long enough that ssh round-trip jitter (tens of ms) is
# small against it.
SLEEP_SECONDS = 3.0
# Local bounded runtime policy (DESIGN-V2 slow budget).
MAX_SLEEP_SECONDS = 30.0


def _now(target: Target) -> float | None:
    text = target.out("date_epoch", "date +%s", timeout=10.0)
    return float(text.strip()) if text and text.strip().isdigit() else None


def probe_uptime(target: Target, ctx: RunContext) -> Result:
    value, fail = sysctl_value(target, "kern.boottime")
    if fail:
        return fail
    boot = parsing.parse_boottime(value)
    now = _now(target)
    if boot is None or now is None:
        return Fail(f"kern.boottime / date unavailable: {value!r}")
    uptime = now - boot
    if uptime < 0:
        return Fail("boot time is in the future")
    minimum = ctx.param("uptime.min_seconds", sig.MIN_UPTIME_SECONDS)
    return Verdict(
        uptime < minimum, {"uptime_seconds": int(uptime)}, measurement={"value": uptime, "threshold": minimum}
    )


def zone_from_localtime(link: str | None) -> str | None:
    """/etc/localtime -> /var/db/timezone/zoneinfo/Europe/Berlin -> Europe/Berlin."""
    if not link:
        return None
    marker = "zoneinfo/"
    return link.split(marker, 1)[1].strip() if marker in link else link.strip()


def probe_time_zone(target: Target, ctx: RunContext) -> Result:
    info = target.stat(["/etc/localtime"])
    if info is None:
        return Fail(UNREACHABLE)
    entry = info.get("/etc/localtime")
    if entry is None:
        return Verdict(True, {"zone": None, "note": "/etc/localtime missing: system default UTC"})
    zone = zone_from_localtime(entry.target)
    if zone is None:
        return Skip("time zone file is not a readable zoneinfo link")
    return Verdict(zone in DEFAULT_TIME_ZONES, {"zone": zone})


def probe_sleep_acceleration(target: Target, ctx: RunContext) -> Result:
    seconds = ctx.param("timing.sleep_seconds", SLEEP_SECONDS)
    if not math.isfinite(seconds) or not 1 <= seconds <= MAX_SLEEP_SECONDS:
        return Fail("timing.sleep_seconds must be between 1 and 30")
    command = f"date +%s; sleep {seconds:g}; date +%s"
    started = time.monotonic()
    result = target.run("sleep_window", command, timeout=seconds + 30.0, cache=False)
    host_elapsed = time.monotonic() - started
    if result is None or not result.ok:
        return Fail(UNREACHABLE + " (sleep window)")
    stamps = [int(x) for x in result.stdout.split() if x.isdigit()]
    if len(stamps) != 2:
        return Fail(f"unexpected output: {result.stdout[:100]!r}")
    target_elapsed = stamps[1] - stamps[0]
    # date has 1 s resolution: allow one second either way on top of the ratio.
    fast = target_elapsed > seconds * (1 + sig.SLEEP_SKEW_RATIO) + 1
    slow = target_elapsed < seconds * (1 - sig.SLEEP_SKEW_RATIO) - 1
    # The host must also have waited at least the sleep (a skipped sleep returns early).
    skipped = host_elapsed < seconds * (1 - sig.SLEEP_SKEW_RATIO)
    return Verdict(
        fast or slow or skipped,
        {
            "requested": seconds,
            "target_clock_elapsed": target_elapsed,
            "driver_elapsed": round(host_elapsed, 2),
        },
        measurement={"target": target_elapsed, "driver": host_elapsed, "requested": seconds},
    )


def _c(check_id, technique, name, description, severity, remediation, probe, **kw):
    return build(P, Meta(check_id, technique, name, description, severity, remediation), probe, **kw)


CHECKS = [
    _c(
        "macos.timing.uptime",
        "timing.uptime",
        "System uptime",
        "Booted less than 12 minutes before the scan (Pafish gensandbox_uptime threshold).",
        Severity.LOW,
        "Boot the VM and let it idle before detonation, or restore a snapshot taken hours after boot.",
        probe_uptime,
    ),
    _c(
        "macos.timing.time_zone",
        "timing.time_plausibility",
        "Time zone",
        "Time zone is UTC/GMT, the default of freshly built images.",
        Severity.LOW,
        "Set the image's time zone to the region the target population lives in.",
        probe_time_zone,
    ),
    _c(
        "macos.timing.sleep_acceleration",
        "timing.sleep_acceleration",
        "Sleep acceleration",
        "The target's clock advances faster or slower than the driver's clock across a sleep.",
        Severity.HIGH,
        "Keep guest wall-clock and monotonic time consistent when skipping sleeps.",
        probe_sleep_acceleration,
        cost="slow",
    ),
]
