"""Timing tells on iOS: uptime, time zone and sleep acceleration (the same
Darwin probes as macOS)."""

from __future__ import annotations

from perdedor_common.models import Platform, Severity
from perdedor_common.registry import RunContext
from perdedor_macos.checkkit import UNREACHABLE, Fail, Meta, Result, Skip, Verdict, build
from perdedor_macos.checks.timing import (
    DEFAULT_TIME_ZONES,
    probe_sleep_acceleration,
    probe_uptime,
    zone_from_localtime,
)

from ..device import IosTarget

P = Platform.IOS


def probe_time_zone(target: IosTarget, ctx: RunContext) -> Result:
    if target.is_simulator:
        # The Simulator follows the host's time zone.
        link = target.out("host_localtime", "readlink /etc/localtime")
        if link is None:
            return Fail("readlink /etc/localtime failed")
        zone = zone_from_localtime(link)
        return Verdict(zone in DEFAULT_TIME_ZONES, {"zone": zone, "source": "host"})
    info = target.stat(["/etc/localtime", "/private/var/db/timezone/localtime"])
    if info is None:
        return Fail(UNREACHABLE)
    link = next((i.target for i in info.values() if i.target), None)
    zone = zone_from_localtime(link)
    if zone is None:
        return Skip("time zone link unavailable")
    return Verdict(zone in DEFAULT_TIME_ZONES, {"zone": zone})


def _c(check_id, technique, name, description, severity, remediation, probe, **kw):
    return build(P, Meta(check_id, technique, name, description, severity, remediation), probe, **kw)


CHECKS = [
    _c(
        "ios.timing.uptime",
        "timing.uptime",
        "System uptime",
        "Booted less than 12 minutes before the scan (Pafish gensandbox_uptime threshold).",
        Severity.LOW,
        "Let the device run for a while before detonation.",
        probe_uptime,
    ),
    _c(
        "ios.timing.time_zone",
        "timing.time_plausibility",
        "Time zone",
        "Time zone is UTC/GMT or unset.",
        Severity.LOW,
        "Set the device time zone to the target region.",
        probe_time_zone,
    ),
    _c(
        "ios.timing.sleep_acceleration",
        "timing.sleep_acceleration",
        "Sleep acceleration",
        "The device clock advances faster or slower than the driver's clock across a sleep.",
        Severity.HIGH,
        "Keep the device clock consistent when accelerating time.",
        probe_sleep_acceleration,
        cost="slow",
    ),
]
