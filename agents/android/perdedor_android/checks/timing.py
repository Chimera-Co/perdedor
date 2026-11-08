"""Read-only guest uptime, measured on the device rather than across adb."""

import math

from perdedor_common.models import Severity
from perdedor_common.registry import RunContext

from ..adb import Device
from ._base import Checks, ProbeError, Verdict, need

REG = Checks()
# Local conservative policy, retained from v1; not a universal device boundary.
# https://evasions.checkpoint.com/src/Evasions/techniques/timing.html
LOW_UPTIME_SECONDS = 600.0


@REG.check(
    "android.timing.low_uptime",
    "timing.uptime",
    name="System uptime",
    description="A recently booted device can be a freshly restored analysis image.",
    severity=Severity.LOW,
    remediation="Let the guest boot and accumulate normal uptime before a run.",
)
def check_uptime(dev: Device, ctx: RunContext) -> Verdict:
    text = need(dev.read("/proc/uptime"), "uptime")
    try:
        seconds = float(text.split()[0])
    except (ValueError, IndexError) as exc:
        raise ProbeError("unrecognized uptime") from exc
    if not math.isfinite(seconds) or seconds < 0:
        raise ProbeError("invalid uptime")
    threshold = ctx.param("android.min_uptime_seconds", LOW_UPTIME_SECONDS)
    return Verdict(
        seconds < threshold,
        {"seconds": seconds},
        confidence=0.4,
        measurement={"seconds": seconds, "min_seconds": threshold},
    )


CHECKS = REG.specs
