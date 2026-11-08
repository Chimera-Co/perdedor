"""v1 behavioural checks (ids frozen): third-party app count and the goldfish
battery defaults."""

from __future__ import annotations

from perdedor_common.models import Severity
from perdedor_common.registry import RunContext

from .. import signatures as sig
from ..adb import Device
from ._base import Checks, ProbeError, Verdict, need, packages, to_int
from ._parsers import parse_battery

REG = Checks()

# Numeric scarcity thresholds below are conservative local policies, not device guarantees.
# Rationale and overrides: docs/notes/android.md; observable APIs:
# https://source.android.com/docs/compatibility/cdd
# https://developer.android.com/reference/android/provider/Settings.Global


# v1 threshold: a device in use carries dozens of user-installed apps;
# fewer than 3 is a freshly provisioned image. Kept low on purpose so that
# minimal-but-real work phones stay clean (tunable with --param).
MIN_THIRD_PARTY_PACKAGES = 3


@REG.check(
    "android.behavioural.installed_packages",
    "wear_and_tear.installed_software",
    name="Third-party installed package count",
    description="Fewer than three user-installed apps (`pm list packages -3`) looks freshly provisioned.",
    severity=Severity.LOW,
    remediation="Install a realistic mix of everyday apps on the golden image before freezing it.",
)
def check_installed_packages(dev: Device, ctx: RunContext) -> Verdict:
    count = len(packages(dev, "third_party"))
    minimum = ctx.param("android.min_third_party_packages", MIN_THIRD_PARTY_PACKAGES)
    return Verdict(
        count < minimum, f"{count} third-party packages", measurement={"third_party": count, "min": minimum}
    )


def _battery(dev: Device) -> dict[str, str]:
    bat = parse_battery(need(dev.dumpsys("battery"), "dumpsys battery"))
    if "level" not in bat:
        raise ProbeError("could not parse `dumpsys battery`")
    return bat


@REG.check(
    "android.behavioural.battery_plausibility",
    "mobile_device.battery",
    name="Battery state plausibility",
    description="The goldfish battery HAL reports a permanently AC-powered battery at exactly 50 %.",
    severity=Severity.LOW,
    remediation="Simulate battery drain and charge-state changes (`dumpsys battery set level/ac/usb` from "
    "the host, or a battery HAL fed with a recorded profile).",
)
def check_battery_plausibility(dev: Device, ctx: RunContext) -> Verdict:
    bat = _battery(dev)
    ac = bat.get("ac powered", "").lower()
    level = to_int(bat.get("level"))
    return Verdict(ac == "true" and level == sig.GOLDFISH_DEFAULT_LEVEL, f"AC powered={ac} level={level}")


@REG.check(
    "android.behavioural.battery_temperature",
    "mobile_device.battery",
    name="Battery temperature plausibility",
    description=f"The goldfish battery HAL reports a fixed "
    f"{sig.GOLDFISH_DEFAULT_TEMPERATURE_TENTHS / 10:.1f} C (or 0); a real battery drifts with use.",
    severity=Severity.INFO,
    remediation="Simulate a realistic, drifting battery temperature.",
)
def check_battery_temperature(dev: Device, ctx: RunContext) -> Verdict:
    temperature = to_int(_battery(dev).get("temperature"))
    if temperature is None:
        raise ProbeError("no temperature in dumpsys battery")
    return Verdict(
        temperature in (sig.GOLDFISH_DEFAULT_TEMPERATURE_TENTHS, 0), f"temperature={temperature / 10:.1f}C"
    )


CHECKS = REG.specs
