"""Category 3 (Ch.3.2.3): behavioural / interaction-based detection, Android
side -- the same "wear and tear" absence signal as the desktop platforms,
adapted to installed-app count and battery-state plausibility."""

from __future__ import annotations

import re

from perdedor_common import FindingFactory
from perdedor_common.models import Category, Finding, Platform, Severity

from .. import adb, signatures

_PLATFORM = Platform.ANDROID
_CATEGORY = Category.BEHAVIOURAL_INTERACTION
_f = FindingFactory(category=_CATEGORY, platform=_PLATFORM)
_ADB_UNREACHABLE = "adb command failed or no device reachable at the given serial"
_MIN_THIRD_PARTY_PACKAGES = 3


def check_installed_packages(serial: str | None = None) -> Finding:
    check_id, name = "android.behavioural.installed_packages", "Third-party installed package count"
    description = (
        "A device with zero third-party apps installed looks freshly provisioned rather than genuinely used."
    )
    output = adb.shell(serial, "pm list packages -3")
    if output is None:
        return _f.error(check_id, name, description, Severity.LOW, _ADB_UNREACHABLE)
    count = len([line for line in output.splitlines() if line.strip().startswith("package:")])
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.LOW,
        is_detected=count < _MIN_THIRD_PARTY_PACKAGES,
        evidence=f"{count} third-party packages",
        remediation="Install a realistic mix of everyday apps on the golden image before freezing it.",
    )


def check_battery_plausibility(serial: str | None = None) -> Finding:
    check_id, name = "android.behavioural.battery_plausibility", "Battery state plausibility"
    description = "Emulators commonly report a fixed, implausible battery state (e.g. permanently AC-powered at exactly 50%)."
    output = adb.shell(serial, "dumpsys battery")
    if output is None:
        return _f.error(check_id, name, description, Severity.LOW, _ADB_UNREACHABLE)
    ac_powered = re.search(r"AC powered:\s*(true|false)", output, re.IGNORECASE)
    level = re.search(r"level:\s*(\d+)", output, re.IGNORECASE)
    if not ac_powered or not level:
        return _f.error(
            check_id,
            name,
            description,
            Severity.LOW,
            f"could not parse `dumpsys battery` output: {output[:200]!r}",
        )
    evidence = f"AC powered={ac_powered.group(1)} level={level.group(1)}"
    # 50% + permanently AC-powered is the AVD/goldfish default and a
    # well-known emulator tell -- a real device's battery level varies.
    detected = ac_powered.group(1).lower() == "true" and level.group(1) == "50"
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.LOW,
        is_detected=detected,
        evidence=evidence,
        remediation="Simulate dynamic battery drain/charge-state transitions on the golden image (CHIMERA Ch.7.4, 'Living Device Simulation').",
    )


def check_battery_temperature(serial: str | None = None) -> Finding:
    check_id, name = "android.behavioural.battery_temperature", "Battery temperature plausibility"
    description = f"goldfish's default battery simulation reports a fixed temperature (typically {signatures.GOLDFISH_DEFAULT_TEMPERATURE_TENTHS / 10:.1f}C); a real device's battery temperature drifts with use."
    output = adb.shell(serial, "dumpsys battery")
    if output is None:
        return _f.error(check_id, name, description, Severity.INFO, _ADB_UNREACHABLE)
    match = re.search(r"temperature:\s*(-?\d+)", output, re.IGNORECASE)
    if not match:
        return _f.error(
            check_id,
            name,
            description,
            Severity.INFO,
            f"could not parse `dumpsys battery` output: {output[:200]!r}",
        )
    temperature = int(match.group(1))
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.INFO,
        is_detected=temperature == signatures.GOLDFISH_DEFAULT_TEMPERATURE_TENTHS or temperature == 0,
        evidence=f"temperature={temperature / 10:.1f}C",
        remediation="Simulate realistic, drifting battery temperature on the golden image.",
    )


def run_all(serial: str | None = None) -> list[Finding]:
    return [
        check_installed_packages(serial),
        check_battery_plausibility(serial),
        check_battery_temperature(serial),
    ]
