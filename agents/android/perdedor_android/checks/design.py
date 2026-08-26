"""Category 4 (Ch.3.2.4): design-choice / platform-specific detection,
Android side -- telephony/sensor absence and build-tag quirks specific to
emulator images rather than virtualisation in general."""

from __future__ import annotations

from perdedor_common import FindingFactory
from perdedor_common.models import Category, Finding, Platform, Severity

from .. import adb, signatures

_PLATFORM = Platform.ANDROID
_CATEGORY = Category.DESIGN_SPECIFIC
_f = FindingFactory(category=_CATEGORY, platform=_PLATFORM)
_ADB_UNREACHABLE = "adb command failed or no device reachable at the given serial"
_MIN_SENSOR_COUNT = 3


def check_build_characteristics(serial: str | None = None) -> Finding:
    check_id, name = "android.design.build_characteristics", "ro.build.characteristics"
    description = "Goldfish/ranchu images literally set ro.build.characteristics to 'emulator'."
    value = adb.getprop(serial, "ro.build.characteristics")
    if value is None:
        return _f.error(check_id, name, description, Severity.HIGH, _ADB_UNREACHABLE)
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.HIGH,
        is_detected="emulator" in value.lower(),
        evidence=f"ro.build.characteristics={value!r}",
        remediation="Set ro.build.characteristics to a realistic device profile (e.g. 'nosdcard,default').",
    )


def check_telephony_signals(serial: str | None = None) -> Finding:
    check_id, name = "android.design.telephony_signals", "Telephony baseband/RIL identity"
    description = "gsm.version.ril-impl and related props report the reference emulator RIL rather than a real modem's identity."
    value = adb.getprop(serial, "gsm.version.ril-impl")
    if value is None:
        return _f.error(check_id, name, description, Severity.HIGH, _ADB_UNREACHABLE)
    lowered = value.lower()
    detected = value == "" or "android reference-ril" in lowered or "unknown" in lowered
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.HIGH,
        is_detected=detected,
        evidence=f"gsm.version.ril-impl={value!r}",
        remediation="Provide a realistic RIL/baseband identity string; this is a well-known, high-prevalence Android malware check.",
    )


def check_sensor_list(serial: str | None = None) -> Finding:
    check_id, name = "android.design.sensor_list", "Hardware sensor count"
    description = "A device advertising very few sensors (no accelerometer/gyroscope/proximity) is a common emulator tell."
    output = adb.shell(serial, "dumpsys sensorservice")
    if output is None:
        return _f.error(check_id, name, description, Severity.MEDIUM, _ADB_UNREACHABLE)
    count = len([line for line in output.splitlines() if "handle=" in line.lower()])
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.MEDIUM,
        is_detected=count < _MIN_SENSOR_COUNT,
        evidence=f"{count} sensors reported",
        remediation="Configure the virtual sensor HAL to expose a realistic sensor set (accelerometer, gyroscope, proximity, light).",
    )


def check_camera_feature(serial: str | None = None) -> Finding:
    check_id, name = "android.design.camera_feature", "Camera hardware feature declaration"
    description = "`pm list features` -- emulators commonly report no camera, or only a fake/software camera, whereas real phones always declare android.hardware.camera."
    output = adb.shell(serial, "pm list features")
    if output is None:
        return _f.error(check_id, name, description, Severity.MEDIUM, _ADB_UNREACHABLE)
    has_camera = "android.hardware.camera" in output.lower()
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.MEDIUM,
        is_detected=not has_camera,
        evidence="android.hardware.camera* not declared" if not has_camera else "camera feature declared",
        remediation="Enable an emulated camera (webcam passthrough or a virtual camera HAL) on the golden image.",
    )


def check_build_tags(serial: str | None = None) -> Finding:
    check_id, name = "android.design.build_tags", "ro.build.tags test-keys"
    description = "'test-keys' in ro.build.tags is common on emulator/dev images; shipped consumer devices use 'release-keys'."
    value = adb.getprop(serial, "ro.build.tags")
    if value is None:
        return _f.error(check_id, name, description, Severity.LOW, _ADB_UNREACHABLE)
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.LOW,
        is_detected="test-keys" in value.lower(),
        evidence=f"ro.build.tags={value!r}",
        remediation="Sign the build with release keys (ro.build.tags=release-keys) if a real-device profile is required.",
    )


def check_avd_default_subnet(serial: str | None = None) -> Finding:
    check_id, name = "android.design.avd_default_subnet", "Default AVD NAT subnet (10.0.2.0/24)"
    description = f"The stock Android emulator's NAT network defaults to the {signatures.AVD_DEFAULT_SUBNET_PREFIX}0/24 subnet -- vanishingly rare on a real device's network."
    output = adb.shell(serial, "ip addr show") or adb.shell(serial, "ifconfig")
    if output is None:
        return _f.error(check_id, name, description, Severity.MEDIUM, _ADB_UNREACHABLE)
    detected = signatures.AVD_DEFAULT_SUBNET_PREFIX in output
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.MEDIUM,
        is_detected=detected,
        evidence=(
            f"'{signatures.AVD_DEFAULT_SUBNET_PREFIX}' found in interface config"
            if detected
            else "default AVD subnet not present"
        ),
        remediation="Configure a custom network range for the emulator rather than the stock AVD NAT default.",
    )


def check_suspicious_hostname(serial: str | None = None) -> Finding:
    check_id, name = "android.design.suspicious_device_name", "Device name plausibility"
    description = (
        "net.hostname/ro.product.device values like 'sandbox' or 'malware' are an easy, high-confidence tell."
    )
    value = adb.getprop(serial, "net.hostname") or adb.getprop(serial, "ro.product.device")
    if value is None:
        return _f.error(check_id, name, description, Severity.LOW, _ADB_UNREACHABLE)
    hit = next((token for token in signatures.SUSPICIOUS_NAME_TOKENS if token in value.lower()), None)
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.LOW,
        is_detected=bool(hit),
        evidence=f"{value!r}" + (f" (matched {hit!r})" if hit else ""),
        remediation="Rename the golden image's device/host identity to a plausible everyday name.",
    )


def run_all(serial: str | None = None) -> list[Finding]:
    return [
        check_build_characteristics(serial),
        check_telephony_signals(serial),
        check_sensor_list(serial),
        check_camera_feature(serial),
        check_build_tags(serial),
        check_avd_default_subnet(serial),
        check_suspicious_hostname(serial),
    ]
