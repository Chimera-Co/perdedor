"""v1 design-specific checks (ids frozen): build characteristics and tags,
RIL identity, sensor count, camera feature, AVD subnet and device name."""

from __future__ import annotations

from perdedor_common.models import Severity
from perdedor_common.registry import RunContext

from .. import signatures as sig
from ..adb import Device
from ._base import Checks, Verdict, features, need, props
from ._parsers import parse_sensors

REG = Checks()

# Android CDD section 7.3 (https://source.android.com/docs/compatibility/cdd):
# handheld devices SHOULD include a 3-axis accelerometer, and telephony
# devices a proximity sensor; phones in practice ship 10+ sensors including
# virtual fusion sensors. The v1 threshold of 3 keeps tablets and old phones
# clean while catching the 0-2 sensors of Android-x86 and bare VMs.
MIN_SENSOR_COUNT = 3


@REG.check(
    "android.design.build_characteristics",
    "emulator.android_build_identity",
    name="ro.build.characteristics",
    description="goldfish/ranchu images set ro.build.characteristics to 'emulator'.",
    severity=Severity.HIGH,
    remediation="Set ro.build.characteristics to a device profile value (e.g. 'nosdcard').",
)
def check_build_characteristics(dev: Device, ctx: RunContext) -> Verdict:
    value = props(dev).get("ro.build.characteristics", "")
    return Verdict("emulator" in value.lower(), f"ro.build.characteristics={value!r}")


@REG.check(
    "android.design.telephony_signals",
    "mobile_device.telephony",
    name="Telephony baseband/RIL identity",
    description="gsm.version.ril-impl is 'android reference-ril' (the emulator's reference RIL) or empty "
    "where a phone names its vendor RIL.",
    severity=Severity.HIGH,
    remediation="Provide a vendor RIL identity (and a modem simulator that answers like one).",
)
def check_telephony_signals(dev: Device, ctx: RunContext) -> Verdict:
    value = props(dev).get("gsm.version.ril-impl", "")
    low = value.lower()
    return Verdict(
        value.strip() == "" or "android reference-ril" in low or "unknown" in low,
        f"gsm.version.ril-impl={value!r}",
    )


@REG.check(
    "android.design.sensor_list",
    "mobile_device.sensors",
    name="Hardware sensor count",
    description="Fewer than three sensors (no accelerometer/gyroscope/proximity) is a common emulator tell.",
    severity=Severity.MEDIUM,
    remediation="Expose a realistic virtual sensor set (accelerometer, gyroscope, magnetometer, proximity, "
    "light, step counter) through a sensor HAL.",
)
def check_sensor_list(dev: Device, ctx: RunContext) -> Verdict:
    sensors = parse_sensors(need(dev.dumpsys("sensorservice"), "dumpsys sensorservice"))
    minimum = ctx.param("android.min_sensors", MIN_SENSOR_COUNT)
    return Verdict(
        len(sensors) < minimum,
        f"{len(sensors)} sensors reported",
        measurement={"sensors": len(sensors), "min": minimum},
    )


@REG.check(
    "android.design.camera_feature",
    "mobile_device.camera",
    name="Camera hardware feature declaration",
    description="`pm list features`: phones always declare android.hardware.camera*; many emulators and "
    "Android-x86 declare none.",
    severity=Severity.MEDIUM,
    remediation="Provide a virtual camera HAL (or a passthrough webcam) so the camera features are declared.",
)
def check_camera_feature(dev: Device, ctx: RunContext) -> Verdict:
    cams = sorted(f for f in features(dev) if f.startswith("android.hardware.camera"))
    return Verdict(not cams, cams or "android.hardware.camera* not declared")


@REG.check(
    "android.design.build_tags",
    "emulator.android_build_identity",
    name="ro.build.tags test-keys",
    description="'test-keys' in ro.build.tags (rootbeer detectTestKeys, CalebFenton) marks builds signed with "
    "the public AOSP test keys; shipped devices use release-keys.",
    severity=Severity.LOW,
    remediation="Sign the build with private release keys (ro.build.tags=release-keys).",
)
def check_build_tags(dev: Device, ctx: RunContext) -> Verdict:
    value = props(dev).get("ro.build.tags", "")
    return Verdict("test-keys" in value.lower(), f"ro.build.tags={value!r}")


@REG.check(
    "android.design.avd_default_subnet",
    "network.default_subnets",
    name="Default AVD NAT subnet (10.0.2.0/24)",
    description="The stock emulator puts the device at 10.0.2.15 behind 10.0.2.2/10.0.2.3 (framgia checkIp; "
    "developer.android.com emulator networking).",
    severity=Severity.MEDIUM,
    remediation="Use a custom network range for the analysis network instead of the emulator's user-mode NAT.",
)
def check_avd_default_subnet(dev: Device, ctx: RunContext) -> Verdict:
    text = need(dev.sh("ip addr show") or dev.sh("ifconfig"), "interface addresses (ip addr / ifconfig)")
    detected = (
        f"inet {sig.AVD_DEFAULT_SUBNET_PREFIX}" in text or f"addr:{sig.AVD_DEFAULT_SUBNET_PREFIX}" in text
    )
    return Verdict(
        detected,
        (
            f"'{sig.AVD_DEFAULT_SUBNET_PREFIX}' found in interface config"
            if detected
            else "default AVD subnet not present"
        ),
    )


@REG.check(
    "android.design.suspicious_device_name",
    "identity.hostname",
    name="Device name plausibility",
    description="net.hostname / ro.product.device values such as 'sandbox', 'malware', 'analysis' or "
    "'mobsf'.",
    severity=Severity.LOW,
    remediation="Give the image a plausible personal device name.",
)
def check_suspicious_hostname(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    value = values.get("net.hostname") or values.get("ro.product.device") or ""
    hit = next((t for t in sig.SUSPICIOUS_NAME_TOKENS if t in value.lower()), None)
    return Verdict(bool(hit), f"{value!r}" + (f" (matched {hit!r})" if hit else ""))


CHECKS = REG.specs
