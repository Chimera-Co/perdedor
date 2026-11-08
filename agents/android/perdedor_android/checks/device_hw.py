"""Phone hardware a sample expects: sensors, radios, camera, battery, CPU
cores, memory, storage and screen.

Banking trojans gate their payload on this: Anubis droppers waited for
accelerometer motion (Trend Micro, 2019), Cerberus counts steps with the
step-counter sensor before activating (ThreatFabric, 2019), and many
families refuse to run without a SIM/telephony radio (see catalog
references).
"""

from __future__ import annotations

import re

from perdedor_common.models import Severity
from perdedor_common.registry import RunContext

from .. import signatures as sig
from ..adb import Device
from ._base import Checks, ProbeError, Skip, Verdict, features, need, substr_hits, to_int
from ._parsers import parse_battery, parse_recent_events, parse_sensors

REG = Checks()

# Numeric scarcity thresholds below are conservative local policies, not device guarantees.
# Rationale and overrides: docs/notes/android.md; observable APIs:
# https://source.android.com/docs/compatibility/cdd
# https://developer.android.com/reference/android/provider/Settings.Global


# Sensor types every mainstream phone exposes; Cerberus uses the step
# counter, Anubis the accelerometer. Two or more missing is the tell (a
# single missing gyroscope is common on budget phones).
ESSENTIAL_SENSOR_TYPES = (
    "android.sensor.accelerometer",
    "android.sensor.gyroscope",
    "android.sensor.magnetic_field",
    "android.sensor.proximity",
    "android.sensor.light",
    "android.sensor.step_counter",
)
MAX_MISSING_ESSENTIAL = 1
# At least this many identical recent accelerometer samples means the device
# may be stationary; low-confidence evidence only, also possible for a
# simulated sensor that replays a constant (Anubis motion check).
MIN_STATIC_EVENTS = 5
# Li-ion cell voltage range: 3.0 V cut-off to 4.45 V (high-voltage cells)
# full charge (Battery University BU-205, https://batteryuniversity.com/article/bu-205-types-of-lithium-ion).
LI_ION_MIN_MV = 3000
LI_ION_MAX_MV = 4500
# Android emulator AVD defaults: 2-4 cores, 2 GB RAM, 6 GB /data
# (Android Studio AVD Manager defaults); every mainstream phone SoC since
# 2014 has at least 4 cores and phones sold since 2019 at least 2 GB RAM
# (Android Go floor) - see docs/notes/android.md.
MIN_CPU_CORES = 4
MIN_MEMORY_MB = 2048
MIN_DATA_GB = 16
# Landscape PC/VESA modes that VMs default to (Android-x86 on a VGA/Bochs
# display, Genymotion, BlueStacks); a phone's natural orientation is portrait.
VESA_MODES = {
    (800, 600),
    (1024, 768),
    (1280, 800),
    (1280, 1024),
    (1366, 768),
    (1440, 900),
    (1600, 900),
    (1920, 1080),
}
MIN_SHORT_SIDE_PX = 720


def _sensors(dev: Device):
    return parse_sensors(need(dev.dumpsys("sensorservice"), "dumpsys sensorservice"))


@REG.check(
    "android.design.sensor_vendors",
    "mobile_device.sensors",
    name="Emulator sensor names and vendors",
    description="Sensor names/vendors such as 'Goldfish 3-axis Accelerometer', 'Genymotion', 'BlueStacks', "
    "or physical sensors (accelerometer) whose vendor is 'The Android Open Source Project' - the AOSP "
    "emulator HAL. Real accelerometers name Bosch, STMicro, InvenSense, TDK...",
    severity=Severity.HIGH,
    remediation="Use a sensor HAL that reports vendor part names (or pass real sensors through).",
)
def check_sensor_vendors(dev: Device, ctx: RunContext) -> Verdict:
    sensors = _sensors(dev)
    if not sensors:
        raise Skip("no sensors listed (see android.design.sensor_list)")
    named = [
        f"{s.name} | {s.vendor}"
        for s in sensors
        if substr_hits(f"{s.name} {s.vendor}", sig.SENSOR_EMULATOR_TOKENS)
    ]
    aosp_physical = [
        s.name
        for s in sensors
        if s.type == "android.sensor.accelerometer" and s.vendor == sig.AOSP_SENSOR_VENDOR
    ]
    return Verdict(
        bool(named or aosp_physical),
        {"emulator_named": named[:8] or None, "aosp_accelerometer": aosp_physical or None},
    )


@REG.check(
    "android.design.sensor_essential_types",
    "mobile_device.sensors",
    name="Essential sensor types",
    description="Accelerometer, gyroscope, magnetometer, proximity, light and step counter; two or more "
    "missing marks a VM/emulator (Cerberus step-counter and Anubis accelerometer gates).",
    severity=Severity.HIGH,
    remediation="Expose the full sensor set through a virtual sensor HAL fed with recorded human motion.",
)
def check_sensor_essential_types(dev: Device, ctx: RunContext) -> Verdict:
    sensors = _sensors(dev)
    types = {s.type for s in sensors}
    if sensors and not any(types):
        raise Skip("sensor list format without type names (very old Android)")
    missing = [t.rsplit(".", 1)[1] for t in ESSENTIAL_SENSOR_TYPES if t not in types]
    return Verdict(
        len(missing) > MAX_MISSING_ESSENTIAL,
        {"missing": missing or None},
        measurement={"missing": len(missing), "max_missing": MAX_MISSING_ESSENTIAL},
    )


@REG.check(
    "android.behavioural.sensor_activity",
    "mobile_device.sensor_activity",
    name="Accelerometer shows no motion",
    description="The 'Recent Sensor events' buffer of dumpsys sensorservice: identical accelerometer samples "
    "mean a perfectly still or replayed sensor (Anubis dropper motion check). Skipped when no app has used the "
    "accelerometer recently.",
    severity=Severity.MEDIUM,
    remediation="Feed the virtual accelerometer with recorded hand-held motion (small noise on every axis).",
)
def check_sensor_activity(dev: Device, ctx: RunContext) -> Verdict:
    text = need(dev.dumpsys("sensorservice"), "dumpsys sensorservice")
    events = parse_recent_events(text)
    accel = {name: ev for name, ev in events.items() if "accel" in name.lower() and ev}
    if not accel:
        raise Skip("no recent accelerometer events buffered (no app listening)")
    name, samples = max(accel.items(), key=lambda kv: len(kv[1]))
    distinct = {tuple(round(v, 3) for v in s[:3]) for s in samples}
    static = len(samples) >= MIN_STATIC_EVENTS and len(distinct) == 1
    return Verdict(
        static,
        {"sensor": name, "samples": len(samples), "distinct": len(distinct)},
        measurement={"samples": len(samples), "distinct_values": len(distinct)},
    )


def _battery(dev: Device) -> dict[str, str]:
    return parse_battery(need(dev.dumpsys("battery"), "dumpsys battery"))


@REG.check(
    "android.behavioural.battery_voltage",
    "mobile_device.battery",
    name="Battery voltage plausibility",
    description=f"dumpsys battery voltage outside the Li-ion range {LI_ION_MIN_MV}-{LI_ION_MAX_MV} mV "
    "(0, 5000 or other fixed simulator values).",
    severity=Severity.LOW,
    remediation="Simulate a battery with a voltage that follows the charge level (3.5-4.4 V).",
)
def check_battery_voltage(dev: Device, ctx: RunContext) -> Verdict:
    voltage = to_int(_battery(dev).get("voltage"))
    if voltage is None:
        raise ProbeError("no voltage in dumpsys battery")
    return Verdict(not LI_ION_MIN_MV <= voltage <= LI_ION_MAX_MV, {"voltage_mv": voltage})


@REG.check(
    "android.behavioural.battery_present",
    "mobile_device.battery",
    name="Battery present and identified",
    description="dumpsys battery 'present: false', no technology or unknown health: a desktop VM without a "
    "battery (Android-x86) or a placeholder HAL.",
    severity=Severity.MEDIUM,
    remediation="Provide a battery HAL that reports a present Li-ion battery with health GOOD.",
)
def check_battery_present(dev: Device, ctx: RunContext) -> Verdict:
    bat = _battery(dev)
    present = bat.get("present", "").lower()
    tech = bat.get("technology", "")
    health = bat.get("health", "")
    bad = present == "false" or tech in ("", "Unknown") or health in ("1", "Unknown")
    return Verdict(bad, {"present": present or None, "technology": tech or None, "health": health or None})


@REG.check(
    "android.design.radio_interfaces",
    "mobile_device.radios",
    name="Network interfaces of an emulator",
    description="eth0 (CalebFenton hasEth0Interface) or the AVD's radio0 interface, and no wlan0/rmnet*/"
    "ccmni* cellular or Wi-Fi interface of a phone.",
    severity=Severity.MEDIUM,
    remediation="Name the guest's interfaces like a phone (wlan0 for Wi-Fi) and avoid exposing eth0.",
)
def check_radio_interfaces(dev: Device, ctx: RunContext) -> Verdict:
    names = dev.listdir("/sys/class/net")
    if names is None:
        raise ProbeError("could not list /sys/class/net")
    phone_like = [n for n in names if n.startswith(("wlan", "rmnet", "ccmni", "rev_rmnet", "seth", "pdp"))]
    emulator_like = [n for n in names if n.startswith(("eth", "radio")) or n in ("enp0s3", "ens3")]
    return Verdict(bool(emulator_like) and not phone_like, {"interfaces": sorted(names)})


def _feature_check(feature: str):
    def fn(dev: Device, ctx: RunContext) -> Verdict:
        present = feature in features(dev)
        return Verdict(not present, {feature: present})

    return fn


for _id, _feature, _title, _sev in (
    ("android.design.wifi_feature", "android.hardware.wifi", "Wi-Fi", Severity.MEDIUM),
    ("android.design.bluetooth_feature", "android.hardware.bluetooth", "Bluetooth", Severity.MEDIUM),
    ("android.design.nfc_feature", "android.hardware.nfc", "NFC", Severity.INFO),
    ("android.design.gps_feature", "android.hardware.location.gps", "GPS", Severity.LOW),
):
    REG.check(
        _id,
        "mobile_device.radios",
        name=f"{_title} hardware feature",
        description=f"{_feature} missing from `pm list features`; phones declare it, VMs and Android-x86 "
        "images often do not.",
        severity=_sev,
        remediation=f"Provide a virtual {_title} device so {_feature} is declared.",
    )(_feature_check(_feature))


@REG.check(
    "android.design.wifi_ssid",
    "mobile_device.radios",
    name="Emulator Wi-Fi network (AndroidWifi)",
    description="The AVD's simulated access point is called 'AndroidWifi'; seeing it connected or saved "
    "identifies the stock emulator.",
    severity=Severity.HIGH,
    remediation="Use a realistic SSID on the analysis network's access point.",
)
def check_wifi_ssid(dev: Device, ctx: RunContext) -> Verdict:
    text = dev.dumpsys("wifi", timeout=30.0)
    if text is None:
        raise Skip("wifi service not available")
    hit = f'"{sig.AVD_WIFI_SSID}"' in text or f"SSID: {sig.AVD_WIFI_SSID}" in text
    return Verdict(hit, {"AndroidWifi": hit})


@REG.check(
    "android.design.bluetooth_identity",
    "mobile_device.radios",
    name="Bluetooth adapter identity",
    description="Bluetooth address 00:00:00:00:00:00 / 02:00:00:00:00:00 or no adapter in dumpsys "
    "bluetooth_manager.",
    severity=Severity.LOW,
    remediation="Provide a Bluetooth controller (virtual or passthrough) with a vendor address.",
)
def check_bluetooth_identity(dev: Device, ctx: RunContext) -> Verdict:
    text = dev.dumpsys("bluetooth_manager")
    if text is None:
        raise Skip("bluetooth_manager service not available")
    match = re.search(r"(?im)^\s*address:\s*([0-9A-F:]{17})", text)
    address = match.group(1).upper() if match else None
    bad = address is None or address in ("00:00:00:00:00:00", "02:00:00:00:00:00")
    return Verdict(bad, {"address_present": address is not None, "placeholder": bad and address is not None})


@REG.check(
    "android.design.camera_hal",
    "mobile_device.camera",
    name="Camera HAL identity",
    description="dumpsys media.camera reporting zero camera devices, or an emulated camera HAL "
    "('EmulatedCamera', 'Emulated', 'goldfish', qemu.sf.fake_camera).",
    severity=Severity.MEDIUM,
    remediation="Provide a camera HAL with vendor-looking camera ids and characteristics.",
    cost="medium",
)
def check_camera_hal(dev: Device, ctx: RunContext) -> Verdict:
    text = dev.dumpsys("media.camera")
    if text is None:
        raise Skip("media.camera service not available")
    count = re.search(r"Number of camera devices:\s*(\d+)", text)
    n = int(count.group(1)) if count else None
    emulated = substr_hits(text[:20000], ("EmulatedCamera", "Emulated camera", "goldfish", "qemu"))
    return Verdict(n == 0 or bool(emulated), {"camera_devices": n, "emulated": emulated or None})


@REG.check(
    "android.env.cpu_count",
    "resources.cpu_count",
    name="CPU core count",
    description=f"Fewer than {MIN_CPU_CORES} CPU cores (/sys/devices/system/cpu/possible); AVDs default to "
    "2-4 cores, current phones have 6-8.",
    severity=Severity.LOW,
    remediation="Give the guest at least 6-8 vCPUs.",
)
def check_cpu_count(dev: Device, ctx: RunContext) -> Verdict:
    text = dev.read("/sys/devices/system/cpu/possible") or dev.read("/sys/devices/system/cpu/present")
    count = None
    if text:
        count = 0
        for part in text.strip().split(","):
            lo, _, hi = part.partition("-")
            if lo.isdigit():
                count += (int(hi) - int(lo) + 1) if hi.isdigit() else 1
    if not count:
        nproc = dev.sh("nproc")
        count = to_int(nproc)
    if not count:
        raise ProbeError("could not read the CPU count")
    minimum = ctx.param("android.min_cpu_cores", MIN_CPU_CORES)
    return Verdict(count < minimum, {"cores": count}, measurement={"cores": count, "min": minimum})


@REG.check(
    "android.env.memory_size",
    "resources.memory_size",
    name="Physical memory",
    description=f"MemTotal below {MIN_MEMORY_MB} MB (/proc/meminfo).",
    severity=Severity.LOW,
    remediation="Give the guest 4-8 GB of RAM, as current phones have.",
)
def check_memory_size(dev: Device, ctx: RunContext) -> Verdict:
    text = need(dev.read("/proc/meminfo"), "/proc/meminfo")
    match = re.search(r"MemTotal:\s*(\d+)\s*kB", text)
    if not match:
        raise ProbeError("no MemTotal in /proc/meminfo")
    mb = int(match.group(1)) // 1024
    minimum = ctx.param("android.min_memory_mb", MIN_MEMORY_MB)
    return Verdict(mb < minimum, {"memtotal_mb": mb}, measurement={"memtotal_mb": mb, "min_mb": minimum})


@REG.check(
    "android.env.storage_size",
    "resources.disk_size",
    name="Data partition size",
    description=f"/data smaller than {MIN_DATA_GB} GB (`df /data`); the AVD default data partition is 6 GB, "
    "phones ship 64-512 GB.",
    severity=Severity.LOW,
    remediation="Give the guest a data partition of 64 GB or more (sparse images cost nothing).",
)
def check_storage_size(dev: Device, ctx: RunContext) -> Verdict:
    text = need(dev.sh("df -k /data"), "df /data")
    rows = [line.split() for line in text.splitlines()[1:] if line.split()]
    size_kb = None
    for row in rows:
        for cell in row[1:3]:
            if cell.isdigit():
                size_kb = int(cell)
                break
        if size_kb:
            break
    if size_kb is None:
        raise ProbeError(f"unparseable df output: {text[:120]!r}")
    gb = round(size_kb / 1024 / 1024, 1)
    minimum = ctx.param("android.min_data_gb", MIN_DATA_GB)
    return Verdict(gb < minimum, {"data_gb": gb}, measurement={"data_gb": gb, "min_gb": minimum})


@REG.check(
    "android.env.screen",
    "resources.screen",
    name="Screen size and orientation",
    description="`wm size`: a landscape PC/VESA mode (1024x768, 1280x800, 1920x1080...) as the physical "
    "size, or a short side below 720 px, instead of a portrait phone panel.",
    severity=Severity.LOW,
    remediation="Configure a portrait phone resolution (e.g. 1080x2400 at 420 dpi) in the VM display.",
)
def check_screen(dev: Device, ctx: RunContext) -> Verdict:
    text = need(dev.sh("wm size"), "wm size")
    match = re.search(r"Physical size:\s*(\d+)x(\d+)", text)
    if not match:
        raise ProbeError(f"unparseable `wm size`: {text[:80]!r}")
    w, h = int(match.group(1)), int(match.group(2))
    density = re.search(r"Physical density:\s*(\d+)", dev.sh("wm density") or "")
    landscape_pc = (w, h) in VESA_MODES
    small = min(w, h) < MIN_SHORT_SIDE_PX
    return Verdict(
        landscape_pc or small,
        {"physical": f"{w}x{h}", "density": int(density.group(1)) if density else None},
    )


CHECKS = REG.specs
