"""Signs of a person using the device: accounts, contacts, messages, call log,
photos, saved networks, paired devices, app usage, everyday apps, install
history and boot count.

Only counts are collected (``content query`` with a ``_id`` projection, never
row contents), per the privacy rule in docs/DESIGN-V2.md.
"""

from __future__ import annotations

import re
from datetime import datetime

from perdedor_common.models import Severity
from perdedor_common.registry import RunContext

from .. import signatures as sig
from ..adb import Device
from ._base import Checks, ProbeError, Skip, Verdict, need, packages, settings, to_int

REG = Checks()

# Numeric scarcity thresholds below are conservative local policies, not device guarantees.
# Rationale and overrides: docs/notes/android.md; observable APIs:
# https://source.android.com/docs/compatibility/cdd
# https://developer.android.com/reference/android/provider/Settings.Global


# Thresholds (operator-tunable with --param). A phone that someone uses has
# at least one account, dozens of contacts, messages and calls and hundreds of
# photos; the thresholds are deliberately far below that so only a sterile
# image trips them.
MIN_ACCOUNTS = 1
MIN_CONTACTS = 5
MIN_SMS = 5
MIN_CALLS = 5
MIN_PHOTOS = 10
MIN_SAVED_NETWORKS = 2
MIN_BONDED_DEVICES = 1
MIN_USED_PACKAGES = 10
MIN_EVERYDAY_APPS = 2
# Fresh images install every app within minutes; a used phone accumulates
# installs over weeks.
MIN_INSTALL_SPAN_DAYS = 7
# settings global boot_count is incremented on every boot since Android 7
# (Settings.Global.BOOT_COUNT); a snapshot that was booted a handful of
# times is a lab image.
MIN_BOOT_COUNT = 10


def _count_rows(dev: Device, uri: str) -> int:
    text = dev.sh(f"content query --uri {uri} --projection _id", timeout=30.0, any_rc=True)
    if text is None:
        raise ProbeError(f"content query {uri} failed")
    if "No result found" in text:
        return 0
    if re.search(
        r"(?i)(SecurityException|Permission Denial|Error while accessing provider|Unknown URI)", text
    ):
        raise Skip(f"{uri} is not readable by the shell user on this build")
    count = len(re.findall(r"^Row: \d+", text, re.MULTILINE))
    if not count:
        raise Skip("provider returned no recognized rows or explicit empty result")
    return count


def _count_check(check_id: str, uri: str, title: str, default_min: int, technique: str, severity: Severity):
    def fn(dev: Device, ctx: RunContext) -> Verdict:
        count = _count_rows(dev, uri)
        minimum = ctx.param(f"android.min_{check_id.rsplit('.', 1)[1]}", default_min)
        return Verdict(count < minimum, {"count": count}, measurement={"count": count, "min": minimum})

    REG.check(
        check_id,
        technique,
        name=f"{title} count",
        description=f"Number of {title.lower()} ({uri}); counts only. Fewer than {default_min} means nobody "
        "uses this device.",
        severity=severity,
        remediation=f"Populate the golden image with synthetic {title.lower()} (generated, not real people's data).",
        cost="medium",
    )(fn)


_count_check(
    "android.behavioural.contacts",
    "content://com.android.contacts/contacts",
    "Contacts",
    MIN_CONTACTS,
    "wear_and_tear.personal_data",
    Severity.MEDIUM,
)
_count_check(
    "android.behavioural.sms",
    "content://sms",
    "SMS messages",
    MIN_SMS,
    "wear_and_tear.personal_data",
    Severity.MEDIUM,
)
_count_check(
    "android.behavioural.call_log",
    "content://call_log/calls",
    "Call log entries",
    MIN_CALLS,
    "wear_and_tear.personal_data",
    Severity.MEDIUM,
)
_count_check(
    "android.behavioural.photos",
    "content://media/external/images/media",
    "Photos",
    MIN_PHOTOS,
    "wear_and_tear.user_files",
    Severity.LOW,
)


@REG.check(
    "android.behavioural.accounts",
    "wear_and_tear.personal_data",
    name="Accounts on the device",
    description="dumpsys account: no Google or other accounts signed in.",
    severity=Severity.MEDIUM,
    remediation="Sign a dedicated (non-personal) test account into the golden image.",
)
def check_accounts(dev: Device, ctx: RunContext) -> Verdict:
    text = need(dev.dumpsys("account"), "dumpsys account")
    match = re.search(r"Accounts:\s*(\d+)", text)
    if not match:
        raise ProbeError("no 'Accounts:' line in dumpsys account")
    count = int(match.group(1))
    types = sorted(set(re.findall(r"Account \{name=[^,]*, type=([^}]+)\}", text)))
    return Verdict(count < MIN_ACCOUNTS, {"accounts": count, "types": types or None})


@REG.check(
    "android.behavioural.saved_wifi_networks",
    "wear_and_tear.network_history",
    name="Saved Wi-Fi networks",
    description="`cmd wifi list-networks` (Android 11+): a used phone remembers home, work and cafe networks; "
    "an emulator knows one (AndroidWifi) or none.",
    severity=Severity.LOW,
    remediation="Pre-provision several saved Wi-Fi networks in the golden image.",
)
def check_saved_wifi_networks(dev: Device, ctx: RunContext) -> Verdict:
    text = dev.sh("cmd wifi list-networks", any_rc=True)
    if text is None or "Unknown command" in text or "No shell command implementation" in text:
        raise Skip("`cmd wifi list-networks` not available (Android 10 or older, or no Wi-Fi)")
    if "No networks" in text:
        count = 0
    else:
        count = len([line for line in text.splitlines()[1:] if re.match(r"^\s*\d+\s", line)])
    return Verdict(count < MIN_SAVED_NETWORKS, {"saved_networks": count})


@REG.check(
    "android.behavioural.bluetooth_bonded",
    "wear_and_tear.peripherals_history",
    name="Paired Bluetooth devices",
    description="dumpsys bluetooth_manager 'Bonded devices': phones are paired with headphones, cars, "
    "watches.",
    severity=Severity.LOW,
    remediation="Add paired-device records to the golden image's Bluetooth configuration.",
)
def check_bluetooth_bonded(dev: Device, ctx: RunContext) -> Verdict:
    text = dev.dumpsys("bluetooth_manager")
    if text is None:
        raise Skip("bluetooth_manager service not available")
    match = re.search(r"Bonded devices:\s*(\d+)?", text)
    if not match:
        raise Skip("no 'Bonded devices' section (Bluetooth disabled or old build)")
    if match.group(1):
        count = int(match.group(1))
    else:
        block = text[match.end() :].split("\n\n", 1)[0]
        count = len(re.findall(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", block, re.IGNORECASE))
    return Verdict(count < MIN_BONDED_DEVICES, {"bonded": count})


@REG.check(
    "android.behavioural.app_usage",
    "wear_and_tear.usage_traces",
    name="App usage history",
    description="dumpsys usagestats: number of distinct packages with recorded usage. A used phone has "
    "dozens; a fresh image only the launcher and settings.",
    severity=Severity.LOW,
    remediation="Exercise apps (open/close cycles) on the golden image before freezing it so usage stats exist.",
    cost="medium",
)
def check_app_usage(dev: Device, ctx: RunContext) -> Verdict:
    text = need(dev.dumpsys("usagestats", timeout=45.0), "dumpsys usagestats")
    used = set(re.findall(r'package=([\w.]+)\s+totalTime(?:Used|Visible)="?(?!0[",\s])', text))
    if not used:
        used = set(re.findall(r"package=([\w.]+)", text))
    return Verdict(len(used) < MIN_USED_PACKAGES, {"packages_with_usage": len(used)})


@REG.check(
    "android.behavioural.everyday_apps",
    "wear_and_tear.installed_software",
    name="Everyday apps installed",
    description=f"How many of {len(sig.EVERYDAY_PACKAGES)} common messaging/social/media/shopping apps are "
    "installed; analysis images rarely have any.",
    severity=Severity.LOW,
    remediation="Install common apps for the imitated region on the golden image.",
)
def check_everyday_apps(dev: Device, ctx: RunContext) -> Verdict:
    installed = set(packages(dev))
    present = [p for p in sig.EVERYDAY_PACKAGES if p in installed]
    return Verdict(
        len(present) < MIN_EVERYDAY_APPS, {"present": present or None, "of": len(sig.EVERYDAY_PACKAGES)}
    )


@REG.check(
    "android.behavioural.install_time_spread",
    "wear_and_tear.system_age",
    name="App install-time spread",
    description="firstInstallTime of user apps (dumpsys package): all installed within a few days means a "
    "freshly built image.",
    severity=Severity.LOW,
    remediation="Age the golden image: install apps over time or set realistic install timestamps in "
    "packages.xml before freezing.",
    cost="medium",
)
def check_install_time_spread(dev: Device, ctx: RunContext) -> Verdict:
    user = set(packages(dev, "third_party"))
    if not user:
        raise Skip("no user-installed apps (see android.behavioural.installed_packages)")
    text = need(dev.dumpsys("package packages", timeout=60.0), "dumpsys package packages")
    times = []
    current = None
    for line in text.splitlines():
        head = re.match(r"^\s*Package \[([\w.]+)\]", line)
        if head:
            current = head.group(1)
            continue
        match = re.search(r"firstInstallTime=(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", line)
        if match and current in user:
            try:
                times.append(datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S"))
            except ValueError:
                pass
    if len(times) < 2:
        raise Skip("fewer than two user apps with an install time")
    span_days = (max(times) - min(times)).total_seconds() / 86400
    minimum = ctx.param("android.min_install_span_days", float(MIN_INSTALL_SPAN_DAYS))
    return Verdict(
        span_days < minimum,
        {"apps": len(times), "span_days": round(span_days, 2)},
        measurement={"span_days": round(span_days, 2), "min_days": minimum},
    )


@REG.check(
    "android.behavioural.boot_count",
    "wear_and_tear.system_age",
    name="Boot count",
    description=f"settings global boot_count below {MIN_BOOT_COUNT}: an image booted only a few times.",
    severity=Severity.LOW,
    remediation="Raise boot_count in the golden image (settings put global boot_count N) or reboot it many "
    "times before freezing.",
)
def check_boot_count(dev: Device, ctx: RunContext) -> Verdict:
    count = to_int(settings(dev, "global").get("boot_count"))
    if count is None:
        raise Skip("settings global boot_count not present (Android 6 or older)")
    minimum = ctx.param("android.min_boot_count", MIN_BOOT_COUNT)
    return Verdict(count < minimum, {"boot_count": count}, measurement={"boot_count": count, "min": minimum})


@REG.check(
    "android.behavioural.user_files",
    "wear_and_tear.user_files",
    name="Files in the user's storage",
    description="Files in /sdcard/DCIM, /sdcard/Download, /sdcard/Pictures and /sdcard/Documents.",
    severity=Severity.LOW,
    remediation="Place synthetic photos, downloads and documents in shared storage.",
)
def check_user_files(dev: Device, ctx: RunContext) -> Verdict:
    counts = {}
    for folder in ("/sdcard/DCIM", "/sdcard/Download", "/sdcard/Pictures", "/sdcard/Documents"):
        names = dev.listdir(folder)
        if names is not None:
            counts[folder] = len(names)
    if not counts:
        raise Skip("shared storage directories are not readable")
    total = sum(counts.values())
    return Verdict(total < MIN_PHOTOS, counts, measurement={"entries": total, "min": MIN_PHOTOS})


CHECKS = REG.specs
