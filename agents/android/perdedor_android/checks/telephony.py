"""Telephony identity: operator, SIM, baseband and subscriber identifiers.

The known emulator values come from anti-emulator (known_numbers,
known_device_ids, known_imsi_ids, isOperatorNameAndroid), framgia
EmulatorDetector (checkTelephony) and CalebFenton AndroidEmulatorDetect
(hasEmulatorTelephonyProperty: operator 'Android', line number prefix
155552155, IMSI ending 0000000000, voicemail 15552175049).

Subscriber identifiers are read through ``service call iphonesubinfo``. Access is often denied to the shell. Also, the transaction numbers of
IPhoneSubInfo differ between Android releases, so the probe calls the first
few (all getters) and classifies every string that comes back by its shape.
"""

from __future__ import annotations

import re

from perdedor_common.models import Severity
from perdedor_common.registry import RunContext

from .. import signatures as sig
from ..adb import Device
from ._base import Checks, Skip, Verdict, features, props
from ._parsers import parse_parcel_string

REG = Checks()

# IPhoneSubInfo transactions 1..4 are getters on every release from Android 5
# to 15 (getDeviceId, getDeviceIdForPhone/getImeiForSubscriber,
# getNaiForSubscriber, getDeviceSvn...). Higher numbers include
# getIccSimChallengeResponse, which talks to the SIM, so they are not called.
IPHONESUBINFO_MAX_TXN = 4
SHELL_PACKAGE = "com.android.shell"
SIM_ABSENT_STATES = ("ABSENT", "NOT_READY", "UNKNOWN", "PERM_DISABLED", "CARD_IO_ERROR")


def _first(value: str) -> str:
    # Multi-SIM builds store comma-separated per-slot values.
    return value.split(",")[0].strip()


@REG.check(
    "android.design.operator_identity",
    "mobile_device.telephony",
    name="Network/SIM operator 'Android' (310260)",
    description="The emulator modem reports operator name 'Android' with MCC/MNC 310260 for both network and "
    "SIM (anti-emulator isOperatorNameAndroid, CalebFenton getSimOperator). 310260 alone is also T-Mobile US, "
    "so only the 'Android' name is decisive.",
    severity=Severity.CRITICAL,
    remediation="Configure the modem simulator with a real operator name and MCC/MNC matching the device's "
    "claimed country (time zone, locale).",
)
def check_operator_identity(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    fields = {
        k: _first(values.get(k, ""))
        for k in (
            "gsm.operator.alpha",
            "gsm.operator.numeric",
            "gsm.sim.operator.alpha",
            "gsm.sim.operator.numeric",
        )
    }
    named_android = any(
        fields[k].lower() == sig.EMULATOR_OPERATOR_NAME for k in fields if k.endswith("alpha")
    )
    return Verdict(named_android, fields)


@REG.check(
    "android.design.sim_state",
    "mobile_device.telephony",
    name="SIM state",
    description="gsm.sim.state ABSENT/NOT_READY/UNKNOWN or unset: no SIM, as on Android-x86, BlueStacks and "
    "most VMs. Phones in use have a SIM in READY/LOADED state.",
    severity=Severity.MEDIUM,
    remediation="Provide a simulated SIM (modem simulator with a SIM profile) that reports READY/LOADED.",
)
def check_sim_state(dev: Device, ctx: RunContext) -> Verdict:
    state = _first(props(dev).get("gsm.sim.state", ""))
    return Verdict(state == "" or state.upper() in SIM_ABSENT_STATES, {"gsm.sim.state": state or None})


@REG.check(
    "android.design.baseband_version",
    "mobile_device.telephony",
    name="Baseband version",
    description="gsm.version.baseband is empty, 'unknown' or a bare emulator version on virtual devices; "
    "phones report the modem firmware build (e.g. g5300g-230925-...).",
    severity=Severity.MEDIUM,
    remediation="Set gsm.version.baseband to a vendor modem firmware string.",
)
def check_baseband_version(dev: Device, ctx: RunContext) -> Verdict:
    value = _first(props(dev).get("gsm.version.baseband", ""))
    bad = value == "" or value.lower() in ("unknown", "1.0.0.0", "baseband")
    return Verdict(bad, {"gsm.version.baseband": value or None})


@REG.check(
    "android.design.telephony_feature",
    "mobile_device.telephony",
    name="Telephony feature declared",
    description="android.hardware.telephony missing from `pm list features`: a 'phone' without a radio "
    "(Android-x86, BlueStacks, WSA). Wi-Fi-only tablets also lack it, hence low severity.",
    severity=Severity.LOW,
    remediation="Use an image/profile with a telephony stack and modem simulator.",
)
def check_telephony_feature(dev: Device, ctx: RunContext) -> Verdict:
    present = "android.hardware.telephony" in features(dev)
    return Verdict(not present, {"android.hardware.telephony": present})


@REG.check(
    "android.design.telephony_registry",
    "mobile_device.telephony",
    name="Cell service state (telephony.registry)",
    description="dumpsys telephony.registry: service state naming the 'Android' operator, or no cell "
    "registration at all (mServiceState out of service/power off, no cell info).",
    severity=Severity.MEDIUM,
    remediation="Simulate a registered cellular network with a real operator identity.",
)
def check_telephony_registry(dev: Device, ctx: RunContext) -> Verdict:
    text = dev.dumpsys("telephony.registry")
    if text is None:
        raise Skip("telephony.registry service not available (no telephony stack)")
    android_op = bool(re.search(r"(?i)(operatorAlphaLong|mOperatorAlphaLong)\s*=\s*Android\b", text))
    states = re.findall(r"mServiceState=\{?(?:mVoiceRegState=)?(\d+|[A-Z_()0-9]+)", text)
    in_service = bool(re.search(r"mVoiceRegState=0|mDataRegState=0|\(IN_SERVICE\)", text))
    return Verdict(
        android_op or not in_service,
        {"operator_android": android_op, "in_service": in_service, "service_states": states[:2] or None},
    )


def _subscriber_strings(dev: Device) -> list[str]:
    out = []
    for code in range(1, IPHONESUBINFO_MAX_TXN + 1):
        text = dev.sh(f"service call iphonesubinfo {code} s16 {SHELL_PACKAGE}", any_rc=True)
        if not text:
            continue
        value = parse_parcel_string(text)
        if value:
            out.append(value)
    return out


@REG.check(
    "android.design.telephony_identifiers",
    "mobile_device.telephony",
    name="IMEI / subscriber identifiers",
    description="Device id, IMSI, line number and voicemail of the emulator modem: 000000000000000 / "
    "e21833235b6eef10 / 012345678912345 (anti-emulator known_device_ids), IMSI 310260000000000, numbers "
    "1555521<port>, voicemail 15552175049, all-zero ids, and all-zero identifiers.",
    severity=Severity.CRITICAL,
    remediation="Give the modem simulator a Luhn-valid IMEI with a real TAC, a real-looking IMSI/MSISDN and "
    "voicemail number for the claimed operator.",
    cost="medium",
)
def check_telephony_identifiers(dev: Device, ctx: RunContext) -> Verdict:
    values = _subscriber_strings(dev)
    voicemail = props(dev).get("gsm.voicemail.number", "") or props(dev).get("ril.voicemail.number", "")
    if voicemail:
        values.append(voicemail)
    if not values:
        raise Skip(
            "no subscriber identifiers returned (no telephony stack, or iphonesubinfo refused the shell)"
        )
    hits = []
    for v in values:
        digits = v.strip()
        if (
            digits in sig.EMULATOR_DEVICE_IDS
            or digits in sig.EMULATOR_IMSI
            or digits in sig.EMULATOR_PHONE_NUMBERS
        ):
            hits.append(f"known emulator value {digits}")
        elif re.fullmatch(r"0+", digits):
            hits.append("all-zero identifier")
        elif digits.lstrip("+").startswith(sig.EMULATOR_PHONE_PREFIX):
            hits.append("emulator line number pattern")
        elif digits == sig.EMULATOR_VOICEMAIL:
            hits.append("emulator voicemail number")
        elif (
            len(digits) == 15
            and digits.isdigit()
            and digits.startswith("310260")
            and digits.endswith(sig.EMULATOR_IMSI_SUFFIX)
        ):
            hits.append("emulator IMSI pattern")
    return Verdict(bool(hits), {"identifiers_read": len(values), "matched": hits or None})


CHECKS = REG.specs
