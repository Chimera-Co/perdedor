"""Read-only peripheral and network signals visible to a device shell.

Daemon availability and registry strings are supporting evidence, not a substitute
for querying CoreMotion or CoreTelephony from a signed application.
"""

import re

from perdedor_common.models import Platform, Severity
from perdedor_common.registry import RunContext
from perdedor_macos.checkkit import Meta, Result, Skip, Verdict, build

from ..device import IosTarget

# CoreMotion services vary by iOS release; absence has deliberately low confidence.
# https://developer.apple.com/documentation/coremotion
MOTION_SERVICES = ("com.apple.motiontrackingd", "com.apple.locationd")
# The public I/O Registry inspection command is optional in iOS bootstraps.
# https://developer.apple.com/library/archive/documentation/Darwin/Reference/ManPages/man8/ioreg.8.html
BASEBAND_MARKERS = ("applebaseband", "baseband", "applegsm", "appletelephony")
# IOSSecuritySuite ProxyChecker uses these tunnel prefixes as VPN indicators.
# https://github.com/securing/IOSSecuritySuite/blob/7436aea705a6c7ad6013edaaeaf051667cdd4beb/IOSSecuritySuite/ProxyChecker.swift
VPN_PREFIXES = ("utun", "tun", "tap", "ppp", "ipsec")


def probe_motion(target: IosTarget, ctx: RunContext) -> Result:
    labels = target.launchd_labels()
    if not labels:
        return Skip("launchd service inventory unavailable")
    found = [label for label in labels if label in MOTION_SERVICES]
    return Verdict(
        not found, {"motion_location_services": found, "scope": "daemon availability"}, confidence=0.3
    )


def probe_baseband(target: IosTarget, ctx: RunContext) -> Result:
    machine = (target.sysctl() or {}).get("hw.machine", "")
    if not machine.lower().startswith("iphone"):
        return Skip("only iPhone identities require a baseband")
    text = target.ioreg("baseband", "-l -w0 -p IODeviceTree")
    if not text or "IORegistryEntry" not in text:
        return Skip("device tree unavailable from this bootstrap")
    found = [marker for marker in BASEBAND_MARKERS if marker in text.lower()]
    return Verdict(not found, {"baseband_markers": found}, confidence=0.4)


def active_tunnels(text: str) -> list[str]:
    """Tunnel interfaces that are UP and have an assigned IP address."""
    active = []
    for block in re.split(r"(?=^[a-zA-Z][\w.]*: flags=)", text, flags=re.MULTILINE):
        match = re.match(r"([\w.]+): flags=\S+<([^>]+)>", block)
        if match and match[1].startswith(VPN_PREFIXES) and "UP" in match[2].split(","):
            if re.search(r"^\s+inet6?\s+", block, re.MULTILINE):
                active.append(match[1])
    return active


def probe_vpn(target: IosTarget, ctx: RunContext) -> Result:
    if target.is_simulator:
        return Skip("network interfaces belong to the Simulator host")
    text = target.out("ifconfig", "ifconfig -a")
    if text is None:
        return Skip("interface inventory unavailable")
    tunnels = active_tunnels(text)
    return Verdict(bool(tunnels), {"active_tunnels": tunnels}, confidence=0.5)


def probe_lockdown(target: IosTarget, ctx: RunContext) -> Result:
    # IOSSecuritySuite ModesChecker.amIInLockdownMode reads this preference.
    # https://github.com/securing/IOSSecuritySuite/blob/7436aea705a6c7ad6013edaaeaf051667cdd4beb/IOSSecuritySuite/ModesChecker.swift
    document = target.read_plist("/var/mobile/Library/Preferences/.GlobalPreferences.plist")
    if not isinstance(document, dict) or "LDMGlobalEnabled" not in document:
        return Skip("Lockdown Mode preference unavailable")
    value = document["LDMGlobalEnabled"]
    if value not in (True, False, 0, 1):
        return Skip("Lockdown Mode preference type unsupported")
    return Verdict(bool(value), {"LDMGlobalEnabled": bool(value)})


CHECKS = [
    build(
        Platform.IOS,
        Meta(
            "ios.design.lockdown_mode",
            "integrity.developer_settings",
            "Lockdown Mode",
            "The readable global preference enables Lockdown Mode, changing app capabilities.",
            Severity.LOW,
            "Match Lockdown Mode to the intended device population.",
        ),
        probe_lockdown,
    ),
    build(
        Platform.IOS,
        Meta(
            "ios.env.motion_services",
            "mobile_device.sensors",
            "Motion and location services",
            "Motion/location service availability as a weak peripheral proxy; no sensor samples.",
            Severity.LOW,
            "Use real sensor hardware and keep normal motion/location services available.",
        ),
        probe_motion,
    ),
    build(
        Platform.IOS,
        Meta(
            "ios.env.baseband_registry",
            "mobile_device.telephony",
            "Baseband device tree",
            "An iPhone identity lacks baseband markers in a readable device tree.",
            Severity.LOW,
            "Use a physical iPhone with its baseband hardware for modem-sensitive samples.",
        ),
        probe_baseband,
    ),
    build(
        Platform.IOS,
        Meta(
            "ios.design.vpn_interfaces",
            "network.proxy_mitm",
            "Active VPN-like interfaces",
            "An active addressed tunnel can expose a VPN; private relay and system tunnels can also match.",
            Severity.LOW,
            "Place analysis routing outside the guest and avoid unnecessary device VPNs.",
        ),
        probe_vpn,
    ),
]
