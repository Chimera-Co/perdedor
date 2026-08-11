"""Category 4 (Ch.3.2.4): design-choice / platform-specific detection.

Not virtualisation-in-general, but quirks specific to *this* analysis
platform's known tells -- exactly the category HYDRA itself exists to keep
current on (CHIMERA Ch.3.2.4: "a CHIMERA-specific instance of this problem
is exactly what HYDRA is intended to continuously check for"). Covers
al-khaser's "Analysis Tools" section and a Linux-native reading of its
username/hostname blacklist.
"""

from __future__ import annotations

import os
import re
import socket
from pathlib import Path

from hydra_common import FindingFactory
from hydra_common.models import Category, Finding, Platform, Severity

from .. import signatures, utils

_PLATFORM = Platform.LINUX
_CATEGORY = Category.DESIGN_SPECIFIC
_f = FindingFactory(category=_CATEGORY, platform=_PLATFORM)


def check_analysis_tools_running() -> Finding:
    check_id, name = "linux.design.analysis_tools_running", "Malware-analysis tooling running"
    description = (
        "Checks the process list for debuggers/sniffers/disassemblers whose presence alone signals analysis."
    )
    ps_out = utils.run(["ps", "-eo", "comm"])
    if ps_out is None:
        return _f.error(
            check_id, name, description, Severity.MEDIUM, "`ps -eo comm` failed or is unavailable"
        )
    running = {line.strip().lower() for line in ps_out.splitlines() if line.strip()}
    hits = [tool for tool in signatures.ANALYSIS_TOOL_PROCESS_NAMES if tool in running]
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.MEDIUM,
        is_detected=bool(hits),
        evidence=hits or None,
        remediation="Run analysis tooling out-of-guest (host-side memory acquisition) instead of inside the detonation VM.",
    )


def check_suspicious_hostname_or_user() -> Finding:
    check_id, name = "linux.design.suspicious_hostname_or_user", "Hostname/username plausibility (substring)"
    description = "Hostnames/usernames like 'sandbox' or 'malware' are an easy, high-confidence tell malware checks for."
    hostname = socket.gethostname()
    username = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    hits = [
        (
            f"hostname={hostname!r}"
            if utils.any_signature_in(hostname, signatures.SUSPICIOUS_NAME_TOKENS)
            else None
        ),
        f"user={username!r}" if utils.any_signature_in(username, signatures.SUSPICIOUS_NAME_TOKENS) else None,
    ]
    hits = [h for h in hits if h]
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.LOW,
        is_detected=bool(hits),
        evidence=hits or f"hostname={hostname!r} user={username!r}",
        remediation="Rename the golden image's hostname/user account to a plausible everyday identity.",
    )


def check_exact_sandbox_username() -> Finding:
    check_id, name = "linux.design.exact_sandbox_username", "Username exact-match blacklist (al-khaser style)"
    description = "al-khaser checks the current username against an exact-match blacklist (e.g. 'test', 'sandbox', 'john doe') rather than a substring -- short names like 'test' would false-positive under substring matching."
    username = (os.environ.get("USER") or os.environ.get("LOGNAME") or "").lower()
    matched = username in signatures.SANDBOX_USERNAME_EXACT
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.LOW,
        is_detected=matched,
        evidence=f"user={username!r}",
        remediation="Use a plausible full-name-style user account (e.g. the CHIMERA build guide's 'Arjun Mehta' convention), never a generic/test-sounding name.",
    )


def check_mac_oui() -> Finding:
    check_id, name = "linux.design.mac_oui", "NIC MAC address OUI"
    description = (
        "Compares the first 3 octets of each NIC's MAC against well-known virtual-NIC vendor prefixes."
    )
    net_root = Path("/sys/class/net")
    if not net_root.is_dir():
        return _f.skipped(check_id, name, description, Severity.MEDIUM, "/sys/class/net not present")
    hits: list[str] = []
    for iface_dir in net_root.iterdir():
        if iface_dir.name == "lo":
            continue
        mac = utils.read_text(str(iface_dir / "address"))
        if not mac or not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", mac.lower()):
            continue
        oui = mac.lower()[:8]
        vendor = signatures.MAC_OUI_SIGNATURES.get(oui)
        if vendor:
            hits.append(f"{iface_dir.name}={mac} ({vendor})")
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.MEDIUM,
        is_detected=bool(hits),
        evidence=hits or None,
        remediation="Assign a MAC address consistent with the spoofed hardware vendor (e.g. an ASUS-registered OUI).",
    )


def run_all() -> list[Finding]:
    return [
        check_analysis_tools_running(),
        check_suspicious_hostname_or_user(),
        check_exact_sandbox_username(),
        check_mac_oui(),
    ]
