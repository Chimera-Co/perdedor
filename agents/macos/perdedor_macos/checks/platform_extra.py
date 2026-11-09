"""Additional standard-command platform observations; no privileged API calls."""

from perdedor_common.models import Platform, Severity
from perdedor_common.registry import RunContext

from .. import parsing
from ..checkkit import Meta, Result, Skip, Verdict, build
from ..target import Target

MRT_PLIST = "/System/Library/CoreServices/MRT.app/Contents/Info.plist"
# XProtect supersedes MRT on recent macOS; absence alone is not an evasion tell.
# https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web
XPROTECT_PLIST = "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist"


def probe_mrt(target: Target, ctx: RunContext) -> Result:
    mrt = target.read_plist(MRT_PLIST)
    successor = target.read_plist(XPROTECT_PLIST)
    versions = {
        name: str(doc.get("CFBundleShortVersionString", doc.get("CFBundleVersion", "unknown")))
        for name, doc in (("MRT", mrt), ("XProtect", successor))
        if isinstance(doc, dict)
    }
    if not versions:
        return Skip("malware-removal component metadata unavailable")
    return Verdict(False, {"versions": versions, "note": "version inventory; no online currency verdict"})


def probe_power(target: Target, ctx: RunContext) -> Result:
    document = target.profiler("SPPowerDataType")
    if document is None:
        return Skip("power profile unavailable")
    text = parsing.flatten_strings(document)
    hits = parsing.find_tokens(text, ("vmware", "parallels", "qemu", "virtual"))
    return Verdict(bool(hits), {"power_vendor_markers": hits})


def probe_network_profile(target: Target, ctx: RunContext) -> Result:
    document = target.profiler("SPNetworkDataType")
    if document is None:
        return Skip("network hardware profile unavailable")
    hits = parsing.find_tokens(parsing.flatten_strings(document), ("vmware", "parallels", "virtio", "qemu"))
    return Verdict(bool(hits), {"network_vendor_markers": hits})


def probe_login_items(target: Target, ctx: RunContext) -> Result:
    # sfltool dumpbtm is the read-only inventory interface for Ventura and later.
    # https://support.apple.com/guide/deployment/manage-login-items-background-tasks-depdca572563/web
    text = target.out("login_items", "sfltool dumpbtm")
    if text is None or "UUID:" not in text:
        return Skip("background task inventory unavailable or empty")
    count = sum(line.strip().startswith("UUID:") for line in text.splitlines())
    # Inventory only: built-in and managed jobs prevent a reliable scarcity threshold.
    return Verdict(False, {"background_task_records": count})


CHECKS = [
    build(
        Platform.MACOS,
        Meta(
            "macos.design.mrt_version",
            "os_config.security_software",
            "Malware removal versions",
            "MRT or successor XProtect version inventory; no external update lookup.",
            Severity.INFO,
            "Maintain the supported XProtect components through Software Update.",
        ),
        probe_mrt,
    ),
    build(
        Platform.MACOS,
        Meta(
            "macos.env.power_identity",
            "hardware.battery_power",
            "Power hardware identity",
            "Power profile explicitly names virtual hardware.",
            Severity.MEDIUM,
            "Use power devices consistent with the advertised Mac hardware.",
        ),
        probe_power,
    ),
    build(
        Platform.MACOS,
        Meta(
            "macos.env.network_profile",
            "hardware.nic_identity",
            "Network hardware identity",
            "Network hardware profile explicitly names a virtual adapter.",
            Severity.HIGH,
            "Use physical adapter passthrough or coherent device identities.",
        ),
        probe_network_profile,
    ),
    build(
        Platform.MACOS,
        Meta(
            "macos.behavioural.login_items",
            "wear_and_tear.usage_traces",
            "Login and background items",
            "Counts background task records without collecting task names.",
            Severity.INFO,
            "Install and use ordinary applications with their usual background components.",
        ),
        probe_login_items,
    ),
]
