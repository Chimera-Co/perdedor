"""Package ecosystem, identity and locally observable integrity signals."""

import re

from perdedor_common.models import Severity
from perdedor_common.registry import RunContext

from ..adb import Device, shell_quote
from ._base import Checks, Skip, Verdict, need, packages, props

REG = Checks()


def package_presence(package):
    def fn(dev, ctx):
        present = package in packages(dev)
        text = dev.dumpsys(f"package {package}") if present else None
        version = re.search(r"versionName=(\S+)", text or "")
        return Verdict(
            not present,
            {"package": package, "present": present, "version": version[1] if version else None},
            confidence=0.5,
        )

    return fn


for name, package in (("play_services", "com.google.android.gms"), ("play_store", "com.android.vending")):
    REG.check(
        f"android.design.{name}",
        "wear_and_tear.installed_software",
        name=name.replace("_", " "),
        description="Google ecosystem package presence and version; AOSP-only devices legitimately lack it.",
        severity=Severity.LOW,
        remediation="Use an appropriately licensed Google-services image when testing that ecosystem.",
    )(package_presence(package))


@REG.check(
    "android.behavioural.only_system_packages",
    "wear_and_tear.installed_software",
    name="Only system packages",
    description="Count all, system and third-party packages.",
    severity=Severity.LOW,
    remediation="Install a realistic set of everyday applications in the baseline.",
)
def only_system(dev: Device, ctx: RunContext):
    counts = {kind: len(packages(dev, kind)) for kind in ("all", "system", "third_party")}
    return Verdict(counts["third_party"] == 0, counts, confidence=0.5)


@REG.check(
    "android.design.locale_timezone",
    "identity.locale",
    name="Locale and time-zone configuration",
    description="Missing locale or an unset/UTC time zone can indicate a fresh image; UTC is also legitimate.",
    severity=Severity.LOW,
    remediation="Configure language and time zone consistently with the intended device region.",
)
def locale_timezone(dev: Device, ctx: RunContext):
    values = props(dev)
    locale = values.get("persist.sys.locale") or values.get("ro.product.locale")
    timezone = values.get("persist.sys.timezone")
    return Verdict(
        not locale or timezone in (None, "", "Etc/UTC", "GMT", "UTC"),
        {"locale": locale, "timezone": timezone},
        confidence=0.3,
    )


@REG.check(
    "android.design.install_source",
    "integrity.developer_settings",
    name="Target application install source",
    description="Installer package for an operator-selected application. Sideloading alone does not imply tampering.",
    severity=Severity.LOW,
    remediation="Install the test application through its intended distribution channel.",
)
def install_source(dev: Device, ctx: RunContext):
    package = ctx.params.get("android.package", "")
    if not re.fullmatch(r"[A-Za-z][\w]*(?:\.[A-Za-z][\w]*)+", package):
        raise Skip("requires --param android.package=<application id>")
    text = need(dev.sh(f"pm list packages -i {shell_quote(package)}"), "installer packages")
    match = re.search(rf"(?m)^package:{re.escape(package)}\s+installer=(\S+)", text)
    if not match:
        raise Skip("target application not found or installer unavailable")
    approved = ctx.params.get("android.approved_installers", "com.android.vending").split(",")
    return Verdict(match[1] not in approved, {"installer": match[1]}, confidence=0.5)


@REG.check(
    "android.design.hardware_keystore",
    "integrity.bootloader",
    name="Hardware keystore features",
    description="Declared StrongBox keystore feature; this does not request or verify Play Integrity attestation.",
    severity=Severity.INFO,
    remediation="Use a physical test device for hardware-backed integrity requirements.",
)
def keystore(dev: Device, ctx: RunContext):
    values = need(dev.features(), "features")
    present = "android.hardware.strongbox_keystore" in values
    return Verdict(not present, {"strongbox_declared": present}, confidence=0.2)


CHECKS = REG.specs
