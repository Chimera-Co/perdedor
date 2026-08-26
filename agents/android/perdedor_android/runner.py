from __future__ import annotations

from perdedor_common.models import Finding, Platform, PlatformReport

from . import adb
from .checks import CHECK_MODULES


def run_scan(serial: str | None = None) -> PlatformReport:
    findings: list[Finding] = []
    for module in CHECK_MODULES:
        findings.extend(module.run_all(serial))

    metadata = {"adb_serial": serial or "(default device)"}
    if adb.device_reachable(serial):
        model = adb.getprop(serial, "ro.product.model")
        android_version = adb.getprop(serial, "ro.build.version.release")
        if model:
            metadata["device_model"] = model
        if android_version:
            metadata["android_version"] = android_version

    return PlatformReport(
        platform=Platform.ANDROID,
        findings=tuple(findings),
        agent_metadata=metadata,
    )
