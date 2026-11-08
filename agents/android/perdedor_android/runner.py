from __future__ import annotations

from collections.abc import Sequence

from perdedor_common.discovery import discover
from perdedor_common.models import Platform, PlatformReport
from perdedor_common.registry import CheckSpec, RunContext, run_checks, select, selection_doc

from . import adb
from . import checks as _checks_pkg


def all_checks() -> list[CheckSpec]:
    return discover(_checks_pkg)


def run_scan(
    serial: str | None = None,
    *,
    profile: str = "standard",
    only: Sequence[str] = (),
    skip: Sequence[str] = (),
    params: dict[str, str] | None = None,
    network: bool = True,
) -> PlatformReport:
    params = dict(params or {})
    chosen = select(all_checks(), profile=profile, only=only, skip=skip, network=network)
    ctx = RunContext(platform=Platform.ANDROID, profile=profile, params=params, network=network, target=serial)
    findings = run_checks(chosen, ctx)

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
        selection=selection_doc(profile, only, skip, params, network),
    )
