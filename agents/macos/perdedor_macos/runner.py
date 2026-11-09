from __future__ import annotations

from collections.abc import Sequence

from perdedor_common.discovery import discover
from perdedor_common.models import Platform, PlatformReport
from perdedor_common.registry import CheckSpec, RunContext, run_checks, select, selection_doc

from . import checks as _checks_pkg
from .target import Target


def all_checks() -> list[CheckSpec]:
    return discover(_checks_pkg)


def collect_metadata(target: Target) -> dict[str, str]:
    metadata = dict(target.describe())
    values = target.sysctl() or {}
    for key, name in (
        ("hw.model", "hw_model"),
        ("kern.osproductversion", "os_version"),
        ("kern.osversion", "os_build"),
        ("hw.machine", "machine"),
    ):
        if values.get(key):
            metadata[name] = values[key]
    if not target.reachable():
        metadata["reachable"] = "false"
    return metadata


def run_scan(
    target: Target,
    *,
    profile: str = "standard",
    only: Sequence[str] = (),
    skip: Sequence[str] = (),
    params: dict[str, str] | None = None,
    network: bool = True,
) -> PlatformReport:
    params = dict(params or {})
    chosen = select(all_checks(), profile=profile, only=only, skip=skip, network=network)
    ctx = RunContext(platform=Platform.MACOS, profile=profile, params=params, network=network, target=target)
    findings = run_checks(chosen, ctx)
    target.deadline = None
    target.transport.deadline = None
    metadata = collect_metadata(target)
    hostname = (target.sysctl() or {}).get("kern.hostname")
    extra = {"hostname": hostname} if hostname else {}
    return PlatformReport(
        platform=Platform.MACOS,
        findings=tuple(findings),
        agent_metadata=metadata,
        selection=selection_doc(profile, only, skip, params, network),
        **extra,
    )
