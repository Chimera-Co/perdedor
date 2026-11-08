from __future__ import annotations

from collections.abc import Sequence

from perdedor_common.discovery import discover
from perdedor_common.models import Platform, PlatformReport
from perdedor_common.registry import CheckSpec, RunContext, run_checks, select, selection_doc

from . import checks as _checks_pkg
from .device import IosTarget


def all_checks() -> list[CheckSpec]:
    return discover(_checks_pkg)


def run_scan(
    target: IosTarget,
    *,
    profile: str = "standard",
    only: Sequence[str] = (),
    skip: Sequence[str] = (),
    params: dict[str, str] | None = None,
    network: bool = True,
) -> PlatformReport:
    params = dict(params or {})
    chosen = select(all_checks(), profile=profile, only=only, skip=skip, network=network)
    ctx = RunContext(platform=Platform.IOS, profile=profile, params=params, network=network, target=target)
    findings = run_checks(chosen, ctx)
    target.deadline = None
    target.transport.deadline = None
    metadata = dict(target.describe())
    metadata["mode"] = target.mode
    values = target.sysctl() or {}
    for key, name in (("hw.machine", "machine"), ("hw.model", "hw_model"), ("kern.osversion", "os_build")):
        if values.get(key):
            metadata[name] = values[key]
    extra = {"hostname": values["kern.hostname"]} if values.get("kern.hostname") else {}
    return PlatformReport(
        platform=Platform.IOS,
        findings=tuple(findings),
        agent_metadata=metadata,
        selection=selection_doc(profile, only, skip, params, network),
        **extra,
    )
