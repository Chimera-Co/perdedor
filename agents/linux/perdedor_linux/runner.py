from __future__ import annotations

from collections.abc import Sequence

from perdedor_common.discovery import discover
from perdedor_common.models import Platform, PlatformReport
from perdedor_common.registry import CheckSpec, RunContext, run_checks, select, selection_doc

from . import checks as _checks_pkg


def all_checks() -> list[CheckSpec]:
    return discover(_checks_pkg)


def run_scan(
    *,
    profile: str = "standard",
    only: Sequence[str] = (),
    skip: Sequence[str] = (),
    params: dict[str, str] | None = None,
    network: bool = True,
) -> PlatformReport:
    params = dict(params or {})
    chosen = select(all_checks(), profile=profile, only=only, skip=skip, network=network)
    ctx = RunContext(platform=Platform.LINUX, profile=profile, params=params, network=network)
    return PlatformReport(
        platform=Platform.LINUX,
        findings=tuple(run_checks(chosen, ctx)),
        agent_metadata=PlatformReport.default_metadata(),
        selection=selection_doc(profile, only, skip, params, network),
    )
