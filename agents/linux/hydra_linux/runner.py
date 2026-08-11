from __future__ import annotations

from hydra_common.models import Finding, Platform, PlatformReport

from .checks import CHECK_MODULES


def run_scan() -> PlatformReport:
    findings: list[Finding] = []
    for module in CHECK_MODULES:
        findings.extend(module.run_all())
    return PlatformReport(
        platform=Platform.LINUX,
        findings=tuple(findings),
        agent_metadata=PlatformReport.default_metadata(),
    )
