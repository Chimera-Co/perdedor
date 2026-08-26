"""Boilerplate reducer for check modules.

Every check ends up constructing a Finding with the same category/platform
and one of four fixed status shapes. With dozens of checks per platform,
spelling out `Finding(id=..., category=..., platform=..., status=..., ...)`
each time is repetitive enough to become error-prone (easy to typo a status/
severity pairing). A FindingFactory is bound to one category+platform once,
then exposes one method per status.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Category, Finding, Platform, Severity, Status


@dataclass(frozen=True)
class FindingFactory:
    category: Category
    platform: Platform

    def clean(
        self, id: str, name: str, description: str, severity: Severity, evidence: Any = None
    ) -> Finding:
        return Finding(
            id=id,
            category=self.category,
            platform=self.platform,
            name=name,
            description=description,
            status=Status.CLEAN,
            severity=severity,
            evidence=evidence,
        )

    def detected(
        self,
        id: str,
        name: str,
        description: str,
        severity: Severity,
        evidence: Any = None,
        remediation: str | None = None,
    ) -> Finding:
        return Finding(
            id=id,
            category=self.category,
            platform=self.platform,
            name=name,
            description=description,
            status=Status.DETECTED,
            severity=severity,
            evidence=evidence,
            remediation=remediation,
        )

    def error(self, id: str, name: str, description: str, severity: Severity, detail: str) -> Finding:
        return Finding(
            id=id,
            category=self.category,
            platform=self.platform,
            name=name,
            description=description,
            status=Status.ERROR,
            severity=severity,
            error_detail=detail,
        )

    def skipped(self, id: str, name: str, description: str, severity: Severity, detail: str) -> Finding:
        return Finding(
            id=id,
            category=self.category,
            platform=self.platform,
            name=name,
            description=description,
            status=Status.SKIPPED,
            severity=severity,
            error_detail=detail,
        )

    def bool_check(
        self,
        id: str,
        name: str,
        description: str,
        severity: Severity,
        *,
        is_detected: bool,
        evidence: Any = None,
        remediation: str | None = None,
    ) -> Finding:
        """Convenience for the common "detected if condition else clean" shape."""
        if is_detected:
            return self.detected(id, name, description, severity, evidence=evidence, remediation=remediation)
        return self.clean(id, name, description, severity, evidence=evidence)
