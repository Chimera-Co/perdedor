"""Shared data model for every HYDRA agent.

This module is the single source of truth for the report shape described in
schema/hydra-report.schema.json. Windows, Linux, and Android agents that are
written in Python import this directly; the PowerShell agent emits matching
JSON by hand (see agents/windows/README.md) since it cannot import Python.
"""

from __future__ import annotations

import platform as _platform
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Category(str, Enum):
    ENVIRONMENT_ARTIFACT = "environment_artifact"
    TIMING = "timing"
    BEHAVIOURAL_INTERACTION = "behavioural_interaction"
    DESIGN_SPECIFIC = "design_specific"


class Platform(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    ANDROID = "android"


class Status(str, Enum):
    CLEAN = "clean"
    DETECTED = "detected"
    ERROR = "error"
    SKIPPED = "skipped"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    id: str
    category: Category
    platform: Platform
    name: str
    description: str
    status: Status
    severity: Severity
    evidence: Any = None
    remediation: str | None = None
    error_detail: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category.value,
            "platform": self.platform.value,
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "error_detail": self.error_detail,
        }


@dataclass(frozen=True)
class PlatformReport:
    """Immutable snapshot of a completed scan.

    Agents collect findings in a plain list while probes run, then construct
    exactly one PlatformReport at the end -- there is no in-place mutator by
    design, so a report can never be observed half-built.
    """

    platform: Platform
    findings: tuple[Finding, ...]
    hostname: str = field(default_factory=socket.gethostname)
    hydra_version: str = "0.1.0"
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    agent_metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        from .scoring import score_report  # local import avoids a cycle

        return {
            "hydra_version": self.hydra_version,
            "platform": self.platform.value,
            "hostname": self.hostname,
            "generated_at": self.generated_at.isoformat(),
            "agent_metadata": self.agent_metadata,
            "findings": [f.to_dict() for f in self.findings],
            "summary": score_report(self.findings),
        }

    @staticmethod
    def default_metadata() -> dict[str, str]:
        return {
            "os": _platform.system(),
            "os_release": _platform.release(),
            "machine": _platform.machine(),
        }
