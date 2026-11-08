"""Shared data model for every PERDEDOR agent.

This module is the single source of truth for the report shape described in
schema/perdedor-report.schema.json. Windows, Linux, and Android agents that are
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
    MACOS = "macos"
    IOS = "ios"


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
    # v2 (optional): catalog technique key and class, how sure the agent is of
    # the status (0-1; timing statistics, partial reads), numeric measurements
    # behind the verdict, and how long the probe took.
    technique: str | None = None
    check_class: str | None = None
    confidence: float | None = None
    measurement: dict | None = None
    duration_ms: float | None = None

    def to_dict(self) -> dict:
        doc = {
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
        for key, value in (
            ("technique", self.technique),
            ("class", self.check_class),
            ("confidence", self.confidence),
            ("measurement", self.measurement),
            ("duration_ms", self.duration_ms),
        ):
            if value is not None:
                doc[key] = value
        return doc


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
    perdedor_version: str = "2.0.0"
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    agent_metadata: dict[str, str] = field(default_factory=dict)
    # v2: what the operator asked for (profile, only/skip patterns, params), so a
    # partial run is never mistaken for a full one when coverage is computed.
    selection: dict | None = None

    def to_dict(self) -> dict:
        from .scoring import score_report  # local import avoids a cycle

        doc = {
            "schema_version": 2,
            "perdedor_version": self.perdedor_version,
            "platform": self.platform.value,
            "hostname": self.hostname,
            "generated_at": self.generated_at.isoformat(),
            "agent_metadata": self.agent_metadata,
            "findings": [f.to_dict() for f in self.findings],
            "summary": score_report(self.findings),
        }
        if self.selection is not None:
            doc["selection"] = self.selection
        return doc

    @staticmethod
    def default_metadata() -> dict[str, str]:
        return {
            "os": _platform.system(),
            "os_release": _platform.release(),
            "machine": _platform.machine(),
        }
