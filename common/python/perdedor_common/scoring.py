"""Unified scoring for PERDEDOR findings.

Two numbers are always reported side by side, deliberately mirroring the
CHIMERA KVM hardening report's own conclusion that a raw detection count
overstates or understates real risk depending on *which* checks fired:

- raw_score:      "clean/total" (VMAware-style headline number)
- weighted_score: 0-100, discounting each detection by its severity weight

When a bare-metal baseline is supplied, net scores leaving out checks that
fire naturally on bare metal are also provided (net_raw_score, net_weighted_score).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .models import Finding, Severity, Status

SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.05,
    Severity.LOW: 0.15,
    Severity.MEDIUM: 0.35,
    Severity.HIGH: 0.65,
    Severity.CRITICAL: 1.0,
}


def _field(finding, name: str, default=None):
    """A Finding's attribute, or the same key of a finding read from JSON (a dict): reports read with
    report_reader stay plain dicts. Status and Severity are str enums, so their string values compare equal.
    """
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


class _View:
    __slots__ = ("id", "status", "severity")

    def __init__(self, finding):
        self.id = _field(finding, "id", "")
        self.status = _field(finding, "status")
        severity = _field(finding, "severity") or Severity.MEDIUM
        try:  # enum members hash by name, so a plain "low" would miss SEVERITY_WEIGHT
            self.severity = Severity(severity)
        except ValueError:
            self.severity = Severity.MEDIUM


def score_report(findings: Iterable[Finding], baseline: dict[str, Any] | None = None) -> dict:
    views = [_View(f) for f in findings]
    total = len(views)
    clean = sum(1 for f in views if f.status == Status.CLEAN)
    detected = sum(1 for f in views if f.status == Status.DETECTED)
    errored = sum(1 for f in views if f.status == Status.ERROR)
    skipped = sum(1 for f in views if f.status == Status.SKIPPED)

    applicable = clean + detected
    raw_score = f"{clean}/{applicable}" if applicable else "0/0"

    if applicable == 0:
        weighted_score = 100.0
    else:
        penalty = sum(SEVERITY_WEIGHT[f.severity] for f in views if f.status == Status.DETECTED)
        weighted_score = max(0.0, 100.0 * (1.0 - penalty / applicable))

    out: dict[str, Any] = {
        "total": total,
        "clean": clean,
        "detected": detected,
        "errored": errored,
        "skipped": skipped,
        "raw_score": raw_score,
        "weighted_score": round(weighted_score, 2),
    }

    if baseline is not None:
        checks = baseline.get("checks", {})
        fired_ids = set(checks.keys()) if isinstance(checks, dict) else set(checks)
        clean_net = sum(
            1
            for f in views
            if f.status == Status.CLEAN or (f.status == Status.DETECTED and f.id in fired_ids)
        )
        detected_net = sum(1 for f in views if f.status == Status.DETECTED and f.id not in fired_ids)
        applicable_net = clean_net + detected_net
        net_raw_score = f"{clean_net}/{applicable_net}" if applicable_net else "0/0"
        if applicable_net == 0:
            net_weighted_score = 100.0
        else:
            net_penalty = sum(
                SEVERITY_WEIGHT[f.severity]
                for f in views
                if f.status == Status.DETECTED and f.id not in fired_ids
            )
            net_weighted_score = max(0.0, 100.0 * (1.0 - net_penalty / applicable_net))
        out["net_raw_score"] = net_raw_score
        out["net_weighted_score"] = round(net_weighted_score, 2)
    else:
        out["net_raw_score"] = "no baseline"
        out["net_weighted_score"] = "no baseline"

    return out
