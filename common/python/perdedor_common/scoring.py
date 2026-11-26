"""Unified scoring for PERDEDOR findings.

Two numbers are always reported side by side, deliberately mirroring the
CHIMERA KVM hardening report's own conclusion that a raw detection count
overstates or understates real risk depending on *which* checks fired:

- raw_score:      "clean/total" (VMAware-style headline number)
- weighted_score: 0-100, discounting each detection by its severity weight

Both are computed over "applicable" findings only -- i.e. status in
{clean, detected}. Findings with status "error" (probe couldn't run) or
"skipped" (not applicable on this host/build) are excluded from the score
itself but still counted in the summary so nothing is silently dropped.
"""

from __future__ import annotations

from collections.abc import Iterable

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
    report_reader stay plain dicts. Status and Severity are str enums, so their string values compare equal."""
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


class _View:
    __slots__ = ("status", "severity")

    def __init__(self, finding):
        self.status = _field(finding, "status")
        severity = _field(finding, "severity") or Severity.MEDIUM
        try:  # enum members hash by name, so a plain "low" would miss SEVERITY_WEIGHT
            self.severity = Severity(severity)
        except ValueError:
            self.severity = Severity.MEDIUM


def score_report(findings: Iterable[Finding]) -> dict:
    findings = [_View(f) for f in findings]
    total = len(findings)
    clean = sum(1 for f in findings if f.status == Status.CLEAN)
    detected = sum(1 for f in findings if f.status == Status.DETECTED)
    errored = sum(1 for f in findings if f.status == Status.ERROR)
    skipped = sum(1 for f in findings if f.status == Status.SKIPPED)

    applicable = clean + detected
    raw_score = f"{clean}/{applicable}" if applicable else "0/0"

    if applicable == 0:
        weighted_score = 100.0
    else:
        penalty = sum(SEVERITY_WEIGHT[f.severity] for f in findings if f.status == Status.DETECTED)
        # Normalise against the number of applicable checks so a suite with
        # more checks isn't automatically penalised harder for the same
        # proportion of failures.
        weighted_score = max(0.0, 100.0 * (1.0 - penalty / applicable))

    return {
        "total": total,
        "clean": clean,
        "detected": detected,
        "errored": errored,
        "skipped": skipped,
        "raw_score": raw_score,
        "weighted_score": round(weighted_score, 2),
    }
