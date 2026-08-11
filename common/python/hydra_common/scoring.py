"""Unified scoring for HYDRA findings.

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


def score_report(findings: Iterable[Finding]) -> dict:
    findings = list(findings)
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
