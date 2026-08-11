"""Minimal, dependency-free validation of a parsed HYDRA report dict against
schema/hydra-report.schema.json.

Deliberately does not depend on the `jsonschema` PyPI package: HYDRA agents
are meant to run inside isolated, disposable sandbox overlays with no
guaranteed internet/package-index access (see CHIMERA Ch.4, network
isolation architecture), so the common package stays stdlib-only.
"""

from __future__ import annotations

_REQUIRED_TOP = {"hydra_version", "platform", "hostname", "generated_at", "findings", "summary"}
_PLATFORMS = {"windows", "linux", "android"}
_CATEGORIES = {"environment_artifact", "timing", "behavioural_interaction", "design_specific"}
_STATUSES = {"clean", "detected", "error", "skipped"}
_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_REQUIRED_FINDING = {"id", "category", "platform", "name", "description", "status", "severity"}
_REQUIRED_SUMMARY = {"total", "clean", "detected", "errored", "skipped", "raw_score", "weighted_score"}


class ValidationError(ValueError):
    pass


def validate_report(report: dict, *, source: str = "<report>") -> None:
    """Raise ValidationError with a precise message on the first problem found."""
    if not isinstance(report, dict):
        raise ValidationError(f"{source}: top-level report must be an object")

    missing = _REQUIRED_TOP - report.keys()
    if missing:
        raise ValidationError(f"{source}: missing required top-level field(s): {sorted(missing)}")

    if report["platform"] not in _PLATFORMS:
        raise ValidationError(f"{source}: platform '{report['platform']}' not in {_PLATFORMS}")

    findings = report["findings"]
    if not isinstance(findings, list):
        raise ValidationError(f"{source}: 'findings' must be a list")

    for i, finding in enumerate(findings):
        _validate_finding(finding, source=f"{source}.findings[{i}]")

    _validate_summary(report["summary"], source=f"{source}.summary")


def _validate_finding(finding: dict, *, source: str) -> None:
    if not isinstance(finding, dict):
        raise ValidationError(f"{source}: finding must be an object")
    missing = _REQUIRED_FINDING - finding.keys()
    if missing:
        raise ValidationError(f"{source}: missing required field(s): {sorted(missing)}")
    if finding["category"] not in _CATEGORIES:
        raise ValidationError(f"{source}: category '{finding['category']}' not in {_CATEGORIES}")
    if finding["platform"] not in _PLATFORMS:
        raise ValidationError(f"{source}: platform '{finding['platform']}' not in {_PLATFORMS}")
    if finding["status"] not in _STATUSES:
        raise ValidationError(f"{source}: status '{finding['status']}' not in {_STATUSES}")
    if finding["severity"] not in _SEVERITIES:
        raise ValidationError(f"{source}: severity '{finding['severity']}' not in {_SEVERITIES}")
    if finding["status"] == "error" and not finding.get("error_detail"):
        raise ValidationError(f"{source}: status is 'error' but 'error_detail' is empty")


def _validate_summary(summary: dict, *, source: str) -> None:
    if not isinstance(summary, dict):
        raise ValidationError(f"{source}: summary must be an object")
    missing = _REQUIRED_SUMMARY - summary.keys()
    if missing:
        raise ValidationError(f"{source}: missing required field(s): {sorted(missing)}")
    counted = summary["clean"] + summary["detected"] + summary["errored"] + summary["skipped"]
    if counted != summary["total"]:
        raise ValidationError(
            f"{source}: clean+detected+errored+skipped ({counted}) != total ({summary['total']})"
        )
