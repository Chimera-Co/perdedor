"""Quality and regression gate for PERDEDOR reports.

Evaluates a target report against a baseline report or profile:
    perdedor gate <report> --baseline <report|profile> [--max-increase N] [--fail-on-new-class]

Returns a non-zero exit code with a short reason on failure.
Returns 0 on success. Never modifies any file or state.
"""

from __future__ import annotations

from typing import Any

from .compare import compare_reports
from .history import HistoryStore
from .report_reader import read_report


class GateResult:
    def __init__(self, passed: bool, reason: str, details: dict | None = None):
        self.passed = passed
        self.reason = reason
        self.details = details or {}

    @property
    def exit_code(self) -> int:
        return 0 if self.passed else 1


def evaluate_gate(
    target_report: Any,
    baseline_input: Any,
    *,
    max_increase: int | float | None = None,
    fail_on_new_class: bool = False,
    store: HistoryStore | None = None,
) -> GateResult:
    """Evaluate target report against baseline and return GateResult."""
    # Resolve target report
    target_doc = None
    if isinstance(target_report, dict):
        target_doc = target_report
    else:
        target_str = str(target_report)
        try:
            target_doc = read_report(target_str, validate=False)
        except Exception:
            if store:
                target_doc = store.get(target_str)

    if not target_doc:
        return GateResult(False, f"could not load target report: {target_report}")

    # Resolve baseline report
    baseline_doc = None
    if isinstance(baseline_input, dict):
        baseline_doc = baseline_input
    else:
        base_str = str(baseline_input)
        try:
            baseline_doc = read_report(base_str, validate=False)
        except Exception:
            pass

        if not baseline_doc and store:
            baseline_doc = store.get(base_str)

    if not baseline_doc:
        return GateResult(False, f"could not load baseline report for: {baseline_input}")

    # Compare
    diff = compare_reports(baseline_doc, target_doc)
    newly_firing = diff["newly_firing"]
    classes = diff["classes"]
    ov = diff["overall"]
    score_a = ov.get("score_a")
    score_b = ov.get("score_b")

    # 1. Check --fail-on-new-class
    if fail_on_new_class:
        for item in newly_firing:
            cls_name = item.get("class", "unknown")
            cls_info = classes.get(cls_name, {})
            # If baseline had 0 detections in this class
            if cls_info.get("detected_a", 0) == 0:
                return GateResult(
                    False,
                    f"new detection in previously clean class '{cls_name}' ({item['id']})",
                    details=diff,
                )

    # 2. Check --max-increase N
    if max_increase is not None:
        new_count = len(newly_firing)
        if new_count > max_increase:
            return GateResult(
                False,
                f"{new_count} newly firing check(s) exceed allowed maximum increase of {max_increase}",
                details=diff,
            )
    else:
        # Default regression rule: no newly firing checks allowed
        if newly_firing:
            first_ids = ", ".join(c["id"] for c in newly_firing[:3])
            more = f" (+{len(newly_firing) - 3} more)" if len(newly_firing) > 3 else ""
            return GateResult(
                False,
                f"{len(newly_firing)} check(s) newly firing: {first_ids}{more}",
                details=diff,
            )
        # Also check if exposure score decreased
        if score_a is not None and score_b is not None and score_b < score_a:
            return GateResult(
                False,
                f"exposure score decreased from {score_a:.1f} to {score_b:.1f}",
                details=diff,
            )

    # All checks passed
    sa_str = f"{score_a:.1f}" if score_a is not None else "n/a"
    sb_str = f"{score_b:.1f}" if score_b is not None else "n/a"
    return GateResult(
        True,
        f"passed: no regressions relative to baseline (score: {sa_str} -> {sb_str})",
        details=diff,
    )
