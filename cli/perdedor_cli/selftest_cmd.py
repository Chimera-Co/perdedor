"""`perdedor selftest`: deterministic self-test suite for native agent and scoring.

Runs the native Linux agent against fake filesystem roots with known detected and
clean states, and scores recorded report fixtures with known score bands.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from perdedor_common.catalog import Catalog, load_catalog
from perdedor_common.exposure import assess

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_EXPECTED = _REPO_ROOT / "tests" / "selftest" / "expected.json"


@dataclass
class CaseResult:
    name: str
    kind: str
    total_checks: int = 0
    passed_checks: int = 0
    band: str | None = None
    score: float | None = None
    status: str = "PASS"  # PASS, FAIL, SKIPPED
    deviations: list[str] = field(default_factory=list)


@dataclass
class SelftestSummary:
    results: list[CaseResult] = field(default_factory=list)
    deviations: list[str] = field(default_factory=list)
    native_skipped: bool = False

    @property
    def passed(self) -> bool:
        return len(self.deviations) == 0

    @property
    def exit_code(self) -> int:
        if not self.passed:
            return 1
        if self.native_skipped:
            return 2
        return 0


def resolve_native_agent(explicit: str | None = None) -> Path | None:
    """Resolve the native agent binary to test."""
    if explicit:
        p = Path(explicit)
        return p if p.is_file() else None
    env = os.environ.get("PERDEDOR_AGENT")
    if env:
        p = Path(env)
        return p if p.is_file() else None
    from perdedor_common.host import TARGETS

    candidate = _REPO_ROOT / "native" / "build" / TARGETS["linux-x86_64"][1]
    return candidate if candidate.is_file() else None


def compare_checks(
    expected_checks: dict[str, str],
    actual_findings: list[dict[str, Any]],
    case_name: str,
) -> tuple[int, list[str]]:
    """Compare findings against expected check statuses.

    Returns (passed_checks_count, list_of_deviations).
    """
    actual_map = {f.get("id"): f.get("status") for f in actual_findings if isinstance(f, dict)}
    deviations: list[str] = []
    passed = 0

    for check_id, exp_status in expected_checks.items():
        if check_id not in actual_map:
            deviations.append(f"{case_name}: missing check '{check_id}'")
        elif actual_map[check_id] != exp_status:
            deviations.append(
                f"{case_name}: check '{check_id}' expected '{exp_status}', got '{actual_map[check_id]}'"
            )
        else:
            passed += 1

    return passed, deviations


def run_native_case(
    case_name: str,
    case_def: dict[str, Any],
    agent_path: Path,
    base_dir: Path,
) -> CaseResult:
    """Run native agent against a fake root and compare findings."""
    expected_checks = case_def.get("checks", {})
    root_rel = case_def.get("root", "")
    root_path = (base_dir / root_rel).resolve() if not Path(root_rel).is_absolute() else Path(root_rel)

    if not root_path.is_dir():
        dev = [f"{case_name}: root directory not found: {root_path}"]
        return CaseResult(
            name=case_name,
            kind="native",
            total_checks=len(expected_checks),
            passed_checks=0,
            status="FAIL",
            deviations=dev,
        )

    cmd = [
        str(agent_path),
        "--param",
        f"root={root_path}",
        "--no-network",
        "--only",
        *expected_checks.keys(),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        dev = [f"{case_name}: agent execution failed: {exc}"]
        return CaseResult(
            name=case_name,
            kind="native",
            total_checks=len(expected_checks),
            passed_checks=0,
            status="FAIL",
            deviations=dev,
        )

    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        dev = [f"{case_name}: invalid JSON output from agent: {exc}"]
        return CaseResult(
            name=case_name,
            kind="native",
            total_checks=len(expected_checks),
            passed_checks=0,
            status="FAIL",
            deviations=dev,
        )

    findings = report.get("findings", [])
    passed, deviations = compare_checks(expected_checks, findings, case_name)
    status = "PASS" if not deviations else "FAIL"

    return CaseResult(
        name=case_name,
        kind="native",
        total_checks=len(expected_checks),
        passed_checks=passed,
        status=status,
        deviations=deviations,
    )


def run_report_case(
    case_name: str,
    case_def: dict[str, Any],
    base_dir: Path,
    catalog: Catalog,
) -> CaseResult:
    """Load a report fixture, verify checks, and verify score band and range."""
    expected_checks = case_def.get("checks", {})
    file_rel = case_def.get("file", "")
    report_path = (base_dir / file_rel).resolve() if not Path(file_rel).is_absolute() else Path(file_rel)

    if not report_path.is_file():
        dev = [f"{case_name}: report fixture not found: {report_path}"]
        return CaseResult(
            name=case_name,
            kind="report",
            total_checks=len(expected_checks),
            passed_checks=0,
            status="FAIL",
            deviations=dev,
        )

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        dev = [f"{case_name}: cannot read report fixture: {exc}"]
        return CaseResult(
            name=case_name,
            kind="report",
            total_checks=len(expected_checks),
            passed_checks=0,
            status="FAIL",
            deviations=dev,
        )

    findings = report.get("findings", [])
    passed, deviations = compare_checks(expected_checks, findings, case_name)

    platform = report.get("platform", "linux")
    assessment = assess(findings, platform, catalog)
    actual_score = assessment.get("score")
    actual_band = assessment.get("verdict")

    exp_band = case_def.get("score_band")
    if exp_band and actual_band != exp_band:
        deviations.append(f"{case_name}: score band expected '{exp_band}', got '{actual_band}'")

    exp_range = case_def.get("score_range")
    if exp_range and len(exp_range) == 2:
        min_s, max_s = exp_range[0], exp_range[1]
        if actual_score is None or not (min_s <= actual_score <= max_s):
            deviations.append(f"{case_name}: score {actual_score} out of expected range [{min_s}, {max_s}]")

    status = "PASS" if not deviations else "FAIL"
    return CaseResult(
        name=case_name,
        kind="report",
        total_checks=len(expected_checks),
        passed_checks=passed,
        band=actual_band,
        score=actual_score,
        status=status,
        deviations=deviations,
    )


def execute_selftest(
    expected_doc: dict[str, Any],
    base_dir: Path,
    agent_path: Path | None = None,
    catalog: Catalog | None = None,
) -> SelftestSummary:
    """Execute all self-test cases defined in expected_doc."""
    if catalog is None:
        catalog = load_catalog()

    summary = SelftestSummary()
    native_available = agent_path is not None and agent_path.is_file()

    for case_name, case_def in expected_doc.items():
        if not isinstance(case_def, dict):
            continue
        kind = case_def.get("kind", "report" if "file" in case_def else "native")

        if kind == "native":
            if not native_available:
                summary.native_skipped = True
                summary.results.append(
                    CaseResult(
                        name=case_name,
                        kind="native",
                        total_checks=len(case_def.get("checks", {})),
                        status="SKIPPED",
                    )
                )
            else:
                assert agent_path is not None
                res = run_native_case(case_name, case_def, agent_path, base_dir)
                summary.results.append(res)
                summary.deviations.extend(res.deviations)
        elif kind == "report":
            res = run_report_case(case_name, case_def, base_dir, catalog)
            summary.results.append(res)
            summary.deviations.extend(res.deviations)

    return summary


def render_table(summary: SelftestSummary) -> str:
    """Format a summary table for human reading."""
    lines = [
        f"{'Case':<18} {'Type':<8} {'Checks':<10} {'Band':<6} {'Score':<8} {'Result'}",
        "-" * 58,
    ]
    for r in summary.results:
        checks_str = f"{r.passed_checks}/{r.total_checks}" if r.total_checks else "-"
        band_str = r.band or "-"
        score_str = f"{r.score:.1f}" if r.score is not None else "-"
        lines.append(f"{r.name:<18} {r.kind:<8} {checks_str:<10} {band_str:<6} {score_str:<8} {r.status}")

    if summary.native_skipped:
        lines.append("")
        lines.append("Note: native Linux agent was not found (native self-test skipped).")

    if summary.deviations:
        lines.append("")
        lines.append(f"Deviations ({len(summary.deviations)}):")
        for dev in summary.deviations:
            lines.append(f"  * {dev}")

    return "\n".join(lines)


def _cmd_selftest(args: argparse.Namespace) -> int:
    expected_path = Path(args.expected) if args.expected else _DEFAULT_EXPECTED
    if not expected_path.is_file():
        print(f"error: expected.json not found: {expected_path}", file=sys.stderr)
        return 1

    try:
        expected_doc = json.loads(expected_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: failed to read {expected_path}: {exc}", file=sys.stderr)
        return 1

    agent_path = resolve_native_agent(args.agent)
    summary = execute_selftest(expected_doc, expected_path.parent, agent_path=agent_path)

    print(render_table(summary))

    if not summary.passed:
        return 1
    if summary.native_skipped:
        return 0 if args.allow_skip else 2
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "selftest",
        help="run deterministic self-test suite (native agent fake roots + scoring fixtures)",
    )
    parser.add_argument(
        "--agent",
        default=None,
        help="path to native Linux agent binary (defaults to native/build/perdedor-linux-x86_64)",
    )
    parser.add_argument(
        "--expected",
        default=None,
        help="path to expected.json (defaults to tests/selftest/expected.json)",
    )
    parser.add_argument(
        "--allow-skip",
        action="store_true",
        help="exit 0 instead of 2 when native agent binary is not available",
    )
    parser.set_defaults(func=_cmd_selftest)
