from __future__ import annotations

import json

import pytest
from perdedor_common.finding_factory import FindingFactory
from perdedor_common.models import Category, Finding, Platform, PlatformReport, Severity, Status
from perdedor_common.report import aggregate_reports, render_html
from perdedor_common.scoring import score_report
from perdedor_common.text_format import render_banner
from perdedor_common.validation import ValidationError, validate_report


def _finding(status: Status, severity: Severity = Severity.MEDIUM, n: int = 0) -> Finding:
    return Finding(
        id=f"test.env.check_{n}",
        category=Category.ENVIRONMENT_ARTIFACT,
        platform=Platform.LINUX,
        name=f"Check {n}",
        description="A test check.",
        status=status,
        severity=severity,
    )


def test_score_report_all_clean_is_perfect() -> None:
    findings = [_finding(Status.CLEAN, n=i) for i in range(5)]
    summary = score_report(findings)
    assert summary["raw_score"] == "5/5"
    assert summary["weighted_score"] == 100.0
    assert summary["total"] == 5


def test_score_report_weights_by_severity() -> None:
    critical = [_finding(Status.DETECTED, Severity.CRITICAL, n=0)]
    low = [_finding(Status.DETECTED, Severity.LOW, n=0)]
    critical_score = score_report(critical + [_finding(Status.CLEAN, n=1)])
    low_score = score_report(low + [_finding(Status.CLEAN, n=1)])
    assert critical_score["weighted_score"] < low_score["weighted_score"]


def test_score_report_excludes_error_and_skipped_from_applicable() -> None:
    findings = [
        _finding(Status.CLEAN, n=0),
        _finding(Status.ERROR, n=1),
        _finding(Status.SKIPPED, n=2),
    ]
    summary = score_report(findings)
    assert summary["raw_score"] == "1/1"
    assert summary["total"] == 3
    assert summary["errored"] == 1
    assert summary["skipped"] == 1


def test_score_report_empty_is_perfect_not_divide_by_zero() -> None:
    summary = score_report([])
    assert summary["weighted_score"] == 100.0
    assert summary["raw_score"] == "0/0"


def test_platform_report_to_dict_round_trips_through_schema_shape() -> None:
    findings = (_finding(Status.CLEAN, n=0), _finding(Status.DETECTED, Severity.HIGH, n=1))
    report = PlatformReport(platform=Platform.LINUX, findings=findings, hostname="test-host")
    d = report.to_dict()
    validate_report(d)  # should not raise
    assert d["platform"] == "linux"
    assert d["summary"]["detected"] == 1
    assert json.dumps(d)  # must be JSON-serialisable


def test_validate_report_rejects_missing_field() -> None:
    findings = (_finding(Status.CLEAN, n=0),)
    d = PlatformReport(platform=Platform.LINUX, findings=findings).to_dict()
    del d["hostname"]
    with pytest.raises(ValidationError):
        validate_report(d)


def test_validate_report_rejects_error_without_detail() -> None:
    findings = (_finding(Status.CLEAN, n=0),)
    d = PlatformReport(platform=Platform.LINUX, findings=findings).to_dict()
    d["findings"][0]["status"] = "error"
    d["findings"][0]["error_detail"] = None
    with pytest.raises(ValidationError):
        validate_report(d)


def test_aggregate_reports_combines_platforms() -> None:
    linux = PlatformReport(
        platform=Platform.LINUX,
        findings=(_finding(Status.CLEAN, n=0), _finding(Status.DETECTED, Severity.LOW, n=1)),
    ).to_dict()
    windows_finding = Finding(
        id="win.env.check_0",
        category=Category.ENVIRONMENT_ARTIFACT,
        platform=Platform.WINDOWS,
        name="Check",
        description="desc",
        status=Status.CLEAN,
        severity=Severity.MEDIUM,
    )
    windows = PlatformReport(platform=Platform.WINDOWS, findings=(windows_finding,)).to_dict()

    aggregate = aggregate_reports([linux, windows])
    assert set(aggregate["platforms"]) == {"linux", "windows"}
    assert aggregate["overall_summary"]["total"] == 3
    assert aggregate["overall_summary"]["clean"] == 2
    assert aggregate["overall_summary"]["detected"] == 1

    html_out = render_html(aggregate)
    assert "PERDEDOR Unified Evasion-Probe Report" in html_out
    assert "Linux" in html_out and "Windows" in html_out


def test_aggregate_reports_validates_inputs_by_default() -> None:
    with pytest.raises(ValidationError):
        aggregate_reports([{"platform": "linux"}])


def test_finding_factory_binds_category_and_platform() -> None:
    factory = FindingFactory(category=Category.TIMING, platform=Platform.WINDOWS)
    finding = factory.clean("win.timing.x", "X", "desc", Severity.LOW)
    assert finding.category == Category.TIMING
    assert finding.platform == Platform.WINDOWS
    assert finding.status == Status.CLEAN


def test_finding_factory_error_and_skipped_carry_detail_not_evidence() -> None:
    factory = FindingFactory(category=Category.ENVIRONMENT_ARTIFACT, platform=Platform.LINUX)
    error = factory.error("id", "name", "desc", Severity.MEDIUM, "boom")
    skipped = factory.skipped("id", "name", "desc", Severity.MEDIUM, "not applicable")
    assert error.status == Status.ERROR
    assert error.error_detail == "boom"
    assert error.evidence is None
    assert skipped.status == Status.SKIPPED
    assert skipped.error_detail == "not applicable"


def test_finding_factory_bool_check_switches_between_detected_and_clean() -> None:
    factory = FindingFactory(category=Category.DESIGN_SPECIFIC, platform=Platform.ANDROID)
    detected = factory.bool_check("id", "name", "desc", Severity.HIGH, is_detected=True, evidence="hit")
    clean = factory.bool_check("id", "name", "desc", Severity.HIGH, is_detected=False, evidence="hit")
    assert detected.status == Status.DETECTED
    assert detected.evidence == "hit"
    assert clean.status == Status.CLEAN


def test_render_banner_contains_wordmark_and_version() -> None:
    banner = render_banner(use_color=False, version="9.9.9")
    assert "v9.9.9" in banner
    assert "Sandbox-Evasion Self-Test Suite" in banner


def test_render_banner_no_color_emits_no_escape_codes() -> None:
    banner = render_banner(use_color=False)
    assert "\033[" not in banner


def test_render_banner_color_emits_escape_codes() -> None:
    banner = render_banner(use_color=True)
    assert "\033[" in banner
