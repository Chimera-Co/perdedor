from __future__ import annotations

from pathlib import Path

from perdedor_cli.__main__ import main
from perdedor_cli.selftest_cmd import (
    CaseResult,
    SelftestSummary,
    compare_checks,
    execute_selftest,
    render_table,
    resolve_native_agent,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PATH = REPO_ROOT / "tests" / "selftest" / "expected.json"


def test_compare_checks_all_pass():
    expected = {"check.a": "clean", "check.b": "detected"}
    actual = [
        {"id": "check.a", "status": "clean"},
        {"id": "check.b", "status": "detected"},
    ]
    passed, deviations = compare_checks(expected, actual, "test-case")
    assert passed == 2
    assert deviations == []


def test_compare_checks_deviation():
    expected = {"check.a": "clean", "check.b": "detected"}
    actual = [
        {"id": "check.a", "status": "clean"},
        {"id": "check.b", "status": "clean"},
    ]
    passed, deviations = compare_checks(expected, actual, "test-case")
    assert passed == 1
    assert len(deviations) == 1
    assert "check 'check.b' expected 'detected', got 'clean'" in deviations[0]


def test_compare_checks_missing_check():
    expected = {"check.a": "clean", "check.missing": "detected"}
    actual = [{"id": "check.a", "status": "clean"}]
    passed, deviations = compare_checks(expected, actual, "test-case")
    assert passed == 1
    assert len(deviations) == 1
    assert "missing check 'check.missing'" in deviations[0]


def test_execute_selftest_skipped_native_without_allow_skip():
    expected_doc = {
        "linux-detected": {
            "kind": "native",
            "root": "roots/linux-detected",
            "checks": {"linux.env.dmi_sys_vendor": "detected"},
        }
    }
    summary = execute_selftest(expected_doc, EXPECTED_PATH.parent, agent_path=None)
    assert summary.native_skipped
    assert summary.passed
    assert summary.exit_code == 2
    assert len(summary.results) == 1
    assert summary.results[0].status == "SKIPPED"


def test_execute_selftest_skipped_native_render_table():
    summary = SelftestSummary(
        results=[CaseResult(name="linux-detected", kind="native", status="SKIPPED")],
        native_skipped=True,
    )
    rendered = render_table(summary)
    assert "native Linux agent was not found" in rendered
    assert "SKIPPED" in rendered


def test_execute_selftest_report_band_deviation():
    # report-pass.json has score 100.0 (pass); expect 'fail' to trigger deviation
    expected_doc = {
        "rep-case": {
            "kind": "report",
            "file": "reports/report-pass.json",
            "score_band": "fail",
            "checks": {},
        }
    }
    summary = execute_selftest(expected_doc, EXPECTED_PATH.parent)
    assert not summary.passed
    assert summary.exit_code == 1
    assert any("score band expected 'fail', got 'pass'" in d for d in summary.deviations)


def test_execute_selftest_report_range_deviation():
    # report-pass.json has score 100.0; range [50.0, 80.0] will trigger deviation
    expected_doc = {
        "rep-case": {
            "kind": "report",
            "file": "reports/report-pass.json",
            "score_band": "pass",
            "score_range": [50.0, 80.0],
            "checks": {},
        }
    }
    summary = execute_selftest(expected_doc, EXPECTED_PATH.parent)
    assert not summary.passed
    assert summary.exit_code == 1
    assert any("score 100.0 out of expected range [50.0, 80.0]" in d for d in summary.deviations)


def test_selftest_cli_allow_skip_when_agent_missing(capsys):
    exit_code = main(["selftest", "--agent", "/nonexistent/perdedor-agent", "--allow-skip"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "SKIPPED" in captured.out
    assert "Note: native Linux agent was not found" in captured.out


def test_selftest_cli_exit_2_when_agent_missing_without_allow_skip(capsys):
    exit_code = main(["selftest", "--agent", "/nonexistent/perdedor-agent"])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "SKIPPED" in captured.out


def test_selftest_full_pass(capsys):
    agent = resolve_native_agent()
    cmd = ["selftest"]
    if agent:
        cmd.extend(["--agent", str(agent)])
    else:
        cmd.append("--allow-skip")

    exit_code = main(cmd)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "PASS" in captured.out
    assert "report-pass" in captured.out
    assert "report-warn" in captured.out
    assert "report-fail" in captured.out
