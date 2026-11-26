from __future__ import annotations

from pathlib import Path

import pytest
from perdedor_android.runner import run_scan as android_run_scan
from perdedor_common.validation import ValidationError, validate_report
from perdedor_ios.device import IosTarget
from perdedor_ios.runner import run_scan as ios_run_scan
from perdedor_macos.runner import run_scan as macos_run_scan
from perdedor_macos.target import Target as MacTarget
from perdedor_macos.transport import FakeTransport

TESTS_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = TESTS_DIR / "fixtures"


@pytest.mark.parametrize(
    "fixture_path",
    sorted((FIXTURES_DIR / "macos").glob("*.json")),
    ids=lambda p: p.stem,
)
def test_macos_fixtures_produce_schema_valid_reports(fixture_path: Path):
    fake = FakeTransport.from_fixture(fixture_path)
    report = macos_run_scan(MacTarget(fake), network=False).to_dict()
    validate_report(report)
    assert report["schema_version"] == 3
    assert "scan_id" in report
    assert "host_facts" in report
    assert "environment" in report


@pytest.mark.parametrize(
    "fixture_path",
    sorted((FIXTURES_DIR / "ios").glob("*.json")),
    ids=lambda p: p.stem,
)
def test_ios_fixtures_produce_schema_valid_reports(fixture_path: Path):
    fake = FakeTransport.from_fixture(fixture_path)
    report = ios_run_scan(IosTarget(fake), network=False).to_dict()
    validate_report(report)
    assert report["schema_version"] == 3
    assert "scan_id" in report
    assert "host_facts" in report
    assert "environment" in report


@pytest.mark.parametrize(
    "fixture_path",
    sorted((FIXTURES_DIR / "android").glob("*.json")),
    ids=lambda p: p.stem,
)
def test_android_fixtures_produce_schema_valid_reports(fixture_path: Path):
    from test_android_agent import FakeAdb

    profile_name = fixture_path.stem
    adb = FakeAdb(profile=profile_name)
    report = android_run_scan(adb, network=False).to_dict()
    validate_report(report)
    assert report["schema_version"] == 3
    assert "scan_id" in report
    assert "host_facts" in report
    assert "environment" in report


def test_schema_rejects_invalid_values():
    valid = {
        "schema_version": 3,
        "perdedor_version": "2.0.1",
        "platform": "linux",
        "hostname": "h",
        "generated_at": "2026-01-01T00:00:00Z",
        "findings": [],
        "summary": {
            "total": 0,
            "clean": 0,
            "detected": 0,
            "errored": 0,
            "skipped": 0,
            "raw_score": "0/0",
            "weighted_score": 100.0,
        },
    }
    validate_report(valid)

    # Bad schema_version
    bad_ver = dict(valid, schema_version=4)
    with pytest.raises(ValidationError):
        validate_report(bad_ver)

    # Bad platform
    bad_plat = dict(valid, platform="solaris")
    with pytest.raises(ValidationError):
        validate_report(bad_plat)

    # Bad core_count (< 1)
    bad_cores = dict(valid, host_facts={"core_count": 0})
    with pytest.raises(ValidationError):
        validate_report(bad_cores)

    # Bad monitor
    bad_mon = dict(valid, environment={"monitor": "invalid-monitor"})
    with pytest.raises(ValidationError):
        validate_report(bad_mon)
