from __future__ import annotations

import json
from pathlib import Path

import pytest
from perdedor_cli.__main__ import main
from perdedor_common.compare import compare_reports


def _make_report(findings: list[dict], scan_id: str = "test-id", platform: str = "linux") -> dict:
    clean_n = sum(1 for f in findings if f.get("status") == "clean")
    det_n = sum(1 for f in findings if f.get("status") == "detected")
    tot = len(findings)
    app = clean_n + det_n
    return {
        "schema_version": 3,
        "scan_id": scan_id,
        "perdedor_version": "2.0.1",
        "agent_version": "2.0.1",
        "catalog_version": "2.0.1",
        "platform": platform,
        "hostname": "host",
        "generated_at": "2026-11-26T12:00:00Z",
        "selection": {"profile": "standard"},
        "findings": findings,
        "summary": {
            "total": tot,
            "clean": clean_n,
            "detected": det_n,
            "errored": 0,
            "skipped": 0,
            "raw_score": f"{clean_n}/{app}" if app else "0/0",
            "weighted_score": 100.0 if not det_n else 50.0,
        },
    }


def test_compare_reports_logic():
    f_a = [
        {
            "id": "linux.env.cpuid_hypervisor_bit",
            "name": "Hypervisor bit",
            "status": "clean",
            "severity": "critical",
            "technique": "cpu.hypervisor_bit",
            "class": "cpu",
            "category": "environment_artifact",
        },
        {
            "id": "linux.env.cpuid_hypervisor_vendor",
            "name": "Hypervisor vendor",
            "status": "detected",
            "severity": "critical",
            "technique": "cpu.hypervisor_vendor_leaf",
            "class": "cpu",
            "category": "environment_artifact",
            "evidence": "KVMKVMKVM",
        },
        {
            "id": "linux.timing.cpuid_vmexit",
            "name": "CPUID VM-exit cost",
            "status": "clean",
            "severity": "medium",
            "technique": "timing.cpuid_vmexit",
            "class": "timing",
            "category": "timing",
            "measurement": {"cycles": 1200},
            "confidence": 0.8,
        },
    ]

    f_b = [
        {
            "id": "linux.env.cpuid_hypervisor_bit",
            "name": "Hypervisor bit",
            "status": "detected",  # newly firing!
            "severity": "critical",
            "technique": "cpu.hypervisor_bit",
            "class": "cpu",
            "category": "environment_artifact",
            "evidence": "present",
        },
        {
            "id": "linux.env.cpuid_hypervisor_vendor",
            "name": "Hypervisor vendor",
            "status": "clean",  # stopped firing!
            "severity": "critical",
            "technique": "cpu.hypervisor_vendor_leaf",
            "class": "cpu",
            "category": "environment_artifact",
        },
        {
            "id": "linux.timing.cpuid_vmexit",
            "name": "CPUID VM-exit cost",
            "status": "clean",  # changed measurement!
            "severity": "medium",
            "technique": "timing.cpuid_vmexit",
            "class": "timing",
            "category": "timing",
            "measurement": {"cycles": 850},
            "confidence": 0.95,
        },
    ]

    rep_a = _make_report(f_a, scan_id="scan-a")
    rep_b = _make_report(f_b, scan_id="scan-b")

    diff = compare_reports(rep_a, rep_b)

    assert len(diff["newly_firing"]) == 1
    assert diff["newly_firing"][0]["id"] == "linux.env.cpuid_hypervisor_bit"

    assert len(diff["stopped_firing"]) == 1
    assert diff["stopped_firing"][0]["id"] == "linux.env.cpuid_hypervisor_vendor"

    assert len(diff["changed_measurement"]) == 1
    assert diff["changed_measurement"][0]["id"] == "linux.timing.cpuid_vmexit"

    # Score deltas
    ov = diff["overall"]
    assert ov["net_delta"] == "net: no baseline"

    # Categories
    assert "environment_artifact" in diff["categories"]
    assert diff["categories"]["environment_artifact"]["net_delta"] == "net: no baseline"

    # Classes
    assert "cpu" in diff["classes"]
    assert diff["classes"]["cpu"]["net_delta"] == "net: no baseline"


def test_cli_compare(tmp_path: Path, capsys):
    f_a = [
        {
            "id": "linux.env.check1",
            "name": "C1",
            "status": "clean",
            "severity": "high",
            "technique": "cpu.hypervisor_bit",
            "class": "cpu",
            "category": "environment_artifact",
        }
    ]
    f_b = [
        {
            "id": "linux.env.check1",
            "name": "C1",
            "status": "detected",
            "severity": "high",
            "technique": "cpu.hypervisor_bit",
            "class": "cpu",
            "category": "environment_artifact",
        }
    ]

    file_a = tmp_path / "a.json"
    file_b = tmp_path / "b.json"
    file_a.write_text(json.dumps(_make_report(f_a, "scan-a")), encoding="utf-8")
    file_b.write_text(json.dumps(_make_report(f_b, "scan-b")), encoding="utf-8")

    # Text compare
    code = main(["compare", str(file_a), str(file_b)])
    assert code == 0
    out = capsys.readouterr().out
    assert "PERDEDOR Report Comparison" in out
    assert "Checks newly firing" in out
    assert "linux.env.check1" in out
    assert "net: no baseline" in out

    # JSON compare
    code = main(["compare", "--json", str(file_a), str(file_b)])
    assert code == 0
    diff_json = json.loads(capsys.readouterr().out)
    assert len(diff_json["newly_firing"]) == 1
    assert diff_json["overall"]["net_delta"] == "net: no baseline"

    # Markdown compare
    code = main(["compare", "--markdown", str(file_a), str(file_b)])
    assert code == 0
    md_out = capsys.readouterr().out
    assert "## PERDEDOR Comparison" in md_out
    assert "net: no baseline" in md_out
