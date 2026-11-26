from __future__ import annotations

import json
from pathlib import Path

from perdedor_cli.__main__ import main
from perdedor_common.gate import evaluate_gate
from perdedor_common.history import HistoryStore


def _report(findings: list[dict], scan_id: str = "id", profile: str = "standard") -> dict:
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
        "platform": "linux",
        "hostname": "host",
        "generated_at": "2026-11-26T12:00:00Z",
        "selection": {"profile": profile},
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


def test_gate_logic_pass():
    f = [
        {
            "id": "linux.env.cpuid_hypervisor_bit",
            "name": "Hypervisor bit",
            "status": "clean",
            "severity": "critical",
            "technique": "cpu.hypervisor_bit",
            "class": "cpu",
            "category": "environment_artifact",
        }
    ]
    rep_a = _report(f, "scan-a")
    rep_b = _report(f, "scan-b")

    res = evaluate_gate(rep_b, rep_a)
    assert res.passed
    assert res.exit_code == 0
    assert "passed" in res.reason


def test_gate_logic_fails_on_new_detection():
    f_a = [
        {
            "id": "linux.env.cpuid_hypervisor_bit",
            "name": "Hypervisor bit",
            "status": "clean",
            "severity": "critical",
            "technique": "cpu.hypervisor_bit",
            "class": "cpu",
            "category": "environment_artifact",
        }
    ]
    f_b = [
        {
            "id": "linux.env.cpuid_hypervisor_bit",
            "name": "Hypervisor bit",
            "status": "detected",
            "severity": "critical",
            "technique": "cpu.hypervisor_bit",
            "class": "cpu",
            "category": "environment_artifact",
        }
    ]
    rep_a = _report(f_a, "scan-a")
    rep_b = _report(f_b, "scan-b")

    res = evaluate_gate(rep_b, rep_a)
    assert not res.passed
    assert res.exit_code == 1
    assert "newly firing" in res.reason or "score decreased" in res.reason


def test_gate_max_increase():
    f_a = [
        {"id": "linux.env.1", "name": "1", "status": "clean", "severity": "low", "class": "cpu", "category": "environment_artifact", "technique": "cpu.hypervisor_bit"},
        {"id": "linux.env.2", "name": "2", "status": "clean", "severity": "low", "class": "cpu", "category": "environment_artifact", "technique": "cpu.hypervisor_vendor_leaf"},
    ]
    f_b = [
        {"id": "linux.env.1", "name": "1", "status": "detected", "severity": "low", "class": "cpu", "category": "environment_artifact", "technique": "cpu.hypervisor_bit"},
        {"id": "linux.env.2", "name": "2", "status": "clean", "severity": "low", "class": "cpu", "category": "environment_artifact", "technique": "cpu.hypervisor_vendor_leaf"},
    ]
    rep_a = _report(f_a, "scan-a")
    rep_b = _report(f_b, "scan-b")

    # 1 new detection with max_increase=1 -> pass
    res_pass = evaluate_gate(rep_b, rep_a, max_increase=1)
    assert res_pass.passed

    # 1 new detection with max_increase=0 -> fail
    res_fail = evaluate_gate(rep_b, rep_a, max_increase=0)
    assert not res_fail.passed
    assert "exceed allowed maximum increase" in res_fail.reason


def test_gate_fail_on_new_class():
    f_a = [
        {"id": "linux.env.1", "name": "1", "status": "detected", "severity": "low", "class": "cpu", "category": "environment_artifact", "technique": "cpu.hypervisor_bit"},
        {"id": "linux.timing.1", "name": "T1", "status": "clean", "severity": "low", "class": "timing", "category": "timing", "technique": "timing.cpuid_vmexit"},
    ]
    f_b = [
        {"id": "linux.env.1", "name": "1", "status": "detected", "severity": "low", "class": "cpu", "category": "environment_artifact", "technique": "cpu.hypervisor_bit"},
        # New detection in timing class (which had 0 detections in baseline):
        {"id": "linux.timing.1", "name": "T1", "status": "detected", "severity": "low", "class": "timing", "category": "timing", "technique": "timing.cpuid_vmexit"},
    ]
    rep_a = _report(f_a, "scan-a")
    rep_b = _report(f_b, "scan-b")

    res = evaluate_gate(rep_b, rep_a, max_increase=5, fail_on_new_class=True)
    assert not res.passed
    assert "new detection in previously clean class 'timing'" in res.reason


def test_cli_gate(tmp_path: Path, capsys):
    f_a = [{"id": "linux.env.1", "name": "1", "status": "clean", "severity": "low", "class": "cpu", "category": "environment_artifact", "technique": "cpu.hypervisor_bit"}]
    f_b = [{"id": "linux.env.1", "name": "1", "status": "detected", "severity": "low", "class": "cpu", "category": "environment_artifact", "technique": "cpu.hypervisor_bit"}]

    path_a = tmp_path / "baseline.json"
    path_b = tmp_path / "target.json"
    path_a.write_text(json.dumps(_report(f_a, "scan-a")), encoding="utf-8")
    path_b.write_text(json.dumps(_report(f_b, "scan-b")), encoding="utf-8")

    # Gate fails on new detection
    code = main(["gate", str(path_b), "--baseline", str(path_a)])
    assert code == 1
    err = capsys.readouterr().err
    assert "gate:" in err

    # Gate passes with max_increase=1
    code = main(["gate", str(path_b), "--baseline", str(path_a), "--max-increase", "1"])
    assert code == 0
    out = capsys.readouterr().out
    assert "gate: passed" in out

    # Gate via history baseline profile lookup
    db_file = tmp_path / "gate_hist.sqlite"
    store = HistoryStore(db_file)
    store.add(_report(f_a, "scan-a", profile="standard"))

    code = main(["gate", str(path_b), "--baseline", "standard", "--max-increase", "1", "--store", str(db_file)])
    assert code == 0
