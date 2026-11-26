from __future__ import annotations

import json
from pathlib import Path

import pytest
from perdedor_cli.__main__ import main
from perdedor_common.baseline import VMRefusalError, check_vm, list_baselines, record_baseline, show_baseline
from perdedor_common.compare import compare_reports
from perdedor_common.exposure import assess
from perdedor_common.gate import evaluate_gate
from perdedor_common.scoring import score_report


def _make_report(
    findings: list[dict],
    *,
    platform: str = "windows",
    scan_id: str = "test-scan-123",
    hypervisor: str = "none",
    cpu_model: str = "Intel Core i7-10700K",
    env_name: str = "workstation",
) -> dict:
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
        "hostname": "bare-metal-host",
        "generated_at": "2026-11-20T12:00:00Z",
        "host_facts": {
            "os_build": "10.0.19045",
            "cpu_model": cpu_model,
            "core_count": 8,
        },
        "environment": {
            "name": env_name,
            "os": platform,
            "image_id": "clean-install",
            "hypervisor": hypervisor,
            "monitor": "none",
            "instrumentation": "none",
            "labels": {},
        },
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


def test_baseline_record_and_show(tmp_path: Path):
    findings = [
        {
            "id": "win.timing.rdtsc_skew",
            "name": "RDTSC skew",
            "status": "detected",
            "severity": "medium",
            "technique": "timing.cpuid_vmexit",
            "class": "timing",
            "category": "timing",
            "measurement": {"cycles": 120},
            "confidence": 0.8,
        },
        {
            "id": "win.env.acpi_oem",
            "name": "ACPI OEM table",
            "status": "detected",
            "severity": "low",
            "technique": "artifacts.acpi",
            "class": "firmware",
            "category": "environment_artifact",
        },
        {
            "id": "win.env.cpuid_hypervisor_bit",
            "name": "Hypervisor bit",
            "status": "clean",
            "severity": "critical",
            "technique": "cpu.hypervisor_bit",
            "class": "cpu",
            "category": "environment_artifact",
        },
    ]
    rep = _make_report(findings, hypervisor="none", cpu_model="Intel Core i9-12900K")
    rep_file = tmp_path / "real_report.json"
    rep_file.write_text(json.dumps(rep), encoding="utf-8")

    store_dir = tmp_path / "baselines"
    doc = record_baseline(rep_file, "baremetal-win10", store_dir=store_dir)

    assert doc["profile"] == "baremetal_win10" or doc["profile"] == "baremetal-win10"
    assert doc["scan_id"] == "test-scan-123"
    assert doc["platform"] == "windows"
    assert doc["checks_fired"] == 2
    assert "win.timing.rdtsc_skew" in doc["checks"]
    assert "win.env.acpi_oem" in doc["checks"]
    assert "win.env.cpuid_hypervisor_bit" not in doc["checks"]
    assert doc["checks"]["win.timing.rdtsc_skew"]["measurement"] == {"cycles": 120}

    # Show
    shw = show_baseline("baremetal-win10", store_dir=store_dir)
    assert shw["scan_id"] == "test-scan-123"
    assert len(shw["checks"]) == 2

    # List
    rows = list_baselines(store_dir=store_dir)
    assert len(rows) == 1
    assert rows[0]["profile"] == doc["profile"]
    assert rows[0]["checks_fired"] == 2


def test_baseline_vm_refusal_hypervisor(tmp_path: Path):
    findings = [
        {
            "id": "win.env.test",
            "name": "test",
            "status": "detected",
            "severity": "high",
            "technique": "cpu.hypervisor_bit",
            "class": "cpu",
            "category": "environment_artifact",
        }
    ]
    rep = _make_report(findings, hypervisor="kvm", cpu_model="Intel Core i7")
    reasons = check_vm(rep)
    assert any("hypervisor" in r for r in reasons)

    rep_file = tmp_path / "vm_report.json"
    rep_file.write_text(json.dumps(rep), encoding="utf-8")

    store_dir = tmp_path / "baselines"
    with pytest.raises(VMRefusalError) as exc_info:
        record_baseline(rep_file, "bad-profile", store_dir=store_dir)
    assert "virtual machine" in str(exc_info.value)

    # Force overrides refusal
    doc = record_baseline(rep_file, "forced-profile", store_dir=store_dir, force=True)
    assert doc["profile"] == "forced-profile"
    assert (store_dir / "forced-profile.json").is_file()


def test_baseline_vm_refusal_cpu_marker(tmp_path: Path):
    findings = [
        {
            "id": "win.env.test",
            "name": "test",
            "status": "clean",
            "severity": "high",
            "technique": "cpu.hypervisor_bit",
            "class": "cpu",
            "category": "environment_artifact",
        }
    ]
    rep = _make_report(findings, hypervisor="none", cpu_model="QEMU Virtual CPU version 2.5+")
    reasons = check_vm(rep)
    assert any("cpu_model" in r for r in reasons)

    rep_file = tmp_path / "qemu_report.json"
    rep_file.write_text(json.dumps(rep), encoding="utf-8")

    store_dir = tmp_path / "baselines"
    with pytest.raises(VMRefusalError):
        record_baseline(rep_file, "qemu-profile", store_dir=store_dir)

    # CLI test without force -> exit code 1
    code = main(["baseline", "record", "--profile", "qemu-cli", str(rep_file), "--store", str(store_dir)])
    assert code == 1

    # CLI test with force -> exit code 0
    code_force = main(
        ["baseline", "record", "--profile", "qemu-cli", str(rep_file), "--store", str(store_dir), "--force"]
    )
    assert code_force == 0


def test_scoring_raw_vs_net_exposure(tmp_path: Path):
    findings = [
        {
            "id": "win.env.cpuid_hypervisor_bit",
            "name": "Hypervisor bit",
            "status": "detected",
            "severity": "critical",
            "technique": "cpu.hypervisor_bit",
            "class": "cpu",
            "category": "environment_artifact",
        },
        {
            "id": "win.timing.rdtsc_skew",
            "name": "RDTSC skew",
            "status": "detected",
            "severity": "high",
            "technique": "timing.cpuid_vmexit",
            "class": "timing",
            "category": "timing",
        },
    ]

    # Without baseline: net is "no baseline"
    raw_assess = assess(findings, "windows")
    assert raw_assess["score"] is not None
    assert raw_assess["net_score"] == "no baseline"
    assert raw_assess["net"] == "no baseline"

    # Baseline where win.timing.rdtsc_skew also fires on bare metal
    baseline_doc = {
        "profile": "bare-metal-win",
        "scan_id": "bm-1",
        "platform": "windows",
        "os": "windows",
        "checks": {
            "win.timing.rdtsc_skew": {
                "id": "win.timing.rdtsc_skew",
                "technique": "timing.cpuid_vmexit",
                "status": "detected",
            }
        },
    }

    net_assess = assess(findings, "windows", baseline=baseline_doc)
    assert net_assess["score"] == raw_assess["score"]
    assert isinstance(net_assess["net_score"], float)

    # Net exposure score (higher is better) must be strictly higher or equal to raw
    assert net_assess["net_score"] >= net_assess["raw_score"]
    assert net_assess["net_score"] > raw_assess["score"]  # timing tell cleared!

    # Both carry confidence (interval) and coverage
    assert "interval" in net_assess["net"]
    assert "coverage" in net_assess["net"]
    assert net_assess["baseline"]["profile"] == "bare-metal-win"


def test_scoring_py_net_scores():
    findings = [
        {"id": "c1", "status": "detected", "severity": "high"},
        {"id": "c2", "status": "detected", "severity": "high"},
        {"id": "c3", "status": "clean", "severity": "low"},
    ]
    # No baseline
    res_no = score_report(findings)
    assert res_no["net_raw_score"] == "no baseline"
    assert res_no["net_weighted_score"] == "no baseline"

    # With baseline where c1 fires on bare metal
    baseline = {"checks": {"c1": {"id": "c1", "status": "detected"}}}
    res_with = score_report(findings, baseline=baseline)
    assert res_with["net_raw_score"] == "2/3"  # c1 and c3 clean in net
    assert res_with["net_weighted_score"] > res_with["weighted_score"]


def test_compare_with_baseline(tmp_path: Path):
    f_a = [
        {
            "id": "win.timing.rdtsc",
            "status": "detected",
            "technique": "timing.cpuid_vmexit",
            "class": "timing",
            "category": "timing",
        },
        {
            "id": "win.env.hyp",
            "status": "detected",
            "technique": "cpu.hypervisor_bit",
            "class": "cpu",
            "category": "environment_artifact",
        },
    ]
    f_b = [
        {
            "id": "win.timing.rdtsc",
            "status": "detected",
            "technique": "timing.cpuid_vmexit",
            "class": "timing",
            "category": "timing",
        },
        {
            "id": "win.env.hyp",
            "status": "clean",
            "technique": "cpu.hypervisor_bit",
            "class": "cpu",
            "category": "environment_artifact",
        },
    ]
    rep_a = _make_report(f_a, scan_id="a")
    rep_b = _make_report(f_b, scan_id="b")

    # Without baseline -> net_delta is "net: no baseline"
    diff_no = compare_reports(rep_a, rep_b)
    assert diff_no["overall"]["net_delta"] == "net: no baseline"
    assert diff_no["categories"]["timing"]["net_delta"] == "net: no baseline"

    # With baseline where win.timing.rdtsc fires on bare metal
    base_file = tmp_path / "baseline.json"
    base_doc = {
        "profile": "bare-metal",
        "scan_id": "bm-scan",
        "platform": "windows",
        "os": "windows",
        "checks": {"win.timing.rdtsc": {"id": "win.timing.rdtsc", "technique": "timing.cpuid_vmexit"}},
    }
    base_file.write_text(json.dumps(base_doc), encoding="utf-8")

    diff_with = compare_reports(rep_a, rep_b, baseline=base_file)
    assert diff_with["overall"]["net_delta"] != "net: no baseline"
    assert isinstance(float(diff_with["overall"]["net_delta"]), float)
    assert diff_with["overall"]["net_score_b"] >= diff_with["overall"]["net_score_a"]


def test_gate_with_bare_metal_baseline(tmp_path: Path):
    base_doc = {
        "profile": "bm-win",
        "scan_id": "bm-scan",
        "platform": "windows",
        "os": "windows",
        "checks": {
            "win.timing.jitter": {
                "id": "win.timing.jitter",
                "technique": "timing.cpuid_vmexit",
                "class": "timing",
            },
        },
    }
    store_dir = tmp_path / "baselines"
    store_dir.mkdir()
    (store_dir / "bm-win.json").write_text(json.dumps(base_doc), encoding="utf-8")

    # Target report that only has the check that fires on bare metal
    clean_target = _make_report(
        [
            {
                "id": "win.timing.jitter",
                "status": "detected",
                "technique": "timing.cpuid_vmexit",
                "class": "timing",
                "category": "timing",
            },
            {
                "id": "win.env.hyp",
                "status": "clean",
                "technique": "cpu.hypervisor_bit",
                "class": "cpu",
                "category": "environment_artifact",
            },
        ],
        scan_id="target-clean",
    )

    res = evaluate_gate(clean_target, "bm-win", baseline_store=str(store_dir))
    assert res.passed
    assert res.exit_code == 0
    assert "passed" in res.reason

    # Target report that has an evasion check that does NOT fire on bare metal (a real VM tell)
    dirty_target = _make_report(
        [
            {
                "id": "win.timing.jitter",
                "status": "detected",
                "technique": "timing.cpuid_vmexit",
                "class": "timing",
                "category": "timing",
            },
            {
                "id": "win.env.hyp",
                "status": "detected",
                "technique": "cpu.hypervisor_bit",
                "class": "cpu",
                "category": "environment_artifact",
            },
        ],
        scan_id="target-dirty",
    )

    res_fail = evaluate_gate(dirty_target, "bm-win", baseline_store=str(store_dir))
    assert not res_fail.passed
    assert res_fail.exit_code == 1
    assert "newly firing" in res_fail.reason or "score decreased" in res_fail.reason


def test_cli_baseline_commands(tmp_path: Path, capsys):
    findings = [
        {
            "id": "linux.timing.cpuid",
            "status": "detected",
            "technique": "timing.cpuid_vmexit",
            "measurement": {"delta": 50},
        },
        {"id": "linux.env.acpi", "status": "clean", "technique": "artifacts.acpi"},
    ]
    rep = _make_report(findings, platform="linux", hypervisor="none", cpu_model="AMD Ryzen 9 5950X")
    rep_file = tmp_path / "linux_report.json"
    rep_file.write_text(json.dumps(rep), encoding="utf-8")
    store_dir = tmp_path / "baselines_store"

    # 1. Record
    code_rec = main(
        ["baseline", "record", "--profile", "linux-ryzen", str(rep_file), "--store", str(store_dir)]
    )
    assert code_rec == 0
    out_rec = capsys.readouterr().out
    assert "Recorded baseline 'linux-ryzen'" in out_rec

    # 2. List (text, json, markdown)
    code_list = main(["baseline", "list", "--store", str(store_dir)])
    assert code_list == 0
    out_list = capsys.readouterr().out
    assert "linux-ryzen" in out_list

    code_list_json = main(["baseline", "list", "--store", str(store_dir), "--json"])
    assert code_list_json == 0
    out_list_json = json.loads(capsys.readouterr().out)
    assert len(out_list_json) == 1
    assert out_list_json[0]["profile"] == "linux-ryzen"

    code_list_md = main(["baseline", "list", "--store", str(store_dir), "--markdown"])
    assert code_list_md == 0
    out_list_md = capsys.readouterr().out
    assert "| linux-ryzen |" in out_list_md

    # 3. Show
    code_show = main(["baseline", "show", "linux-ryzen", "--store", str(store_dir)])
    assert code_show == 0
    out_show = capsys.readouterr().out
    assert "PERDEDOR Bare-Metal Baseline: linux-ryzen" in out_show
    assert "linux.timing.cpuid" in out_show

    # 4. Score CLI with baseline
    main(
        [
            "score",
            str(rep_file),
            "--baseline",
            "linux-ryzen",
            "--store",
            str(store_dir),
            "--catalog",
            "catalog",
        ]
    )
    # May be 0 or 1 depending on score pass/fail, but must execute cleanly
    out_score = capsys.readouterr().out
    assert "raw" in out_score.lower()
    assert "net" in out_score.lower()
    assert "linux-ryzen" in out_score
