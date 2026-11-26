from __future__ import annotations

import json
from pathlib import Path

import pytest
from perdedor_common.report_reader import read_report
from perdedor_common.validation import ValidationError, validate_report


def test_reader_handles_v1_report(tmp_path: Path) -> None:
    v1_doc = {
        "perdedor_version": "1.0.0",
        "platform": "linux",
        "hostname": "legacy-host",
        "generated_at": "2023-01-01T00:00:00Z",
        "findings": [
            {
                "id": "linux.env.dmi_sys_vendor",
                "category": "environment_artifact",
                "platform": "linux",
                "name": "DMI system vendor",
                "description": "Vendor string check",
                "status": "clean",
                "severity": "high",
                "evidence": "QEMU",
                "remediation": None,
                "error_detail": None,
            }
        ],
        "summary": {
            "total": 1,
            "clean": 1,
            "detected": 0,
            "errored": 0,
            "skipped": 0,
            "raw_score": "1/1",
            "weighted_score": 100.0,
        },
    }
    p = tmp_path / "v1.json"
    p.write_text(json.dumps(v1_doc), encoding="utf-8")

    rep = read_report(p)
    assert rep["schema_version"] == 1
    assert "scan_id" in rep
    assert rep["agent_version"] == "1.0.0"
    assert rep["catalog_version"] == "1.0.0"
    assert "host_facts" in rep
    assert "environment" in rep
    assert rep["environment"]["os"] == "linux"
    assert rep["environment"]["monitor"] == "none"
    validate_report(rep)


def test_reader_handles_v2_report() -> None:
    v2_doc = {
        "schema_version": 2,
        "perdedor_version": "2.0.1",
        "platform": "windows",
        "hostname": "win-box",
        "generated_at": "2026-01-01T00:00:00Z",
        "agent_metadata": {"os": "Windows", "os_release": "10.0.19045", "machine": "AMD64"},
        "selection": {"profile": "standard", "only": [], "skip": [], "params": {}, "network": True},
        "findings": [
            {
                "id": "win.env.cpuid_hypervisor_bit",
                "category": "environment_artifact",
                "platform": "windows",
                "name": "CPUID hypervisor bit",
                "description": "ECX bit 31",
                "status": "detected",
                "severity": "critical",
                "technique": "cpu.hypervisor_bit",
                "class": "cpu",
                "confidence": 1.0,
                "evidence": "present",
                "remediation": "Mask CPUID bit",
                "error_detail": None,
            }
        ],
        "summary": {
            "total": 1,
            "clean": 0,
            "detected": 1,
            "errored": 0,
            "skipped": 0,
            "raw_score": "0/1",
            "weighted_score": 0.0,
        },
    }
    rep = read_report(v2_doc)
    assert rep["schema_version"] == 2
    assert "scan_id" in rep
    assert rep["host_facts"]["os_build"] == "10.0.19045"
    assert rep["environment"]["os"] == "windows"
    validate_report(rep)


def test_reader_handles_v3_report() -> None:
    v3_doc = {
        "schema_version": 3,
        "scan_id": "99999999-0000-4000-8000-000000000001",
        "perdedor_version": "2.0.1",
        "agent_version": "2.0.1",
        "catalog_version": "2.0.1",
        "platform": "linux",
        "hostname": "sandbox-01",
        "generated_at": "2026-11-26T12:00:00Z",
        "seed": 42,
        "host_facts": {
            "os_build": "6.1.0-custom",
            "cpu_model": "Intel Core i7",
            "core_count": 8,
        },
        "environment": {
            "name": "golden-xen",
            "os": "linux",
            "image_id": "xen-img-1",
            "hypervisor": "xen",
            "monitor": "out-of-guest",
            "instrumentation": "drakvuf",
            "labels": {"owner": "threat-intel", "pool": "automated"},
        },
        "selection": {
            "profile": "deep",
            "only": ["class:cpu"],
            "skip": [],
            "params": {},
            "network": False,
            "seed": 42,
        },
        "findings": [
            {
                "id": "linux.env.cpuid_hypervisor_bit",
                "category": "environment_artifact",
                "platform": "linux",
                "name": "CPUID hypervisor bit",
                "description": "ECX bit 31",
                "status": "clean",
                "severity": "critical",
                "technique": "cpu.hypervisor_bit",
                "class": "cpu",
                "evidence": "masked",
                "remediation": None,
                "error_detail": None,
            }
        ],
        "summary": {
            "total": 1,
            "clean": 1,
            "detected": 0,
            "errored": 0,
            "skipped": 0,
            "raw_score": "1/1",
            "weighted_score": 100.0,
        },
    }
    rep = read_report(v3_doc)
    assert rep["schema_version"] == 3
    assert rep["scan_id"] == "99999999-0000-4000-8000-000000000001"
    assert rep["seed"] == 42
    assert rep["environment"]["monitor"] == "out-of-guest"
    validate_report(rep)
