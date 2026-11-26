from __future__ import annotations

import json
from pathlib import Path

from perdedor_cli.__main__ import main
from perdedor_common.history import (
    HistoryStore,
    render_history_markdown,
    render_history_text,
)


def _sample_report(
    scan_id: str, platform: str = "linux", profile: str = "standard", detected: int = 1
) -> dict:
    return {
        "schema_version": 3,
        "scan_id": scan_id,
        "perdedor_version": "2.0.1",
        "agent_version": "2.0.1",
        "catalog_version": "2.0.1",
        "platform": platform,
        "hostname": f"{platform}-host",
        "generated_at": "2026-11-26T10:00:00Z",
        "seed": 100,
        "host_facts": {"os_build": "6.1.0", "cpu_model": "x86_64", "core_count": 4},
        "environment": {
            "name": f"{platform}-env",
            "os": platform,
            "image_id": "img-01",
            "hypervisor": "xen",
            "monitor": "out-of-guest",
            "instrumentation": "drakvuf",
            "labels": {"stage": "test"},
        },
        "selection": {"profile": profile, "only": [], "skip": [], "params": {}, "network": True},
        "findings": [
            {
                "id": f"{platform}.env.check1",
                "category": "environment_artifact",
                "platform": platform,
                "name": "Check 1",
                "description": "Probe",
                "status": "detected" if detected > 0 else "clean",
                "severity": "high",
                "technique": "cpu.hypervisor_bit",
                "class": "cpu",
            }
        ],
        "summary": {
            "total": 1,
            "clean": 0 if detected > 0 else 1,
            "detected": detected,
            "errored": 0,
            "skipped": 0,
            "raw_score": "0/1" if detected > 0 else "1/1",
            "weighted_score": 35.0 if detected > 0 else 100.0,
        },
    }


def test_history_store_add_get_list(tmp_path: Path):
    db_file = tmp_path / "history.sqlite"
    store = HistoryStore(db_file)

    rep1 = _sample_report("11111111-1111-4111-8111-111111111111", platform="linux", profile="standard")
    rep2 = _sample_report("22222222-2222-4222-8222-222222222222", platform="windows", profile="deep")

    res1 = store.add(rep1)
    assert res1["scan_id"] == "11111111-1111-4111-8111-111111111111"
    assert res1["profile"] == "standard"

    res2 = store.add(rep2)
    assert res2["scan_id"] == "22222222-2222-4222-8222-222222222222"
    assert res2["profile"] == "deep"

    # List all
    all_rows = store.list()
    assert len(all_rows) == 2

    # Filter by profile
    std_rows = store.list(profile="standard")
    assert len(std_rows) == 1
    assert std_rows[0]["scan_id"] == "11111111-1111-4111-8111-111111111111"

    deep_rows = store.list(profile="deep")
    assert len(deep_rows) == 1
    assert deep_rows[0]["scan_id"] == "22222222-2222-4222-8222-222222222222"

    # Filter by platform
    win_rows = store.list(platform="windows")
    assert len(win_rows) == 1

    # Get by exact scan_id
    got1 = store.get("11111111-1111-4111-8111-111111111111")
    assert got1 is not None
    assert got1["scan_id"] == "11111111-1111-4111-8111-111111111111"

    # Get by prefix
    got1_prefix = store.get("11111111")
    assert got1_prefix is not None
    assert got1_prefix["scan_id"] == "11111111-1111-4111-8111-111111111111"

    # Get latest by profile
    got_profile = store.get("deep")
    assert got_profile is not None
    assert got_profile["scan_id"] == "22222222-2222-4222-8222-222222222222"


def test_history_renderers(tmp_path: Path):
    db_file = tmp_path / "history.sqlite"
    store = HistoryStore(db_file)
    store.add(_sample_report("33333333-3333-4333-8333-333333333333"))
    rows = store.list()

    text_out = render_history_text(rows)
    assert "33333333-3333-4333-8333-333333333333" in text_out
    assert "SCAN ID" in text_out

    md_out = render_history_markdown(rows)
    assert "| Scan ID | Date (UTC) |" in md_out
    assert "`33333333-3333-4333-8333-333333333333`" in md_out


def test_cli_history_add_and_list(tmp_path: Path, capsys):
    db_file = tmp_path / "cli_history.sqlite"
    rep_file = tmp_path / "report.json"
    rep = _sample_report("44444444-4444-4444-8444-444444444444", profile="standard")
    rep_file.write_text(json.dumps(rep), encoding="utf-8")

    # Add via CLI
    code = main(["history", "add", str(rep_file), "--store", str(db_file)])
    assert code == 0
    out = capsys.readouterr().out
    assert "Stored report 44444444-4444-4444-8444-444444444444" in out

    # List text via CLI
    code = main(["history", "list", "--store", str(db_file), "--profile", "standard"])
    assert code == 0
    out = capsys.readouterr().out
    assert "44444444-4444-4444-8444-444444444444" in out

    # List JSON via CLI
    code = main(["history", "list", "--store", str(db_file), "--json"])
    assert code == 0
    json_out = json.loads(capsys.readouterr().out)
    assert len(json_out) == 1
    assert json_out[0]["scan_id"] == "44444444-4444-4444-8444-444444444444"

    # List Markdown via CLI
    code = main(["history", "list", "--store", str(db_file), "--markdown"])
    assert code == 0
    md_out = capsys.readouterr().out
    assert "| Scan ID |" in md_out
