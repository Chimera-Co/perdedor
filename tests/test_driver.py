"""Reference driver (issue #6 section 3) and the progress contract (docs/INTEGRATION.md)."""

import json
import shutil
from pathlib import Path

import pytest
from perdedor_common.driver import (
    LocalTransport,
    agent_argv,
    guest_join,
    parse_progress,
    run_scan,
)

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "native" / "build" / "perdedor-linux-x86_64"


def _lines(*events):
    return [json.dumps(e) for e in events]


BEGIN = {"event": "begin", "total": 3, "scan_id": "s1", "t_ms": 1}


def test_complete_run():
    p = parse_progress(
        _lines(
            BEGIN,
            {"event": "start", "probe": "a", "index": 1, "budget_s": 10},
            {"event": "end", "probe": "a", "ms": 5, "outcome": "ok"},
            {"event": "start", "probe": "b", "index": 2, "budget_s": 45},
            {"event": "end", "probe": "b", "ms": 900, "outcome": "timed_out"},
            {"event": "done", "exit_code": 0, "t_ms": 1000},
        )
    )
    assert p.state == "done" and p.exit_code == 0 and p.stuck is None
    assert p.timed_out == ["b"] and p.slowest[0] == ("b", 900.0)


def test_frozen_guest_names_the_probe_and_ignores_a_torn_line():
    lines = _lines(
        BEGIN,
        {"event": "start", "probe": "a", "budget_s": 10},
        {"event": "end", "probe": "a", "ms": 3, "outcome": "ok"},
        {"event": "start", "probe": "win.env.hypervisor_exception_quirks", "budget_s": 10, "t_ms": 40},
    ) + ['{"event": "end", "probe": "win.env.hyp']
    p = parse_progress(lines)
    assert p.state == "stopped in a probe"
    assert p.stuck == "win.env.hypervisor_exception_quirks" and p.stuck_budget_s == 10
    assert p.started == 2 and p.finished == 1 and p.last_t_ms == 40


def test_failed_and_empty():
    assert (
        parse_progress(_lines(BEGIN, {"event": "failed", "reason": "disk full", "exit_code": 1})).state
        == "failed"
    )
    assert parse_progress([]).state == "not started"


def test_guest_paths_and_argv():
    assert guest_join("C:\\perdedor", "report.json") == "C:\\perdedor\\report.json"
    assert guest_join("/tmp/p", "report.json") == "/tmp/p/report.json"
    argv = agent_argv(
        "a.exe", "r.json", "p.jsonl", profile="quick", only=["win.timing.*"], params={"x": 1}, network=False
    )
    assert argv == [
        "a.exe",
        "--profile",
        "quick",
        "--report",
        "r.json",
        "--progress",
        "p.jsonl",
        "--only",
        "win.timing.*",
        "--param",
        "x=1",
        "--no-network",
    ]


@pytest.mark.skipif(
    not AGENT.is_file() or shutil.which("true") is None, reason="native Linux agent not built"
)
def test_local_scan_end_to_end(tmp_path):
    result = run_scan(
        LocalTransport(),
        AGENT,
        str(tmp_path / "guest"),
        out_dir=tmp_path / "out",
        only=["linux.env.dmi_*"],
        network=False,
        timeout=120,
    )
    assert result.ok, (result.exit_code, result.progress)
    assert result.progress.total == result.progress.finished > 0
    assert result.report["platform"] == "linux" and result.report["findings"]
