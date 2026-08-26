from __future__ import annotations

import json

from perdedor_cli import __main__ as cli_main
from perdedor_cli.__main__ import main


def test_test_linux_writes_schema_valid_json(tmp_path) -> None:
    output = tmp_path / "linux.json"
    exit_code = main(["test", "linux", "-o", str(output), "--json"])
    assert exit_code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["platform"] == "linux"
    assert "summary" in report


def test_test_android_writes_schema_valid_json_even_with_no_device(tmp_path) -> None:
    output = tmp_path / "android.json"
    exit_code = main(["test", "android", "-o", str(output), "--json"])
    assert exit_code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["platform"] == "android"


def test_test_linux_default_output_is_human_readable_text(capsys) -> None:
    exit_code = main(["test", "linux", "--no-color"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "PERDEDOR -- Linux Sandbox-Evasion Self-Test" in out
    assert "Score:" in out
    # human-readable mode must not just be JSON on stdout
    assert not out.strip().startswith("{")


def test_test_linux_shows_splash_banner_before_the_report(capsys) -> None:
    exit_code = main(["test", "linux", "--no-color"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Sandbox-Evasion Self-Test Suite" in out
    # the banner must appear before the report, not after
    assert out.index("Self-Test Suite") < out.index("Score:")


def test_test_linux_json_flag_never_shows_the_banner(capsys) -> None:
    """--json must keep stdout as pure JSON -- the decorative splash banner
    is exactly the kind of stray text that would break a caller piping
    stdout straight into a JSON parser (see the Write-Host stdout-pollution
    bug case study for why this discipline matters)."""
    exit_code = main(["test", "linux", "--json"])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["platform"] == "linux"


def test_test_linux_json_flag_prints_raw_json(capsys) -> None:
    exit_code = main(["test", "linux", "--json"])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["platform"] == "linux"


def test_test_rejects_unknown_platform() -> None:
    try:
        main(["test", "macos"])
        raised = False
    except SystemExit as exc:
        raised = True
        assert exc.code != 0
    assert raised, "argparse should reject an unsupported platform choice"


def test_report_aggregates_multiple_platforms(tmp_path) -> None:
    linux_report = tmp_path / "linux.json"
    android_report = tmp_path / "android.json"
    main(["test", "linux", "-o", str(linux_report), "--json"])
    main(["test", "android", "-o", str(android_report), "--json"])

    html_output = tmp_path / "unified.html"
    json_output = tmp_path / "unified.json"
    exit_code = main(
        [
            "report",
            str(linux_report),
            str(android_report),
            "-o",
            str(html_output),
            "--json",
            str(json_output),
        ]
    )
    assert exit_code == 0
    assert html_output.exists()
    assert "PERDEDOR Unified Evasion-Probe Report" in html_output.read_text(encoding="utf-8")

    aggregate = json.loads(json_output.read_text(encoding="utf-8"))
    assert set(aggregate["platforms"]) == {"linux", "android"}
    assert aggregate["overall_summary"]["total"] > 0


def test_report_rejects_malformed_input(tmp_path, capsys) -> None:
    bad_report = tmp_path / "bad.json"
    bad_report.write_text(json.dumps({"platform": "linux"}), encoding="utf-8")

    exit_code = main(["report", str(bad_report), "-o", str(tmp_path / "out.html")])
    assert exit_code == 1
    assert "does not match the PERDEDOR schema" in capsys.readouterr().err


def test_report_rejects_missing_file(tmp_path, capsys) -> None:
    exit_code = main(["report", str(tmp_path / "does-not-exist.json"), "-o", str(tmp_path / "out.html")])
    assert exit_code == 1
    assert "could not read" in capsys.readouterr().err


def test_test_windows_reports_clear_error_when_pwsh_missing(monkeypatch, capsys) -> None:
    """`perdedor test windows` only runs the Windows platform's checks (never
    falling back to another platform's suite) -- when the pwsh prerequisite
    is missing it must fail loudly with actionable guidance, not silently
    report an empty/wrong-platform result."""
    monkeypatch.setattr(cli_main.shutil, "which", lambda name: None)
    exit_code = main(["test", "windows"])
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "pwsh" in err
    assert "PowerShell 7" in err
