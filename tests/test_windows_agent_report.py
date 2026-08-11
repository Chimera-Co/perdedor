"""Cross-language contract test: run the real PowerShell Windows agent and
validate its JSON output against the same schema the Python side uses.

Skipped if `pwsh` (PowerShell 7) isn't installed -- this is a real
integration test, not a mock, so it needs the actual interpreter. It runs
happily on macOS/Linux dev machines because every Windows-only cmdlet in the
agent is guarded to degrade to a `skipped`/`error` finding rather than
crashing (see agents/windows/README.md).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from hydra_common.validation import validate_report

_REPO_ROOT = Path(__file__).resolve().parent.parent
_AGENT_SCRIPT = _REPO_ROOT / "agents" / "windows" / "Invoke-Hydra.ps1"

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 (pwsh) not installed")


def test_windows_agent_produces_schema_valid_report(tmp_path) -> None:
    output_path = tmp_path / "windows-report.json"
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(_AGENT_SCRIPT), "-OutputPath", str(output_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, f"agent failed:\nstdout={result.stdout}\nstderr={result.stderr}"

    report = json.loads(output_path.read_text(encoding="utf-8"))
    validate_report(report)  # raises ValidationError on any schema mismatch

    assert report["platform"] == "windows"
    ids = {f["id"] for f in report["findings"]}
    # Spot-check that every category is actually represented, not just that
    # *some* findings exist.
    assert any(i.startswith("win.env.") for i in ids)
    assert any(i.startswith("win.timing.") for i in ids)
    assert any(i.startswith("win.behavioural.") for i in ids)
    assert any(i.startswith("win.design.") for i in ids)


def test_windows_agent_finding_status_is_never_a_crash() -> None:
    """Every finding must resolve to one of the four schema statuses -- i.e.
    a platform gap must degrade to skipped/error, never abort the scan."""
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(_AGENT_SCRIPT)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, f"agent crashed:\nstderr={result.stderr}"
    report = json.loads(result.stdout)
    statuses = {f["status"] for f in report["findings"]}
    assert statuses <= {"clean", "detected", "error", "skipped"}
