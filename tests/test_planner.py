"""Hardening planner (issue #5 section 6): layers, recipe targets, changes since a previous report, Markdown."""

import json

from perdedor_cli.__main__ import main as cli_main
from perdedor_common.catalog import load_catalog
from perdedor_common.planner import (
    changes_since,
    hardening_plan,
    layer_for,
    render_markdown,
    target_for,
)

CATALOG = load_catalog()


def _linux_findings(detected: set[str]) -> list[dict]:
    """Every implemented Linux check: clean, except the ids in `detected`."""
    out = []
    for c in CATALOG.checks_for("linux"):
        if c.get("status") != "implemented":
            continue
        out.append(
            {
                "id": c["id"],
                "name": c.get("title") or c.get("name") or c["id"],
                "status": "detected" if c["id"] in detected else "clean",
                "severity": c.get("severity", "low"),
                "technique": c["technique"],
            }
        )
    return out


def _pick(layer: str, prefix: str = "") -> str:
    for c in CATALOG.checks_for("linux"):
        fix = c.get("fix") or {}
        if (
            c.get("status") == "implemented"
            and fix.get("layer") == layer
            and c["technique"].startswith(prefix)
        ):
            return c["id"]
    raise AssertionError(f"no implemented linux check with layer {layer} {prefix}")


FIRMWARE = _pick("firmware")
PROFILE = _pick("guest-image", "wear_and_tear.")
MONITOR = _pick("analysis-engine")


def test_layer_names_follow_the_operator_layers():
    assert layer_for({"layer": "vm-config"}) == "device model"
    assert layer_for({"layer": "analysis-engine"}) == "monitor"
    assert layer_for({"layer": "guest-image", "technique": "wear_and_tear.browser_history"}) == "user profile"
    assert layer_for({"layer": "guest-image", "technique": "container.container_runtime"}) == "guest OS"
    assert "registry" in target_for("guest OS", "windows")
    assert "udev" in target_for("guest OS", "linux")
    assert "xl.cfg" in target_for("firmware", "linux")


def test_plan_names_layer_and_target_and_never_applies():
    p = hardening_plan(_linux_findings({FIRMWARE, PROFILE, MONITOR}), "linux", CATALOG)
    assert p["applies_fixes"] is False
    assert p["steps"], "three detected checks must give at least one step"
    groups = {s["layer_group"] for s in p["steps"]}
    assert groups <= {
        "firmware",
        "user profile",
        "monitor",
        "guest OS",
        "device model",
        "hypervisor",
        "network",
    }
    assert all(s["target"] for s in p["steps"])
    # ordered by gain per effort, and the score only goes up
    after = [s["score_after"] for s in p["steps"]]
    assert after == sorted(after) and p["end"] >= p["start"]


def test_changes_since_a_previous_report():
    before = _linux_findings({FIRMWARE, PROFILE})
    now = _linux_findings({PROFILE, MONITOR})
    d = changes_since(before, now)
    assert d["improved"] == [FIRMWARE]
    assert d["regressed"] == [MONITOR]
    p = hardening_plan(now, "linux", CATALOG, previous=before)
    assert p["since_previous"]["improved"] == [FIRMWARE]
    assert p["since_previous"]["score_now"] == p["start"]


def test_markdown_change_list():
    p = hardening_plan(
        _linux_findings({FIRMWARE, PROFILE}),
        "linux",
        CATALOG,
        previous=_linux_findings({FIRMWARE, PROFILE, MONITOR}),
    )
    md = render_markdown(p)
    assert md.startswith("# Hardening plan (linux)")
    assert "never applies these changes" in md
    assert md.count("- [ ] Applied and re-scanned") == len(p["steps"])
    assert "## Since the previous report" in md and f"`{MONITOR}`" in md


def test_empty_report_has_nothing_to_plan():
    p = hardening_plan([], "linux", CATALOG)
    assert "Nothing to plan" in render_markdown(p)


def test_cli_writes_json_and_markdown(tmp_path, capsys):
    report = {"platform": "linux", "findings": _linux_findings({FIRMWARE, PROFILE})}
    prev = {"platform": "linux", "findings": _linux_findings({FIRMWARE, PROFILE, MONITOR})}
    (tmp_path / "now.json").write_text(json.dumps(report))
    (tmp_path / "prev.json").write_text(json.dumps(prev))
    rc = cli_main(
        [
            "plan",
            str(tmp_path / "now.json"),
            "--previous",
            str(tmp_path / "prev.json"),
            "--json",
            str(tmp_path / "plan.json"),
            "--markdown",
            str(tmp_path / "plan.md"),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Since the previous report" in out
    data = json.loads((tmp_path / "plan.json").read_text())
    assert data["applies_fixes"] is False and data["since_previous"]["improved"] == [MONITOR]
    assert (tmp_path / "plan.md").read_text().startswith("# Hardening plan (linux)")
