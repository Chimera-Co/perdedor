"""Host helpers: selection validation, agent arguments, check tree, native build cache."""

from __future__ import annotations

import os
import time

import pytest
from perdedor_common import host
from perdedor_common.catalog import load_catalog


def test_selection_defaults_and_normalisation():
    s = host.validate_selection({})
    assert s == {"profile": "standard", "only": [], "skip": [], "params": {}, "network": True}
    s = host.validate_selection({"only": "class:cpu, id:win.*  class:cpu", "params": ["watchdog.slow_s=300"]})
    assert s["only"] == ["class:cpu", "id:win.*"] and s["params"] == {"watchdog.slow_s": "300"}


@pytest.mark.parametrize(
    "bad,field",
    [
        ({"profile": "max"}, "profile"),
        ({"only": ["foo;rm -rf"]}, "only"),
        ({"skip": ["vendor:xen"]}, "skip"),
        ({"skip": ["cost:huge"]}, "skip"),
        ({"params": {"Bad Key": "1"}}, "params"),
        ({"params": {"a.b": "x\ny"}}, "params"),
        ({"params": ["novalue"]}, "params"),
        ({"network": "no"}, "network"),
    ],
)
def test_selection_rejects_what_the_agent_would(bad, field):
    with pytest.raises(host.SelectionError) as exc:
        host.validate_selection(bad)
    assert exc.value.field == field


def test_agent_args_round_trip():
    s = host.validate_selection(
        {
            "profile": "deep",
            "only": ["class:cpu"],
            "skip": ["cost:slow"],
            "params": {"watchdog.fast_s": 5},
            "network": False,
        }
    )
    assert host.agent_args(s, "r.json") == [
        "-o",
        "r.json",
        "--profile",
        "deep",
        "--only",
        "class:cpu",
        "--skip",
        "cost:slow",
        "--param",
        "watchdog.fast_s=5",
        "--no-network",
    ]


@pytest.mark.parametrize("platform", ["windows", "linux", "android"])
def test_check_tree_covers_every_implemented_check_once(platform):
    cat = load_catalog()
    tree = host.check_tree(platform, cat)
    ids = [c["id"] for g in tree for k in g["classes"] for c in k["checks"]]
    assert sorted(ids) == sorted(c["id"] for c in cat.checks_for(platform))
    assert len(ids) == len(set(ids))
    for g in tree:
        for k in g["classes"]:
            assert all(cat.techniques[c["technique"]]["class"] == k["class"] for c in k["checks"])


def test_native_binary_reuses_a_fresh_build(tmp_path, monkeypatch):
    native = tmp_path / "native"
    (native / "src").mkdir(parents=True)
    (native / "src" / "a.cpp").write_text("x")
    (native / "Makefile").write_text(
        "win64:\n\tmkdir -p build && echo bin > build/perdedor-windows-x64.exe\n"
    )
    out = host.native_binary(tmp_path, "windows-x64")
    assert out.read_text() == "bin\n"
    out.write_text("cached")
    assert host.native_binary(tmp_path, "windows-x64").read_text() == "cached"
    future = time.time() + 5
    os.utime(native / "src" / "a.cpp", (future, future))
    assert host.native_binary(tmp_path, "windows-x64").read_text() == "bin\n"


def test_native_binary_reports_build_failures(tmp_path):
    (tmp_path / "native" / "src").mkdir(parents=True)
    (tmp_path / "native" / "Makefile").write_text("linux:\n\t@echo boom >&2; exit 3\n")
    with pytest.raises(host.BuildError, match="boom"):
        host.native_binary(tmp_path, "linux-x86_64")
    with pytest.raises(host.BuildError, match="unknown native target"):
        host.native_binary(tmp_path, "macos-arm64")
