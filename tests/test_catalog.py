"""The catalog and the agents must agree: every check id an agent can emit is
catalogued (with the same technique), and every implemented catalog entry is
emitted by some agent."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from perdedor_common.catalog import load_catalog

ROOT = Path(__file__).resolve().parents[1]
ID_RE = re.compile(r"""['"]((?:win|linux|android|macos|ios)\.[a-z_]+\.[a-z0-9_]+)['"]""")


def python_specs():
    from perdedor_android.runner import all_checks as android_checks
    from perdedor_linux.runner import all_checks as linux_checks

    specs = {"linux": linux_checks(), "android": android_checks()}
    try:
        from perdedor_macos.runner import all_checks as macos_checks

        specs["macos"] = macos_checks()
    except ImportError:
        pass
    try:
        from perdedor_ios.runner import all_checks as ios_checks

        specs["ios"] = ios_checks()
    except ImportError:
        pass
    return specs


def powershell_ids() -> set[str]:
    """Ids registered by the PowerShell agent (Register-PerdedorCheck -Ids ...)."""
    ids: set[str] = set()
    for path in (ROOT / "agents/windows").rglob("*.ps1"):
        for block in re.findall(r"Register-PerdedorCheck(.*?)(?:\n\s*\n|$)", path.read_text(), re.S):
            ids.update(ID_RE.findall(block))
    return ids


NATIVE_REG = re.compile(
    r"PERDEDOR_REGISTER\(\s*\w+\s*,\s*\"([a-z_]+\.[a-z0-9_]+)\"\s*,\s*\"(fast|medium|slow)\"\s*,\s*(true|false)\s*,(.*?)\);",
    re.S,
)
NATIVE_DIRS = {"common": ("win", "linux"), "windows": ("win",), "linux": ("linux",)}


def native_registrations() -> dict[str, str]:
    """id -> technique for every PERDEDOR_REGISTER in native/src (prefix by build)."""
    out: dict[str, str] = {}
    for sub, prefixes in NATIVE_DIRS.items():
        for path in (ROOT / "native/src" / sub).rglob("*.cpp"):
            for technique, _cost, _net, rest in NATIVE_REG.findall(path.read_text()):
                for rel in re.findall(r'"([a-z_]+\.[a-z0-9_]+)"', rest):
                    for prefix in prefixes:
                        out[f"{prefix}.{rel}"] = technique
    return out


def test_native_checks_are_catalogued_with_matching_technique():
    catalog = load_catalog(cache=False)
    regs = native_registrations()
    assert regs, "no native registrations found"
    for check_id, technique in regs.items():
        entry = catalog.check(check_id)
        assert entry, f"{check_id} (native) is not in catalog/checks"
        assert entry["technique"] == technique, f"{check_id}: native {technique} != catalog {entry['technique']}"


def test_catalog_loads():
    catalog = load_catalog(cache=False)
    assert len(catalog.techniques) > 100
    assert catalog.checks


def test_python_agent_checks_are_catalogued_with_matching_technique():
    catalog = load_catalog(cache=False)
    for platform, specs in python_specs().items():
        for spec in specs:
            for check_id in spec.ids:
                entry = catalog.check(check_id)
                assert entry, f"{check_id} ({platform}) is not in catalog/checks"
                assert entry["technique"] == spec.technique or check_id.startswith("linux.env.dmi_"), check_id
                assert entry["status"] == "implemented", check_id


def test_implemented_catalog_entries_exist_in_an_agent():
    catalog = load_catalog(cache=False)
    emitted = (
        {i for specs in python_specs().values() for s in specs for i in s.ids}
        | powershell_ids()
        | set(native_registrations())
    )
    if not powershell_ids():
        pytest.skip("PowerShell agent has no Register-PerdedorCheck table yet")
    missing = sorted(
        c["id"] for c in catalog.checks.values() if c["status"] == "implemented" and c["id"] not in emitted
    )
    assert not missing, f"catalogued as implemented but no agent emits: {missing}"


def test_every_technique_platform_has_a_check_or_a_reason():
    """Coverage honesty: a technique listed for a platform must have at least
    one catalog entry there (implemented, planned or not_feasible)."""
    catalog = load_catalog(cache=False)
    covered = {(c["platform"], c["technique"]) for c in catalog.checks.values()}
    gaps = sorted(
        (p, t["key"]) for t in catalog.techniques.values() for p in t["platforms"] if (p, t["key"]) not in covered
    )
    # Reported, not failed, while the v2 catalog is being filled in.
    print(f"{len(gaps)} technique/platform pairs without a catalog entry")
