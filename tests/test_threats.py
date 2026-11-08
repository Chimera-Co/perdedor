"""The threat model (catalog/threats.json, research/prevalence.json) must be
well formed: every technique is a catalogued key backed by a cited source."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from perdedor_common.catalog import load_catalog

ROOT = Path(__file__).resolve().parents[1]
TYPES = {"loader", "stealer", "rat", "ransomware", "banker", "backdoor", "botnet",
         "miner", "spyware", "apt-tool", "protector", "crypter"}
PLATFORMS = {"windows", "linux", "macos", "android", "ios"}
DATE_RE = re.compile(r"^\d{4}(-\d{2}(-\d{2})?)?$")
MIN_YEAR, MAX_YEAR = 1980, 2026


@pytest.fixture(scope="module")
def catalog():
    return load_catalog(ROOT / "catalog", cache=False)


@pytest.fixture(scope="module")
def threats(catalog):
    assert catalog.threats, "catalog/threats.json has no threats"
    return catalog.threats


def test_technique_keys_are_catalogued(catalog, threats):
    for t in threats:
        for key in t["techniques"]:
            assert catalog.technique(key) is not None, f"{t['name']}: unknown technique {key}"


def test_every_technique_has_cited_evidence(threats):
    for t in threats:
        assert t["techniques"], f"{t['name']}: no techniques"
        cited = {e["technique"] for e in t["evidence"] if re.match(r"^https?://", e.get("source") or "")}
        missing = set(t["techniques"]) - cited
        assert not missing, f"{t['name']}: techniques without a cited URL: {sorted(missing)}"
        stray = {e["technique"] for e in t["evidence"]} - set(t["techniques"])
        assert not stray, f"{t['name']}: evidence for unlisted techniques: {sorted(stray)}"
        for e in t["evidence"]:
            assert e["detail"].strip(), f"{t['name']}: empty evidence detail"


def test_no_duplicate_names(threats):
    names = [t["name"].lower() for t in threats]
    dups = {n for n in names if names.count(n) > 1}
    assert not dups, f"duplicate threat names: {sorted(dups)}"


def test_years_and_dates_are_sane(threats):
    for t in threats:
        fs, lr = t["first_seen"], t["last_reported"]
        assert MIN_YEAR <= fs <= MAX_YEAR and MIN_YEAR <= lr <= MAX_YEAR, t["name"]
        assert fs <= lr, f"{t['name']}: first_seen {fs} after last_reported {lr}"
        for e in t["evidence"]:
            p = e["published"]
            if p is None:
                continue
            assert DATE_RE.match(p), f"{t['name']}: bad published date {p!r}"
            assert MIN_YEAR <= int(p[:4]) <= MAX_YEAR, f"{t['name']}: published {p}"


def test_fields_weights_types_platforms(threats):
    for t in threats:
        assert t["type"] in TYPES, f"{t['name']}: type {t['type']}"
        assert t["platforms"] and set(t["platforms"]) <= PLATFORMS, t["name"]
        assert 0.2 <= float(t["weight"]) <= 3.0, f"{t['name']}: weight {t['weight']}"
        assert t["weight_basis"].strip(), f"{t['name']}: weight without a basis"
        assert isinstance(t["aliases"], list) and isinstance(t["actors"], list), t["name"]


# Sourced checks on a platform the technique entry does not list yet. Each one is
# raised in docs/notes/threats.md as a request to widen the technique's platforms.
PLATFORM_GAPS = {
    ("Atomic macOS Stealer", "hardware.memory_modules"),  # system_profiler SPMemoryDataType on macOS
}


def test_technique_platforms_overlap_family_platforms(catalog, threats):
    bad = []
    for t in threats:
        for key in t["techniques"]:
            tech_plats = set(catalog.technique(key)["platforms"])
            if not tech_plats & set(t["platforms"]) and (t["name"], key) not in PLATFORM_GAPS:
                bad.append(f"{t['name']}: {key} not applicable to {t['platforms']}")
    assert not bad, bad


@pytest.mark.parametrize("platform", ["windows", "linux", "android"])
def test_family_form_is_reached(threats, platform):
    n = sum(1 for t in threats if platform in t["platforms"] and t["techniques"])
    assert n >= 10, f"{platform}: only {n} sourced families"


def test_prevalence_file(catalog):
    doc = json.loads((ROOT / "research" / "prevalence.json").read_text())
    seen = set()
    for row in doc["techniques"]:
        assert catalog.technique(row["key"]) is not None, row["key"]
        lo, hi = row["ci"]
        assert 0.0 <= lo <= row["p"] <= hi <= 1.0, row["key"]
        assert row["basis"], row["key"]
        seen.add(row["key"])
    assert seen == set(catalog.techniques), "prevalence.json must cover every technique"


def test_proposed_keys_are_new(catalog):
    doc = json.loads((ROOT / "research" / "proposed-techniques-threats.json").read_text())
    for p in doc["proposals"]:
        assert catalog.technique(p["key"]) is None, f"{p['key']} already exists"
        assert {"key", "class", "title", "attack", "mbc", "discrimination", "tier", "platforms", "why"} <= set(p)
