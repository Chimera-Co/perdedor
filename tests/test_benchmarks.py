from __future__ import annotations

import json
from pathlib import Path

from perdedor_common.catalog import load_catalog

ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS_DIR = ROOT / "catalog" / "benchmarks"


def test_benchmarks_exist_and_load():
    catalog = load_catalog(cache=False)
    assert catalog.benchmarks
    assert "standard-evasion" in catalog.benchmarks
    assert "quick-triage" in catalog.benchmarks
    assert "deep-evasion" in catalog.benchmarks
    assert "anti-vm-core" in catalog.benchmarks


def test_benchmark_schema_and_integrity():
    catalog = load_catalog(cache=False)
    benchmark_files = list(BENCHMARKS_DIR.glob("*.json"))
    assert len(benchmark_files) >= 4

    for path in benchmark_files:
        doc = json.loads(path.read_text(encoding="utf-8"))
        for field in ("name", "version", "catalog_version", "description", "selection", "checks"):
            assert field in doc, f"{path.name} missing required field '{field}'"

        assert doc["name"] == path.stem
        assert doc["catalog_version"] == "2.0.1"
        assert isinstance(doc["checks"], list)
        assert len(doc["checks"]) > 0

        # Every pinned check id should exist in the catalog
        for cid in doc["checks"]:
            assert catalog.check(cid) is not None, f"{path.name}: check '{cid}' not found in catalog"


def test_catalog_benchmark_lookup():
    catalog = load_catalog(cache=False)
    b = catalog.benchmark("standard-evasion")
    assert b is not None
    assert b["name"] == "standard-evasion"
    assert b["catalog_version"] == "2.0.1"
    assert catalog.benchmark("nonexistent-benchmark") is None
