"""Load and cross-check the technique catalog (catalog/ at the repo root).

The catalog is the single source of truth for what a check *means*: which
technique it implements, how decisive and how widespread that technique is,
which upstream tools have an equivalent, which malware uses it, and how to fix
it. Agents only report ids and evidence; the host joins the rest from here.

Layout::

    catalog/classes.json        classes -> categories, weights, scales
    catalog/techniques.json     cross-platform technique vocabulary
    catalog/checks/*.json       concrete checks, one file per platform area
    catalog/threats.json        malware families / actors -> techniques
    catalog/upstreams.json      tracked upstream projects (upstream watcher)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

PLATFORMS = ("windows", "linux", "android", "macos", "ios")
CHECK_STATUSES = ("implemented", "planned", "not_feasible")
ID_PREFIX = {"windows": "win", "linux": "linux", "android": "android", "macos": "macos", "ios": "ios"}


class CatalogError(ValueError):
    pass


def default_catalog_dir() -> Path:
    env = os.environ.get("PERDEDOR_CATALOG")
    if env:
        return Path(env)
    # common/python/perdedor_common/catalog.py -> repo root
    return Path(__file__).resolve().parents[3] / "catalog"


@dataclass
class Catalog:
    root: Path
    classes: dict[str, dict]
    severity_weights: dict[str, float]
    tiers: dict[str, float]
    techniques: dict[str, dict]
    checks: dict[str, dict]
    threats: list[dict] = field(default_factory=list)
    upstreams: list[dict] = field(default_factory=list)

    def check(self, check_id: str) -> dict | None:
        return self.checks.get(check_id)

    def technique(self, key: str) -> dict | None:
        return self.techniques.get(key)

    def prevalence(self, key: str) -> float:
        tech = self.techniques.get(key)
        if not tech:
            return self.tiers["rare"]
        if isinstance(tech.get("prevalence"), (int, float)):
            return float(tech["prevalence"])
        return self.tiers[tech["tier"]]

    def checks_for(self, platform: str, status: str | None = "implemented") -> list[dict]:
        return [
            c
            for c in self.checks.values()
            if c["platform"] == platform and (status is None or c["status"] == status)
        ]

    def techniques_for(self, platform: str) -> list[dict]:
        return [t for t in self.techniques.values() if platform in t["platforms"]]

    def class_category(self, klass: str) -> str:
        return self.classes[klass]["category"]


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"{path}: {exc}") from exc


@lru_cache(maxsize=8)
def _load_cached(root: str) -> Catalog:
    return _load(Path(root))


def load_catalog(root: Path | str | None = None, *, cache: bool = True) -> Catalog:
    root = Path(root) if root else default_catalog_dir()
    return _load_cached(str(root)) if cache else _load(root)


def _load(root: Path) -> Catalog:
    classes_doc = _read(root / "classes.json")
    classes = classes_doc["classes"]
    tiers = {name: float(t["p"]) for name, t in classes_doc["prevalence_tiers"].items()}
    techniques: dict[str, dict] = {}
    for tech in _read(root / "techniques.json")["techniques"]:
        key = tech["key"]
        if key in techniques:
            raise CatalogError(f"technique {key} defined twice")
        if tech["class"] not in classes:
            raise CatalogError(f"technique {key}: unknown class {tech['class']}")
        if tech["tier"] not in tiers:
            raise CatalogError(f"technique {key}: unknown tier {tech['tier']}")
        if not 0 <= float(tech["discrimination"]) <= 1:
            raise CatalogError(f"technique {key}: discrimination outside 0..1")
        techniques[key] = tech

    checks: dict[str, dict] = {}
    for path in sorted((root / "checks").glob("*.json")):
        doc = _read(path)
        platform = doc["platform"]
        if platform not in PLATFORMS:
            raise CatalogError(f"{path.name}: unknown platform {platform}")
        for entry in doc["checks"]:
            cid = entry["id"]
            if cid in checks:
                raise CatalogError(f"check {cid} defined twice ({path.name}, {checks[cid]['file']})")
            if not cid.startswith(ID_PREFIX[platform] + "."):
                raise CatalogError(f"{path.name}: check {cid} does not start with {ID_PREFIX[platform]}.")
            if entry["technique"] not in techniques:
                raise CatalogError(f"check {cid}: unknown technique {entry['technique']}")
            status = entry.get("status", "implemented")
            if status not in CHECK_STATUSES:
                raise CatalogError(f"check {cid}: status {status} not in {CHECK_STATUSES}")
            if status != "implemented" and not entry.get("reason"):
                raise CatalogError(f"check {cid}: status {status} needs a reason")
            fix = entry.get("fix") or {}
            if fix and not (1 <= int(fix.get("effort", 3)) <= 5):
                raise CatalogError(f"check {cid}: fix.effort must be 1..5")
            checks[cid] = {**entry, "platform": platform, "status": status, "file": path.name}

    threats = _read(root / "threats.json")["threats"] if (root / "threats.json").exists() else []
    for threat in threats:
        for key in threat.get("techniques", []):
            if key not in techniques:
                raise CatalogError(f"threat {threat.get('name')}: unknown technique {key}")
    upstreams = _read(root / "upstreams.json")["upstreams"] if (root / "upstreams.json").exists() else []
    return Catalog(
        root=root,
        classes=classes,
        severity_weights={k: float(v) for k, v in classes_doc["severity_weights"].items()},
        tiers=tiers,
        techniques=techniques,
        checks=checks,
        threats=threats,
        upstreams=upstreams,
    )


def enrich_finding(finding: dict, catalog: Catalog) -> dict:
    """Return a copy of a report finding with catalog metadata attached under
    ``catalog`` (technique title, ATT&CK/MBC ids, tier, fix, equivalents)."""
    entry = catalog.check(finding["id"]) or {}
    key = finding.get("technique") or entry.get("technique")
    tech = catalog.technique(key) if key else None
    out = dict(finding)
    if key and "technique" not in out:
        out["technique"] = key
    if tech and "class" not in out:
        out["class"] = tech["class"]
    out["catalog"] = {
        "known": bool(entry),
        "technique_title": tech["title"] if tech else None,
        "attack": tech["attack"] if tech else [],
        "mbc": tech["mbc"] if tech else [],
        "tier": tech["tier"] if tech else None,
        "discrimination": tech["discrimination"] if tech else None,
        "fix": entry.get("fix"),
        "equivalents": entry.get("equivalents", {}),
        "references": entry.get("references", []),
    }
    return out
