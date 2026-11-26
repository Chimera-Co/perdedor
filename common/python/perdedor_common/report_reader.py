"""Version-aware report reader for PERDEDOR reports.

Supports reports across schema versions:
- Schema v1: Legacy v1 reports (optional or missing schema_version, v1 summary and finding fields).
- Schema v2: Added technique/class/confidence/measurement fields and selection.
- Schema v3: Current versioned reports with stable scan_id, agent/catalog versions, host_facts,
  environment profile block (name, os, image_id, hypervisor, monitor, instrumentation, labels),
  and random seed of check order.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

from .scoring import score_report
from .validation import validate_report


def _generate_scan_id(doc: dict) -> str:
    """Generate a stable, deterministic scan_id for legacy reports without one."""
    seed_data = f"{doc.get('platform')}:{doc.get('hostname')}:{doc.get('generated_at')}"
    h = hashlib.sha256(seed_data.encode("utf-8")).hexdigest()
    # Format as a standard UUID v4 style string
    return str(uuid.UUID(h[:32]))


def read_report(source: str | Path | dict, *, validate: bool = True) -> dict:
    """Read and normalize a PERDEDOR report from a file path or dict.

    Accepts schema version 1, 2, and 3 reports. Upgrades missing metadata to ensure
    consistent access to scan_id, versions, environment, host_facts, and selection.
    """
    if isinstance(source, (str, Path)):
        path = Path(source)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"could not read report from {path}: {exc}") from exc
    elif isinstance(source, dict):
        raw = json.loads(json.dumps(source))  # deep copy
    else:
        raise TypeError(f"expected path or dict, got {type(source).__name__}")

    if not isinstance(raw, dict):
        raise ValueError("report content must be a JSON object")

    # Detect version
    ver = raw.get("schema_version")
    if ver is None:
        schema_version = 1
    elif ver in (1, 2, 3):
        schema_version = int(ver)
    else:
        raise ValueError(f"unsupported schema_version: {ver}")

    normalized = dict(raw)
    normalized["schema_version"] = schema_version
    normalized.setdefault("perdedor_version", "2.0.1")
    normalized.setdefault("agent_version", normalized["perdedor_version"])
    normalized.setdefault("catalog_version", normalized["perdedor_version"])

    platform_name = normalized.get("platform", "unknown")
    normalized.setdefault("hostname", "unknown")
    normalized.setdefault("generated_at", "1970-01-01T00:00:00Z")

    # scan_id
    if not normalized.get("scan_id"):
        normalized["scan_id"] = _generate_scan_id(normalized)

    # host_facts
    if "host_facts" not in normalized or not isinstance(normalized["host_facts"], dict):
        meta = normalized.get("agent_metadata") or {}
        normalized["host_facts"] = {
            "os_build": meta.get("os_release", meta.get("os_version", "")),
            "cpu_model": meta.get("machine", ""),
            "core_count": 1,
        }

    # environment
    if "environment" not in normalized or not isinstance(normalized["environment"], dict):
        meta = normalized.get("agent_metadata") or {}
        normalized["environment"] = {
            "name": meta.get("env_name", ""),
            "os": platform_name,
            "image_id": meta.get("image_id", ""),
            "hypervisor": meta.get("hypervisor", ""),
            "monitor": "none",
            "instrumentation": "none",
            "labels": {},
        }
    else:
        env = normalized["environment"]
        env.setdefault("name", "")
        env.setdefault("os", platform_name)
        env.setdefault("image_id", "")
        env.setdefault("hypervisor", "")
        env.setdefault("monitor", "none")
        env.setdefault("instrumentation", "none")
        env.setdefault("labels", {})

    # selection
    if "selection" not in normalized or not isinstance(normalized["selection"], dict):
        normalized["selection"] = {
            "profile": "standard",
            "only": [],
            "skip": [],
            "params": {},
            "network": True,
        }

    # findings & summary
    findings = normalized.get("findings")
    if not isinstance(findings, list):
        findings = []
        normalized["findings"] = findings

    if "summary" not in normalized or not isinstance(normalized["summary"], dict):
        normalized["summary"] = score_report(findings)

    if validate:
        validate_report(normalized, allow_v1=True)

    return normalized
