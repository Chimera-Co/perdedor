"""Bare-metal baseline recording, storage, and net exposure calibration (stdlib only).

Records reports produced on real, non-virtual machines to establish which checks
fire naturally on bare metal. Refuses reports from virtual machines unless forced.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .report_reader import read_report

VM_CPU_MARKERS = (
    "qemu",
    "kvm",
    "virtual",
    "vmware",
    "hyper-v",
    "hyperv",
    "bhyve",
    "xen",
    "parallels",
    "bochs",
    "tcg",
)

VM_NAME_MARKERS = (
    "qemu",
    "kvm",
    "virtualbox",
    "vbox",
    "vmware",
    "xen",
    "hyper-v",
    "hyperv",
    "parallels",
    "bhyve",
)


class VMRefusalError(ValueError):
    """Raised when a baseline report appears to have run in a virtual machine."""

    def __init__(self, message: str, reasons: list[str] | None = None):
        super().__init__(message)
        self.reasons = reasons or []


def check_vm(report: dict) -> list[str]:
    """Inspect environment block and host facts for virtual machine indicators.

    Returns a list of reasons if VM markers are found, or an empty list if clean.
    """
    reasons: list[str] = []

    env = report.get("environment") or {}
    hypervisor = (env.get("hypervisor") or "").strip().lower()
    if hypervisor and hypervisor not in ("none", "bare-metal", "physical", "unknown"):
        reasons.append(f"environment hypervisor is '{hypervisor}' (expected 'none')")

    env_name = (env.get("name") or "").lower()
    for marker in VM_NAME_MARKERS:
        if marker in env_name:
            reasons.append(f"environment name '{env.get('name')}' contains VM marker '{marker}'")
            break

    image_id = (env.get("image_id") or "").lower()
    for marker in VM_NAME_MARKERS:
        if marker in image_id:
            reasons.append(f"environment image_id '{env.get('image_id')}' contains VM marker '{marker}'")
            break

    host_facts = report.get("host_facts") or {}
    cpu_model = (host_facts.get("cpu_model") or "").lower()
    for marker in VM_CPU_MARKERS:
        if marker in cpu_model:
            reasons.append(f"cpu_model '{host_facts.get('cpu_model')}' contains VM marker '{marker}'")
            break

    return reasons


def default_baselines_dir() -> Path:
    """Default directory for storing bare-metal baseline profiles."""
    env = os.environ.get("PERDEDOR_BASELINES")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "perdedor" / "baselines"
    return Path.home() / ".local" / "share" / "perdedor" / "baselines"


def record_baseline(
    report_input: str | Path | dict,
    profile: str,
    store_dir: str | Path | None = None,
    *,
    force: bool = False,
) -> dict:
    """Record a bare-metal baseline from a real machine report.

    Extracts which checks fire there too, with their measurements, plus
    os/build/cpu/date and the report's scan_id. Refuses reports from VMs unless force=True.
    """
    report = read_report(report_input, validate=False)

    vm_reasons = check_vm(report)
    if vm_reasons and not force:
        detail = "; ".join(vm_reasons)
        raise VMRefusalError(
            f"Refusing to record baseline: report indicates virtual machine execution ({detail}). "
            "Baselines must be recorded from real, bare-metal physical machines. Use --force to override.",
            reasons=vm_reasons,
        )

    # Clean profile name (alphanumeric, dashes, underscores)
    safe_profile = re.sub(r"[^A-Za-z0-9_-]", "_", profile.strip())
    if not safe_profile:
        raise ValueError("profile name cannot be empty")

    checks: dict[str, dict[str, Any]] = {}
    for f in report.get("findings", []):
        if f.get("status") == "detected":
            cid = f.get("id", "")
            if cid:
                checks[cid] = {
                    "id": cid,
                    "technique": f.get("technique"),
                    "status": "detected",
                    "measurement": f.get("measurement"),
                    "confidence": f.get("confidence"),
                    "severity": f.get("severity", "medium"),
                }

    host_facts = report.get("host_facts") or {}
    env = report.get("environment") or {}
    platform_name = report.get("platform", "unknown")
    os_name = env.get("os") or platform_name

    baseline_doc = {
        "profile": safe_profile,
        "scan_id": report.get("scan_id", ""),
        "platform": platform_name,
        "os": os_name,
        "build": host_facts.get("os_build", ""),
        "cpu": host_facts.get("cpu_model", ""),
        "date": report.get("generated_at", ""),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "total_checks": len(report.get("findings", [])),
        "checks_fired": len(checks),
        "checks": checks,
    }

    store = Path(store_dir) if store_dir else default_baselines_dir()
    store.mkdir(parents=True, exist_ok=True)
    out_file = store / f"{safe_profile}.json"
    out_file.write_text(json.dumps(baseline_doc, indent=2), encoding="utf-8")

    return baseline_doc


def list_baselines(store_dir: str | Path | None = None) -> list[dict]:
    """List all recorded baseline profiles in the baseline store."""
    store = Path(store_dir) if store_dir else default_baselines_dir()
    if not store.is_dir():
        return []

    rows = []
    for p in sorted(store.glob("*.json")):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(doc, dict) and "profile" in doc and "checks" in doc:
                rows.append(
                    {
                        "profile": doc.get("profile", p.stem),
                        "platform": doc.get("platform", "unknown"),
                        "os": doc.get("os", "unknown"),
                        "build": doc.get("build", ""),
                        "cpu": doc.get("cpu", ""),
                        "date": doc.get("date", ""),
                        "scan_id": doc.get("scan_id", ""),
                        "checks_fired": doc.get("checks_fired", len(doc.get("checks", {}))),
                        "total_checks": doc.get("total_checks", 0),
                        "recorded_at": doc.get("recorded_at", ""),
                        "path": str(p),
                    }
                )
        except Exception:
            continue
    return rows


def resolve_baseline(ident: str | Path | dict, store_dir: str | Path | None = None) -> dict:
    """Resolve a baseline from a dict, a file path, or a profile name in the store."""
    if isinstance(ident, dict):
        if "checks" in ident:
            return ident
        return ident

    path_candidate = Path(ident)
    if path_candidate.is_file():
        try:
            doc = json.loads(path_candidate.read_text(encoding="utf-8"))
            if "checks" in doc:
                return doc
        except Exception as exc:
            raise ValueError(f"could not parse baseline from {ident}: {exc}") from exc

    store = Path(store_dir) if store_dir else default_baselines_dir()
    profile_file = store / f"{ident}.json"
    if profile_file.is_file():
        try:
            return json.loads(profile_file.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ValueError(f"could not parse baseline profile from {profile_file}: {exc}") from exc

    raise FileNotFoundError(f"could not resolve baseline profile or file: '{ident}'")


def show_baseline(profile_or_path: str, store_dir: str | Path | None = None) -> dict:
    """Fetch full baseline profile data."""
    return resolve_baseline(profile_or_path, store_dir)


def apply_baseline_to_findings(findings: Iterable[Any], baseline: dict) -> list[dict]:
    """Apply bare-metal baseline to findings for net exposure scoring.

    Leaves out (marks clean) any check that also fires on bare metal for the same OS.
    """
    baseline_checks = baseline.get("checks", {})
    if isinstance(baseline_checks, dict):
        fired_ids = set(baseline_checks.keys())
    else:
        fired_ids = set(baseline_checks)

    net_findings = []
    for raw in findings:
        f = dict(raw if isinstance(raw, dict) else raw.to_dict())
        cid = f.get("id")
        if cid and cid in fired_ids and f.get("status") == "detected":
            f["status"] = "clean"
            f["bare_metal_baseline_cleared"] = True
        net_findings.append(f)
    return net_findings


def render_baseline_list_text(rows: list[dict], store_path: Path | str | None = None) -> str:
    loc = str(store_path or default_baselines_dir())
    if not rows:
        return f"No bare-metal baselines found in {loc}.\nRecord one with: perdedor baseline record --profile <name> <report.json>"

    header = f"{'PROFILE':<18} {'OS':<10} {'BUILD':<14} {'CPU':<24} {'DATE':<19} {'CHECKS':<6} {'SCAN ID'}"
    lines = [
        f"PERDEDOR Bare-Metal Baselines ({loc})",
        header,
        "-" * len(header),
    ]
    for r in rows:
        date_str = (r.get("date") or "")[:19].replace("T", " ")
        cpu_str = (r.get("cpu") or "-")[:23]
        build_str = (r.get("build") or "-")[:13]
        lines.append(
            f"{r['profile']:<18} {r.get('os', '-'):<10} {build_str:<14} {cpu_str:<24} "
            f"{date_str:<19} {r.get('checks_fired', 0):<6} {r.get('scan_id', '-')}"
        )
    return "\n".join(lines)


def render_baseline_list_markdown(rows: list[dict]) -> str:
    if not rows:
        return "_No bare-metal baselines recorded._"
    lines = [
        "## PERDEDOR Bare-Metal Baselines",
        "| Profile | OS | Build | CPU | Date | Checks Fired | Scan ID |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['profile']} | {r.get('os', '-')} | {r.get('build', '-')} | "
            f"{r.get('cpu', '-')} | {r.get('date', '-')} | {r.get('checks_fired', 0)} | `{r.get('scan_id', '-')}` |"
        )
    return "\n".join(lines)


def render_baseline_show_text(base: dict) -> str:
    checks = base.get("checks", {})
    lines = [
        f"PERDEDOR Bare-Metal Baseline: {base.get('profile', 'unknown')}",
        f"  Scan ID:      {base.get('scan_id', '-')}",
        f"  Platform:     {base.get('platform', '-')}",
        f"  OS:           {base.get('os', '-')}",
        f"  Build:        {base.get('build', '-')}",
        f"  CPU Model:    {base.get('cpu', '-')}",
        f"  Date:         {base.get('date', '-')}",
        f"  Recorded At:  {base.get('recorded_at', '-')}",
        f"  Firing checks on bare metal ({len(checks)}):",
    ]
    if checks:
        for cid, info in sorted(checks.items()):
            tech = info.get("technique") or "unknown"
            meas = info.get("measurement")
            conf = info.get("confidence")
            meas_str = f", measurement={meas}" if meas is not None else ""
            conf_str = f", confidence={conf}" if conf is not None else ""
            lines.append(f"    [+] {cid} ({tech}){conf_str}{meas_str}")
    else:
        lines.append("    (none: completely clean on bare metal)")
    return "\n".join(lines)


def render_baseline_show_markdown(base: dict) -> str:
    checks = base.get("checks", {})
    lines = [
        f"## Baseline: `{base.get('profile', 'unknown')}`",
        f"- **Scan ID**: `{base.get('scan_id', '-')}`",
        f"- **Platform / OS**: {base.get('platform', '-')} / {base.get('os', '-')}",
        f"- **Build**: `{base.get('build', '-')}`",
        f"- **CPU**: `{base.get('cpu', '-')}`",
        f"- **Date**: {base.get('date', '-')}",
        f"- **Recorded**: {base.get('recorded_at', '-')}",
        "",
        f"### Firing Checks on Bare Metal ({len(checks)})",
        "| Check ID | Technique | Confidence | Measurement |",
        "|---|---|---|---|",
    ]
    if checks:
        for cid, info in sorted(checks.items()):
            tech = info.get("technique") or "-"
            conf = f"{info.get('confidence'):.2f}" if info.get("confidence") is not None else "-"
            meas = str(info.get("measurement")) if info.get("measurement") is not None else "-"
            lines.append(f"| `{cid}` | `{tech}` | {conf} | {meas} |")
    else:
        lines.append("| _none_ | - | - | - |")
    return "\n".join(lines)
