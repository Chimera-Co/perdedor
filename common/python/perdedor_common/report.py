"""Aggregate one or more parsed PERDEDOR platform reports into a single unified
report (JSON) and a self-contained HTML rendering of it.

This is the "one suite, three platforms" half of the design: a Windows
report, a Linux report, and an Android report -- each produced independently
by their own agent -- are combined here into one comparable artifact.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from .models import Severity
from .scoring import SEVERITY_WEIGHT
from .validation import validate_report

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_STATUS_COLOR = {
    "clean": "#1a7f37",
    "detected": "#cf222e",
    "error": "#9a6700",
    "skipped": "#57606a",
}
_SEVERITY_COLOR = {
    "critical": "#82071e",
    "high": "#cf222e",
    "medium": "#9a6700",
    "low": "#0969da",
    "info": "#57606a",
}


def aggregate_reports(reports: list[dict], *, validate: bool = True) -> dict:
    """Combine multiple platform reports into one unified report dict."""
    if validate:
        for i, report in enumerate(reports):
            validate_report(report, source=f"reports[{i}]")

    total = clean = detected = errored = skipped = 0
    penalty = 0.0
    applicable = 0
    for report in reports:
        s = report["summary"]
        total += s["total"]
        clean += s["clean"]
        detected += s["detected"]
        errored += s["errored"]
        skipped += s["skipped"]
        for finding in report["findings"]:
            if finding["status"] == "detected":
                penalty += SEVERITY_WEIGHT[Severity(finding["severity"])]
        applicable += s["clean"] + s["detected"]

    overall_weighted = 100.0 if applicable == 0 else max(0.0, 100.0 * (1.0 - penalty / applicable))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platforms": [r["platform"] for r in reports],
        "reports": reports,
        "overall_summary": {
            "total": total,
            "clean": clean,
            "detected": detected,
            "errored": errored,
            "skipped": skipped,
            "raw_score": f"{clean}/{applicable}" if applicable else "0/0",
            "weighted_score": round(overall_weighted, 2),
        },
    }


def render_html(aggregate: dict) -> str:
    parts: list[str] = [_HTML_HEAD, _summary_block(aggregate)]
    for report in aggregate["reports"]:
        parts.append(_platform_block(report))
    parts.append("</body></html>")
    return "\n".join(parts)


def _summary_block(aggregate: dict) -> str:
    s = aggregate["overall_summary"]
    platforms = ", ".join(p.capitalize() for p in aggregate["platforms"]) or "none"
    return f"""
<header>
  <h1>PERDEDOR Unified Evasion-Probe Report</h1>
  <p class="meta">Generated {html.escape(aggregate['generated_at'])} &middot; Platforms tested: {html.escape(platforms)}</p>
  <div class="score-row">
    <div class="score-card"><div class="score-num">{html.escape(s['raw_score'])}</div><div class="score-label">clean / applicable</div></div>
    <div class="score-card"><div class="score-num">{s['weighted_score']}</div><div class="score-label">weighted score (0-100)</div></div>
    <div class="score-card detected"><div class="score-num">{s['detected']}</div><div class="score-label">detected</div></div>
    <div class="score-card errored"><div class="score-num">{s['errored']}</div><div class="score-label">errored</div></div>
    <div class="score-card skipped"><div class="score-num">{s['skipped']}</div><div class="score-label">skipped</div></div>
  </div>
</header>
"""


def _platform_block(report: dict) -> str:
    s = report["summary"]
    rows = "\n".join(_finding_row(f) for f in _sorted_findings(report["findings"]))
    return f"""
<section>
  <h2>{html.escape(report['platform'].capitalize())} &mdash; {html.escape(report['hostname'])}</h2>
  <p class="meta">PERDEDOR {html.escape(report['perdedor_version'])} &middot; {html.escape(report['generated_at'])} &middot;
     raw {html.escape(s['raw_score'])} &middot; weighted {s['weighted_score']}</p>
  <table>
    <thead><tr><th>Status</th><th>Severity</th><th>Category</th><th>Check</th><th>Evidence</th><th>Remediation</th></tr></thead>
    <tbody>
{rows}
    </tbody>
  </table>
</section>
"""


def _sorted_findings(findings: list[dict]) -> list[dict]:
    status_rank = {"detected": 0, "error": 1, "skipped": 2, "clean": 3}
    sev_rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: (status_rank[f["status"]], sev_rank.get(f["severity"], 99)))


def _finding_row(f: dict) -> str:
    status_color = _STATUS_COLOR.get(f["status"], "#000")
    sev_color = _SEVERITY_COLOR.get(f["severity"], "#000")
    evidence = _stringify_evidence(f.get("evidence"))
    remediation = f.get("remediation") or f.get("error_detail") or "&mdash;"
    return (
        "      <tr>"
        f'<td><span class="pill" style="background:{status_color}">{html.escape(f["status"])}</span></td>'
        f'<td><span class="pill" style="background:{sev_color}">{html.escape(f["severity"])}</span></td>'
        f"<td>{html.escape(f['category'])}</td>"
        f"<td><strong>{html.escape(f['name'])}</strong><br><span class='desc'>{html.escape(f['description'])}</span></td>"
        f"<td><code>{html.escape(evidence)}</code></td>"
        f"<td>{html.escape(str(remediation))}</td>"
        "</tr>"
    )


def _stringify_evidence(evidence: Any) -> str:
    if evidence is None:
        return ""
    if isinstance(evidence, (dict, list)):
        import json

        return json.dumps(evidence)
    return str(evidence)


_HTML_HEAD = """<!doctype html>
<html><head><meta charset="utf-8"><title>PERDEDOR Report</title>
<style>
:root { color-scheme: light dark; }
body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; margin: 2rem auto; max-width: 1100px; padding: 0 1rem; line-height: 1.4; }
header { border-bottom: 2px solid #444; padding-bottom: 1rem; margin-bottom: 1.5rem; }
h1 { margin-bottom: 0.25rem; }
.meta { color: #666; font-size: 0.9rem; }
.score-row { display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 1rem; }
.score-card { border: 1px solid #ccc; border-radius: 8px; padding: 0.75rem 1.25rem; text-align: center; min-width: 100px; }
.score-num { font-size: 1.6rem; font-weight: 700; }
.score-label { font-size: 0.75rem; color: #666; text-transform: uppercase; letter-spacing: 0.03em; }
section { margin-bottom: 2.5rem; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th, td { text-align: left; padding: 0.5rem 0.6rem; border-bottom: 1px solid #ddd; vertical-align: top; }
th { background: rgba(127,127,127,0.08); }
.pill { color: #fff; border-radius: 999px; padding: 0.1rem 0.6rem; font-size: 0.75rem; white-space: nowrap; }
.desc { color: #777; font-size: 0.8rem; }
code { font-size: 0.8rem; word-break: break-word; }
</style></head>
<body>"""
