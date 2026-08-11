"""Human-readable terminal rendering of a single platform report.

HYDRA is CLI-only by design (see cli/hydra_cli) -- this is the primary
output format a user actually sees when they run `hydra test <platform>`,
in the same spirit as Pafish/al-khaser's own console output.
"""

from __future__ import annotations

import sys
from typing import Any

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_STATUS_RANK = {"detected": 0, "error": 1, "skipped": 2, "clean": 3}

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_COLOR = {
    "clean": "\033[32m",  # green
    "detected": "\033[31m",  # red
    "error": "\033[33m",  # yellow
    "skipped": "\033[90m",  # grey
    "critical": "\033[41m\033[97m",  # white-on-red
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[34m",
    "info": "\033[90m",
}


def supports_color(stream: Any = None) -> bool:
    stream = stream or sys.stdout
    return hasattr(stream, "isatty") and stream.isatty()


def _c(text: str, key: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_COLOR.get(key, '')}{text}{_RESET}"


def _sorted_findings(findings: list[dict]) -> list[dict]:
    sev_rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: (_STATUS_RANK[f["status"]], sev_rank.get(f["severity"], 99)))


def _stringify_evidence(evidence: Any) -> str:
    if evidence is None:
        return ""
    if isinstance(evidence, (dict, list)):
        import json

        return json.dumps(evidence)
    return str(evidence)


def render_platform_text(report: dict, *, use_color: bool | None = None, verbose: bool = False) -> str:
    """Render one platform report as a terminal-friendly summary.

    With verbose=False (the default), only detected/error findings are
    listed in detail -- clean/skipped findings are just counted, since a
    long scroll of "clean" lines is noise for the common case of "did
    anything go wrong". Pass verbose=True to list every finding.
    """
    if use_color is None:
        use_color = supports_color()

    s = report["summary"]
    lines: list[str] = []
    lines.append(f"{_BOLD}HYDRA -- {report['platform'].capitalize()} Sandbox-Evasion Self-Test{_RESET}")
    lines.append(f"{_DIM}Host: {report['hostname']}    Generated: {report['generated_at']}{_RESET}")
    lines.append("")
    lines.append(
        f"Score: {_BOLD}{s['raw_score']}{_RESET} clean (applicable checks)"
        f"    Weighted: {_BOLD}{s['weighted_score']}/100{_RESET}"
    )
    lines.append(
        f"{_c(str(s['clean']) + ' clean', 'clean', use_color)}  "
        f"{_c(str(s['detected']) + ' detected', 'detected', use_color)}  "
        f"{_c(str(s['errored']) + ' errored', 'error', use_color)}  "
        f"{_c(str(s['skipped']) + ' skipped', 'skipped', use_color)}  "
        f"({s['total']} total checks)"
    )
    lines.append("")

    findings = _sorted_findings(report["findings"])
    shown = findings if verbose else [f for f in findings if f["status"] in ("detected", "error")]

    if shown:
        lines.append(f"{_BOLD}{'STATUS':10} {'SEVERITY':9} {'CATEGORY':24} CHECK{_RESET}")
        for f in shown:
            status = _c(f["status"].upper().ljust(10), f["status"], use_color)
            severity = _c(f["severity"].upper().ljust(9), f["severity"], use_color)
            lines.append(f"{status} {severity} {f['category']:24} {f['name']}")
            evidence = _stringify_evidence(f.get("evidence"))
            if evidence:
                lines.append(f"{_DIM}    evidence: {evidence}{_RESET}")
            note = f.get("remediation") or f.get("error_detail")
            if note:
                label = "fix" if f.get("remediation") else "reason"
                lines.append(f"{_DIM}    {label}: {note}{_RESET}")
    elif not verbose:
        lines.append(
            _c("No detections or errors -- run with --verbose to see every check.", "clean", use_color)
        )

    return "\n".join(lines)
