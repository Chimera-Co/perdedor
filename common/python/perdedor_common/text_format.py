"""Human-readable terminal rendering of a single platform report.

PERDEDOR is CLI-only by design (see cli/perdedor_cli) -- this is the primary
output format a user actually sees when they run `perdedor test <platform>`,
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

# Block-letter "PERDEDOR" wordmark, 8 chars x 7 rows. Kept as a plain literal
# (not generated at runtime) so the exact glyph shapes are easy to eyeball
# and diff -- see docs/BUILD_GUIDE_VOL2 for how it was originally generated.
_BANNER_ART = r"""
████   █████  ████   ███    █████  ███     ███   ████
█   █  █      █   █  █  █   █      █  █   █   █  █   █
█   █  █      █   █  █   █  █      █   █  █   █  █   █
████   ████   ████   █   █  ████   █   █  █   █  ████
█      █      █ █    █   █  █      █   █  █   █  █ █
█      █      █  █   █  █   █      █  █   █   █  █  █
█      █████  █   █  ███    █████  ███     ███   █   █
""".strip("\n")

_BANNER_TAGLINE = "Cross-Platform Sandbox-Evasion Self-Test Suite"
_BANNER_WIDTH = max(len(line) for line in _BANNER_ART.splitlines())


def supports_color(stream: Any = None) -> bool:
    stream = stream or sys.stdout
    return hasattr(stream, "isatty") and stream.isatty()


def render_banner(*, use_color: bool | None = None, version: str | None = None) -> str:
    """Render the CLI's startup splash screen.

    A fixed-width block-letter wordmark plus a centered tagline/version line
    underneath -- shown once, before a `perdedor test <platform>` run, in
    every output mode except --json (Chapter 15 of the build guide covers
    why --json must never share stdout with anything else).
    """
    if use_color is None:
        use_color = supports_color()

    art = _BANNER_ART
    if use_color:
        art = "\n".join(f"{_BOLD}\033[36m{line}{_RESET}" for line in art.splitlines())

    subtitle = _BANNER_TAGLINE if version is None else f"{_BANNER_TAGLINE}  (v{version})"
    subtitle = subtitle.center(_BANNER_WIDTH)
    if use_color:
        subtitle = f"{_DIM}{subtitle}{_RESET}"

    return f"{art}\n{subtitle}\n"


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

    bold = _BOLD if use_color else ""
    dim = _DIM if use_color else ""
    reset = _RESET if use_color else ""

    s = report["summary"]
    lines: list[str] = []
    lines.append(f"{bold}PERDEDOR -- {report['platform'].capitalize()} Sandbox-Evasion Self-Test{reset}")
    lines.append(f"{dim}Host: {report['hostname']}    Generated: {report['generated_at']}{reset}")
    lines.append("")
    lines.append(
        f"Score: {bold}{s['raw_score']}{reset} clean (applicable checks)"
        f"    Weighted: {bold}{s['weighted_score']}/100{reset}"
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
        lines.append(f"{bold}{'STATUS':10} {'SEVERITY':9} {'CATEGORY':24} CHECK{reset}")
        for f in shown:
            status = _c(f["status"].upper().ljust(10), f["status"], use_color)
            severity = _c(f["severity"].upper().ljust(9), f["severity"], use_color)
            lines.append(f"{status} {severity} {f['category']:24} {f['name']}")
            evidence = _stringify_evidence(f.get("evidence"))
            if evidence:
                lines.append(f"{dim}    evidence: {evidence}{reset}")
            note = f.get("remediation") or f.get("error_detail")
            if note:
                label = "fix" if f.get("remediation") else "reason"
                lines.append(f"{dim}    {label}: {note}{reset}")
    elif not verbose:
        lines.append(
            _c("No detections or errors -- run with --verbose to see every check.", "clean", use_color)
        )

    return "\n".join(lines)
