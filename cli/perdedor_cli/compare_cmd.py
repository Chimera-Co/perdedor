"""`perdedor compare`: compare two reports and show diffs and score deltas.

Usage:
    perdedor compare reportA.json reportB.json
    perdedor compare <scan_id_A> <scan_id_B>
    perdedor compare --json reportA.json reportB.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from perdedor_common.compare import compare_reports, render_compare_markdown, render_compare_text
from perdedor_common.history import HistoryStore
from perdedor_common.report_reader import read_report


def _resolve_report(target: str, store: HistoryStore) -> dict:
    p = Path(target)
    if p.is_file():
        return read_report(p, validate=False)
    doc = store.get(target)
    if doc:
        return doc
    raise SystemExit(f"error: could not resolve report from file or history: '{target}'")


def _cmd_compare(args: argparse.Namespace) -> int:
    store = HistoryStore(args.store)
    doc_a = _resolve_report(args.report_a, store)
    doc_b = _resolve_report(args.report_b, store)

    diff = compare_reports(doc_a, doc_b, baseline=args.baseline, baseline_store=args.store)

    fmt = args.format.lower()
    if args.json or fmt == "json":
        print(json.dumps(diff, indent=2))
    elif args.markdown or fmt in ("markdown", "md"):
        print(render_compare_markdown(diff))
    else:
        print(render_compare_text(diff))

    return 0


def register(subparsers) -> None:
    parser = subparsers.add_parser("compare", help="compare two reports: new tells, fixes, score deltas")
    parser.add_argument("report_a", help="baseline report (file path, scan_id, or profile)")
    parser.add_argument("report_b", help="target report (file path, scan_id, or profile)")
    parser.add_argument(
        "--baseline",
        default=None,
        help="bare-metal baseline profile or file to evaluate net exposure deltas",
    )
    parser.add_argument(
        "--format", choices=("text", "json", "markdown", "md"), default="text", help="output format"
    )
    parser.add_argument("--json", action="store_true", help="output as JSON")
    parser.add_argument("--markdown", action="store_true", help="output as Markdown")
    parser.add_argument("--store", default=None, help="path to history database")
    parser.set_defaults(func=_cmd_compare)
