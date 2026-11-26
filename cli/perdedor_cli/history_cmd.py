"""`perdedor history`: local report history tracking.

Commands:
    perdedor history add <report.json>
    perdedor history list --profile standard
    perdedor history list --format json
    perdedor history list --format markdown
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from perdedor_common.history import HistoryStore, render_history_markdown, render_history_text


def _cmd_history_add(args: argparse.Namespace) -> int:
    store = HistoryStore(args.store)
    path = Path(args.report)
    if not path.is_file():
        print(f"error: report file not found: {args.report}", file=sys.stderr)
        return 1
    try:
        rec = store.add(path)
    except Exception as exc:
        print(f"error: failed to add report to history: {exc}", file=sys.stderr)
        return 1

    score_str = f"{rec['score']:.1f}/100" if rec.get("score") is not None else "no score"
    print(
        f"Stored report {rec['scan_id']} ({rec['platform']}, profile: {rec['profile']}, "
        f"score: {score_str}, {rec['detected']}/{rec['total']} detected)"
    )
    return 0


def _cmd_history_list(args: argparse.Namespace) -> int:
    store = HistoryStore(args.store)
    try:
        rows = store.list(profile=args.profile, platform=args.platform, limit=args.limit)
    except Exception as exc:
        print(f"error: failed to list history: {exc}", file=sys.stderr)
        return 1

    fmt = args.format.lower()
    if args.json or fmt == "json":
        print(json.dumps(rows, indent=2))
    elif args.markdown or fmt in ("markdown", "md"):
        print(render_history_markdown(rows))
    else:
        print(render_history_text(rows))
    return 0


def register(subparsers) -> None:
    history = subparsers.add_parser("history", help="manage local report history store")
    sub = history.add_subparsers(dest="history_command", required=True)

    add_parser = sub.add_parser("add", help="store a report in local history")
    add_parser.add_argument("report", help="path to a PERDEDOR JSON report")
    add_parser.add_argument("--store", default=None, help="path to history database")
    add_parser.set_defaults(func=_cmd_history_add)

    list_parser = sub.add_parser("list", help="list reports stored in local history")
    list_parser.add_argument("--profile", default=None, help="filter by profile (quick, standard, deep)")
    list_parser.add_argument("--platform", default=None, help="filter by platform")
    list_parser.add_argument(
        "--format", choices=("text", "json", "markdown", "md"), default="text", help="output format"
    )
    list_parser.add_argument(
        "--json", action="store_true", help="output as JSON (shortcut for --format json)"
    )
    list_parser.add_argument(
        "--markdown", action="store_true", help="output as Markdown table (shortcut for --format markdown)"
    )
    list_parser.add_argument("--limit", type=int, default=100, help="maximum reports to list")
    list_parser.add_argument("--store", default=None, help="path to history database")
    list_parser.set_defaults(func=_cmd_history_list)
