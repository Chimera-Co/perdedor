"""`perdedor baseline`: manage bare-metal baselines for net exposure scoring.

Commands:
    perdedor baseline record --profile <name> <report.json> [--store <dir>] [--force]
    perdedor baseline list [--store <dir>] [--format text|json|markdown]
    perdedor baseline show <profile> [--store <dir>] [--format text|json|markdown]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from perdedor_common.baseline import (
    VMRefusalError,
    list_baselines,
    record_baseline,
    render_baseline_list_markdown,
    render_baseline_list_text,
    render_baseline_show_markdown,
    render_baseline_show_text,
    show_baseline,
)


def _cmd_record(args: argparse.Namespace) -> int:
    report_path = Path(args.report)
    if not report_path.is_file():
        print(f"error: report file not found: {args.report}", file=sys.stderr)
        return 1

    try:
        doc = record_baseline(report_path, args.profile, store_dir=args.store, force=args.force)
    except VMRefusalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"error: failed to record baseline: {exc}", file=sys.stderr)
        return 1

    print(
        f"Recorded baseline '{doc['profile']}' for {doc['platform']} ({doc['os']}): "
        f"{doc['checks_fired']} check(s) fire on bare metal (scan: {doc['scan_id']})"
    )
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    try:
        rows = list_baselines(store_dir=args.store)
    except Exception as exc:
        print(f"error: failed to list baselines: {exc}", file=sys.stderr)
        return 1

    fmt = args.format.lower()
    if args.json or fmt == "json":
        print(json.dumps(rows, indent=2))
    elif args.markdown or fmt in ("markdown", "md"):
        print(render_baseline_list_markdown(rows))
    else:
        print(render_baseline_list_text(rows, store_path=args.store))
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    try:
        doc = show_baseline(args.profile, store_dir=args.store)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"error: failed to load baseline: {exc}", file=sys.stderr)
        return 1

    fmt = args.format.lower()
    if args.json or fmt == "json":
        print(json.dumps(doc, indent=2))
    elif args.markdown or fmt in ("markdown", "md"):
        print(render_baseline_show_markdown(doc))
    else:
        print(render_baseline_show_text(doc))
    return 0


def register(subparsers) -> None:
    parser = subparsers.add_parser("baseline", help="manage bare-metal baselines for net exposure scoring")
    sub = parser.add_subparsers(dest="baseline_command", required=True)

    # record
    rec = sub.add_parser("record", help="record a bare-metal baseline from a real machine report")
    rec.add_argument("report", help="path to PERDEDOR JSON report produced on a real machine")
    rec.add_argument("--profile", required=True, help="name for the baseline profile")
    rec.add_argument(
        "--store",
        default=None,
        help="directory to store baselines (default: ~/.local/share/perdedor/baselines)",
    )
    rec.add_argument(
        "--force",
        action="store_true",
        help="force recording even if environment block or host facts indicate a virtual machine",
    )
    rec.set_defaults(func=_cmd_record)

    # list
    lst = sub.add_parser("list", help="list recorded bare-metal baseline profiles")
    lst.add_argument("--store", default=None, help="directory to store baselines")
    lst.add_argument(
        "--format", choices=("text", "json", "markdown", "md"), default="text", help="output format"
    )
    lst.add_argument("--json", action="store_true", help="output as JSON")
    lst.add_argument("--markdown", action="store_true", help="output as Markdown table")
    lst.set_defaults(func=_cmd_list)

    # show
    shw = sub.add_parser("show", help="show details of a bare-metal baseline profile")
    shw.add_argument("profile", help="baseline profile name or path to a baseline JSON file")
    shw.add_argument("--store", default=None, help="directory to store baselines")
    shw.add_argument(
        "--format", choices=("text", "json", "markdown", "md"), default="text", help="output format"
    )
    shw.add_argument("--json", action="store_true", help="output as JSON")
    shw.add_argument("--markdown", action="store_true", help="output as Markdown")
    shw.set_defaults(func=_cmd_show)
