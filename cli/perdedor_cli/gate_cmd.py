"""`perdedor gate`: gate a report against a baseline with configurable limits.

Usage:
    perdedor gate <report> --baseline <report|profile> [--max-increase N] [--fail-on-new-class]

Exits with a non-zero code and prints a short reason when the gate policy is violated.
Exits with 0 when the report passes the gate. Never modifies anything.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from perdedor_common.gate import evaluate_gate
from perdedor_common.history import HistoryStore
from perdedor_common.report_reader import read_report


def _resolve_report(ident: str, store: HistoryStore) -> dict:
    p = Path(ident)
    if p.is_file():
        return read_report(p, validate=False)
    doc = store.get(ident)
    if doc:
        return doc
    raise SystemExit(f"error: could not resolve report '{ident}'")


def _resolve_baseline(ident: str, store: HistoryStore, baseline_store: str | None = None) -> dict:
    p = Path(ident)
    if p.is_file():
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(doc, dict) and "checks" in doc and "findings" not in doc:
                return doc
        except Exception:
            pass
        return read_report(p, validate=False)

    from perdedor_common.baseline import resolve_baseline

    try:
        return resolve_baseline(ident, store_dir=baseline_store)
    except Exception:
        pass

    doc = store.get(ident)
    if doc:
        return doc
    raise SystemExit(f"error: could not resolve report or baseline '{ident}'")


def _cmd_gate(args: argparse.Namespace) -> int:
    store = HistoryStore(args.store)
    report_doc = _resolve_report(args.report, store)
    baseline_doc = _resolve_baseline(args.baseline, store, baseline_store=args.store)

    res = evaluate_gate(
        report_doc,
        baseline_doc,
        max_increase=args.max_increase,
        fail_on_new_class=args.fail_on_new_class,
        store=store,
        baseline_store=args.store,
    )

    if res.passed:
        print(f"gate: {res.reason}")
        return 0
    else:
        print(f"gate: {res.reason}", file=sys.stderr)
        return res.exit_code


def register(subparsers) -> None:
    gate = subparsers.add_parser("gate", help="regression gate against a baseline report or profile")
    gate.add_argument("report", help="target PERDEDOR JSON report to evaluate")
    gate.add_argument(
        "--baseline",
        required=True,
        help="baseline report or bare-metal baseline profile (file path, scan_id, or profile name)",
    )
    gate.add_argument(
        "--max-increase",
        type=int,
        default=None,
        help="maximum number of newly firing checks allowed before failing",
    )
    gate.add_argument(
        "--fail-on-new-class",
        action="store_true",
        help="fail if any newly firing check belongs to a class with zero baseline detections",
    )
    gate.add_argument("--store", default=None, help="path to history database or baselines directory")
    gate.set_defaults(func=_cmd_gate)
