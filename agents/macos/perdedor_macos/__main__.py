"""Entry point: ``perdedor-macos --local`` or ``perdedor-macos --ssh user@host [-i key] [-p port]``.

Runs on the analyst machine (or on the Mac itself with --local) and executes
only commands that ship with macOS on the target. Nothing is installed; the
driver performs read-only observations using standard commands.

    perdedor-macos --local -o macos-report.json
    perdedor-macos --ssh analyst@10.0.0.5 -i ~/.ssh/id_ed25519 --profile deep
"""

from __future__ import annotations

import argparse
import json
import sys

from perdedor_common.registry import add_selection_arguments, list_doc, parse_params, select

from .runner import all_checks, run_scan
from .target import Target
from .transport import LocalTransport, SshTransport


def add_target_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--local", action="store_true", help="probe the machine this runs on")
    group.add_argument("--ssh", metavar="USER@HOST", help="probe a remote target over ssh (key auth only)")
    parser.add_argument("-i", "--identity", help="ssh private key")
    parser.add_argument("-p", "--port", type=int, help="ssh port")
    parser.add_argument(
        "--ssh-option",
        action="append",
        default=[],
        metavar="OPT",
        help="extra ssh -o option (repeatable), e.g. StrictHostKeyChecking=accept-new",
    )


def make_transport(args):
    if args.ssh:
        extra = tuple(x for opt in args.ssh_option for x in ("-o", opt))
        return SshTransport(args.ssh, identity=args.identity, port=args.port, extra_options=extra)
    return LocalTransport()


def emit(report: dict, output: str | None, label: str) -> None:
    text = json.dumps(report, indent=2)
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"Wrote report to {output}", file=sys.stderr)
    else:
        print(text)
    summary = report["summary"]
    print(
        f"PERDEDOR {label} scan: {summary['raw_score']} clean, weighted {summary['weighted_score']}/100 "
        f"({summary['errored']} errored, {summary['skipped']} skipped)",
        file=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="perdedor-macos")
    add_target_arguments(parser)
    parser.add_argument("-o", "--output", help="write the JSON report here instead of stdout")
    add_selection_arguments(parser)
    args = parser.parse_args(argv)
    try:
        params = parse_params(args.param)
    except ValueError as exc:
        parser.error(str(exc))
    if args.list_checks:
        chosen = select(
            all_checks(), profile=args.profile, only=args.only, skip=args.skip, network=not args.no_network
        )
        print(json.dumps(list_doc(chosen), indent=2))
        return 0
    if not args.local and not args.ssh:
        parser.error("choose a target: --local or --ssh USER@HOST")
    target = Target(make_transport(args), platform="macos")
    if not target.reachable():
        print("warning: target unreachable -- every check will report as errored", file=sys.stderr)
    report = run_scan(
        target,
        profile=args.profile,
        only=args.only,
        skip=args.skip,
        params=params,
        network=not args.no_network,
    ).to_dict()
    emit(report, args.output, "macos")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
