"""Entry point: `python -m perdedor_linux [-o output.json] [selection flags]`

Runs the selected checks (all of the standard profile by default) and writes a
schema-conformant JSON report. With no -o, prints to stdout so it can be piped
straight off the guest, e.g.:

    ssh sandbox-run 'python3 -m perdedor_linux --profile deep' > linux-report.json
"""

from __future__ import annotations

import argparse
import json
import sys

from perdedor_common.exposure import headline_text
from perdedor_common.registry import add_selection_arguments, list_doc, parse_params, select

from .runner import all_checks, run_scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="perdedor_linux")
    parser.add_argument(
        "-o", "--output", type=str, default=None, help="write JSON report to this path instead of stdout"
    )
    add_selection_arguments(parser)
    args = parser.parse_args(argv)
    try:
        params = parse_params(args.param)
        if args.list_checks:
            chosen = select(
                all_checks(),
                profile=args.profile,
                only=args.only,
                skip=args.skip,
                network=not args.no_network,
            )
            print(json.dumps(list_doc(chosen), indent=2))
            return 0
        report = run_scan(
            profile=args.profile, only=args.only, skip=args.skip, params=params, network=not args.no_network
        ).to_dict()
    except ValueError as exc:
        parser.error(str(exc))
    text = json.dumps(report, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Wrote report to {args.output}", file=sys.stderr)
    else:
        print(text)

    print(f"PERDEDOR linux scan: {headline_text(report)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
