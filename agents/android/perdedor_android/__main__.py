"""Entry point: `python -m perdedor_android [-s SERIAL] [-o output.json]`

Drives the target device (or CHIMERA's own qemu-system-aarch64 guest) over
adb. If no device is reachable at all, every check reports `error` with a
clear reason rather than the scan failing outright -- the emitted report is
always schema-valid so it can still be aggregated.

    adb devices                                  # find the serial
    python3 -m perdedor_android -s emulator-5554 -o android-report.json
"""

from __future__ import annotations

import argparse
import json
import sys

from perdedor_common.exposure import headline_text
from perdedor_common.registry import add_selection_arguments, list_doc, parse_params, select

from . import adb
from .runner import all_checks, run_scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="perdedor_android")
    parser.add_argument(
        "-s",
        "--serial",
        type=str,
        default=None,
        help="adb device serial (see `adb devices`); default device if omitted",
    )
    parser.add_argument(
        "-o", "--output", type=str, default=None, help="write JSON report to this path instead of stdout"
    )
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

    if not adb.adb_binary_available():
        print("warning: `adb` not found on PATH -- every check will report as errored", file=sys.stderr)
    elif not adb.device_reachable(args.serial):
        print(
            f"warning: no device reachable at serial={args.serial!r} (see `adb devices`) -- "
            "every check will report as errored",
            file=sys.stderr,
        )

    report = run_scan(
        args.serial,
        profile=args.profile,
        only=args.only,
        skip=args.skip,
        params=params,
        network=not args.no_network,
    ).to_dict()
    text = json.dumps(report, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Wrote report to {args.output}", file=sys.stderr)
    else:
        print(text)

    print(f"PERDEDOR android scan: {headline_text(report)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
