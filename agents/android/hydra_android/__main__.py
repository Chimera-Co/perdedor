"""Entry point: `python -m hydra_android [-s SERIAL] [-o output.json]`

Drives the target device (or CHIMERA's own qemu-system-aarch64 guest) over
adb. If no device is reachable at all, every check reports `error` with a
clear reason rather than the scan failing outright -- the emitted report is
always schema-valid so it can still be aggregated.

    adb devices                                  # find the serial
    python3 -m hydra_android -s emulator-5554 -o android-report.json
"""

from __future__ import annotations

import argparse
import json
import sys

from . import adb
from .runner import run_scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hydra_android")
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
    args = parser.parse_args(argv)

    if not adb.adb_binary_available():
        print("warning: `adb` not found on PATH -- every check will report as errored", file=sys.stderr)
    elif not adb.device_reachable(args.serial):
        print(
            f"warning: no device reachable at serial={args.serial!r} (see `adb devices`) -- "
            "every check will report as errored",
            file=sys.stderr,
        )

    report = run_scan(args.serial).to_dict()
    text = json.dumps(report, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Wrote report to {args.output}", file=sys.stderr)
    else:
        print(text)

    summary = report["summary"]
    print(
        f"HYDRA android scan: {summary['raw_score']} clean, weighted {summary['weighted_score']}/100 "
        f"({summary['errored']} errored, {summary['skipped']} skipped)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
