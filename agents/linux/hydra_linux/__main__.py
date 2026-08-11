"""Entry point: `python -m hydra_linux [-o output.json]`

Runs every check and writes a schema-conformant JSON report. With no -o,
prints to stdout so it can be piped straight off the guest, e.g.:

    ssh sandbox-run 'python3 -m hydra_linux' > linux-report.json
"""

from __future__ import annotations

import argparse
import json
import sys

from .runner import run_scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hydra_linux")
    parser.add_argument(
        "-o", "--output", type=str, default=None, help="write JSON report to this path instead of stdout"
    )
    args = parser.parse_args(argv)

    report = run_scan().to_dict()
    text = json.dumps(report, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Wrote report to {args.output}", file=sys.stderr)
    else:
        print(text)

    summary = report["summary"]
    print(
        f"HYDRA linux scan: {summary['raw_score']} clean, weighted {summary['weighted_score']}/100 "
        f"({summary['errored']} errored, {summary['skipped']} skipped)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
