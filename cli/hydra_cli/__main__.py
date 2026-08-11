"""HYDRA CLI: pick a sandbox platform, run its full check suite, get a score.

    hydra test linux
    hydra test android -s emulator-5554
    hydra test windows                    # shells out to the PowerShell agent

Also supports aggregating reports collected from multiple guests into one
unified report:

    hydra report linux-report.json android-report.json windows-report.json -o hydra-report.html
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WINDOWS_AGENT_SCRIPT = _REPO_ROOT / "agents" / "windows" / "Invoke-Hydra.ps1"

_PLATFORMS = ("windows", "linux", "android")


def _run_windows_agent(serial: str | None) -> dict | None:
    """Shell out to the PowerShell agent and return its parsed report, or
    None with an error already printed to stderr."""
    del serial  # the Windows agent has no adb-style serial concept

    if shutil.which("pwsh") is None:
        print(
            "error: `pwsh` (PowerShell 7) not found on PATH. The Windows agent needs .NET's "
            "X86Base CPUID intrinsic, which requires PowerShell 7+ (not Windows PowerShell 5.1).\n"
            f"Run it directly instead: pwsh -File {_WINDOWS_AGENT_SCRIPT}",
            file=sys.stderr,
        )
        return None
    if not _WINDOWS_AGENT_SCRIPT.exists():
        print(
            f"error: Windows agent script not found at {_WINDOWS_AGENT_SCRIPT}\n"
            "(the `hydra` CLI locates it relative to the repo checkout -- this only works "
            "when running from an editable install or the repo itself)",
            file=sys.stderr,
        )
        return None

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_output = Path(tmp_dir) / "windows-report.json"
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-File", str(_WINDOWS_AGENT_SCRIPT), "-OutputPath", str(tmp_output)],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        if result.returncode != 0 or not tmp_output.exists():
            print(f"error: Windows agent failed:\n{result.stdout}\n{result.stderr}", file=sys.stderr)
            return None
        return json.loads(tmp_output.read_text(encoding="utf-8"))


def _run_agent(platform: str, serial: str | None) -> dict | None:
    if platform == "linux":
        from hydra_linux.runner import run_scan

        return run_scan().to_dict()
    if platform == "android":
        from hydra_android.runner import run_scan

        return run_scan(serial).to_dict()
    if platform == "windows":
        return _run_windows_agent(serial)
    raise AssertionError(f"unreachable: unknown platform {platform!r}")  # argparse choices guards this


def _cmd_test(args: argparse.Namespace) -> int:
    report = _run_agent(args.platform, args.serial)
    if report is None:
        return 1

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Wrote JSON report to {args.output}", file=sys.stderr)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        from hydra_common.text_format import render_platform_text

        use_color = None if not args.no_color else False
        print(render_platform_text(report, use_color=use_color, verbose=args.verbose))

    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    from hydra_common.report import aggregate_reports, render_html
    from hydra_common.validation import ValidationError

    reports = []
    for path in args.reports:
        try:
            reports.append(json.loads(Path(path).read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: could not read {path}: {exc}", file=sys.stderr)
            return 1

    try:
        aggregate = aggregate_reports(reports)
    except ValidationError as exc:
        print(f"error: input report does not match the HYDRA schema: {exc}", file=sys.stderr)
        return 1

    if args.json:
        Path(args.json).write_text(json.dumps(aggregate, indent=2), encoding="utf-8")
        print(f"Wrote aggregate JSON to {args.json}", file=sys.stderr)

    output_path = Path(args.output)
    output_path.write_text(render_html(aggregate), encoding="utf-8")
    print(f"Wrote unified report to {output_path}", file=sys.stderr)

    summary = aggregate["overall_summary"]
    platforms = ", ".join(aggregate["platforms"])
    print(
        f"HYDRA unified: {summary['raw_score']} clean, weighted {summary['weighted_score']}/100 across [{platforms}]",
        file=sys.stderr,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hydra", description="HYDRA: cross-platform sandbox-evasion self-test suite for CHIMERA."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    test = subparsers.add_parser(
        "test",
        help="test one sandbox platform against its full check suite and print a score",
    )
    test.add_argument("platform", choices=_PLATFORMS, help="which sandbox this host/device is")
    test.add_argument(
        "-s", "--serial", default=None, help="adb device serial (android only; see `adb devices`)"
    )
    test.add_argument("-o", "--output", default=None, help="also write the raw JSON report to this path")
    test.add_argument(
        "--json", action="store_true", help="print raw JSON instead of the human-readable summary"
    )
    test.add_argument("--verbose", action="store_true", help="list every check, not just detections/errors")
    test.add_argument("--no-color", action="store_true", help="disable ANSI colour in the summary output")
    test.set_defaults(func=_cmd_test)

    report = subparsers.add_parser(
        "report",
        help="aggregate one or more previously-collected JSON reports into one unified HTML+JSON report",
    )
    report.add_argument("reports", nargs="+", help="paths to JSON reports produced by any HYDRA agent")
    report.add_argument(
        "-o",
        "--output",
        default="hydra-report.html",
        help="path to write the unified HTML report (default: %(default)s)",
    )
    report.add_argument("--json", default=None, help="also write the unified aggregate as JSON to this path")
    report.set_defaults(func=_cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
