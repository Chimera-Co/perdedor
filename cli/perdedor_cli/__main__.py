"""PERDEDOR CLI: pick a sandbox platform, run its full check suite, get a score.

    perdedor test windows                    # native agent (perdedor-windows-x64.exe)
    perdedor test linux --profile deep       # native agent (perdedor-linux-x86_64)
    perdedor test android -s emulator-5554   # adb-driven agent
    perdedor test macos -- --local           # arguments after -- go to the macOS/iOS agent
    perdedor test ios -- --simulator booted

Also supports aggregating reports collected from multiple guests into one
unified report:

    perdedor report linux-report.json android-report.json windows-report.json -o perdedor-report.html
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from perdedor_common.exposure import headline_text

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WINDOWS_AGENT_SCRIPT = _REPO_ROOT / "agents" / "windows" / "Invoke-Perdedor.ps1"

_PLATFORMS = ("windows", "linux", "android", "macos", "ios")
_NATIVE_TARGETS = {"windows": "windows-x64", "linux": "linux-x86_64"}
_NATIVE_TIMEOUT_S = 900  # the deep profile with interactive checks stays well under this


def _native_agent_path(platform: str, explicit: str | None) -> Path | None:
    """The native agent to run: --agent, then $PERDEDOR_AGENT, then the repository build."""
    if explicit:
        return Path(explicit)
    env = os.environ.get("PERDEDOR_AGENT")
    if env:
        return Path(env)
    from perdedor_common.host import TARGETS

    target = _NATIVE_TARGETS[platform]
    if platform == "windows" and _is_32bit_windows():
        target = "windows-x86"
    candidate = _REPO_ROOT / "native" / "build" / TARGETS[target][1]
    return candidate if candidate.is_file() else None


def _is_32bit_windows() -> bool:
    return (
        sys.platform == "win32"
        and os.environ.get("PROCESSOR_ARCHITECTURE", "").upper() == "X86"
        and ("PROCESSOR_ARCHITEW6432" not in os.environ)
    )


def _run_native_agent(platform: str, agent: Path, args: argparse.Namespace) -> dict | None:
    """Run the native C++ agent on this host and return its parsed report."""
    from perdedor_common.host import agent_args, validate_selection

    if not agent.is_file():
        print(f"error: native agent not found: {agent}", file=sys.stderr)
        return None
    try:
        selection = validate_selection(
            {
                "profile": args.profile,
                "only": args.only or [],
                "skip": args.skip or [],
                "network": not args.no_network,
            }
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None
    with tempfile.TemporaryDirectory() as tmp_dir:
        out = Path(tmp_dir) / f"{platform}-report.json"
        try:
            result = subprocess.run(
                [str(agent), *agent_args(selection, str(out))],
                capture_output=True,
                text=True,
                timeout=_NATIVE_TIMEOUT_S,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"error: could not run {agent}: {exc}", file=sys.stderr)
            return None
        if result.returncode != 0 or not out.is_file():
            print(f"error: native agent failed ({result.returncode}):\n{result.stderr}", file=sys.stderr)
            return None
        return json.loads(out.read_text(encoding="utf-8"))


def _run_windows_legacy() -> dict | None:
    """The frozen v1 PowerShell 7 agent, kept only for comparison runs (--engine legacy)."""
    if shutil.which("pwsh") is None:
        print(
            "error: the legacy Windows agent needs PowerShell 7 (`pwsh`). Use the native agent instead: "
            "build it with `make -C native win64` or pass --agent perdedor-windows-x64.exe.",
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


def _run_apple_agent(platform: str, extra: list[str]) -> dict | None:
    """Run the macOS or iOS agent with its own target arguments and return its report."""
    module = {"macos": "perdedor_macos.__main__", "ios": "perdedor_ios.__main__"}[platform]
    with tempfile.TemporaryDirectory() as tmp_dir:
        out = Path(tmp_dir) / f"{platform}-report.json"
        main_fn = __import__(module, fromlist=["main"]).main
        code = main_fn([*extra, "-o", str(out)])
        if code not in (0, None) or not out.is_file():
            print(f"error: the {platform} agent failed (exit {code})", file=sys.stderr)
            return None
        return json.loads(out.read_text(encoding="utf-8"))


def _run_agent(args: argparse.Namespace) -> dict | None:
    platform = args.platform
    if platform in ("macos", "ios"):
        return _run_apple_agent(platform, args.agent_args)
    if platform == "android":
        from perdedor_android.runner import run_scan

        return run_scan(args.serial).to_dict()
    agent = None if args.engine == "legacy" else _native_agent_path(platform, args.agent)
    if args.engine == "native" and agent is None:
        print(
            f"error: no native {platform} agent; build it with `make -C native` or pass --agent",
            file=sys.stderr,
        )
        return None
    if agent is not None:
        return _run_native_agent(platform, agent, args)
    if platform == "linux":
        from perdedor_linux.runner import run_scan

        return run_scan().to_dict()
    return _run_windows_legacy()


def _exposure_summary(report: dict) -> str | None:
    """Two-line exposure headline for the human-readable output, or None if it cannot be scored."""
    try:
        from perdedor_common.catalog import load_catalog
        from perdedor_common.exposure import assess

        a = assess(report["findings"], report["platform"], load_catalog())
    except Exception:  # noqa: BLE001 - the summary is extra; the report itself already printed
        return None
    if a.get("score") is None:
        return None
    return (
        f"Exposure: {a['score']:.1f}/100 [{a['verdict'].upper()}] "
        f"(90 % interval {a['interval'][0]:.1f}-{a['interval'][1]:.1f}, "
        f"trust {a['pillars']['overall']})\n"
        "  Detail: perdedor score <report.json>    Fix order: perdedor plan <report.json>"
    )


def _cmd_test(args: argparse.Namespace) -> int:
    use_color = None if not args.no_color else False

    # The splash banner is decorative terminal output, never emitted in
    # --json mode -- stdout must stay pure JSON there (Chapter 15 of the
    # build guide covers why a caller piping stdout can never see anything
    # else mixed in).
    if not args.json:
        from perdedor_common import __version__
        from perdedor_common.text_format import render_banner

        print(render_banner(use_color=use_color, version=__version__))

    if args.agent_args and args.platform not in ("macos", "ios"):
        print("error: extra agent arguments are only for macos and ios", file=sys.stderr)
        return 2
    report = _run_agent(args)
    if report is None:
        return 1

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Wrote JSON report to {args.output}", file=sys.stderr)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        from perdedor_common.text_format import render_platform_text

        print(render_platform_text(report, use_color=use_color, verbose=args.verbose))
        summary = _exposure_summary(report)
        if summary:
            print(summary)

    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    from perdedor_common.report import aggregate_reports, render_html
    from perdedor_common.validation import ValidationError

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
        print(f"error: input report does not match the PERDEDOR schema: {exc}", file=sys.stderr)
        return 1

    if args.json:
        Path(args.json).write_text(json.dumps(aggregate, indent=2), encoding="utf-8")
        print(f"Wrote aggregate JSON to {args.json}", file=sys.stderr)

    output_path = Path(args.output)
    output_path.write_text(render_html(aggregate), encoding="utf-8")
    print(f"Wrote unified report to {output_path}", file=sys.stderr)

    for report in aggregate["reports"]:
        print(f"PERDEDOR {report['platform']}: {headline_text(report)}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="perdedor", description="PERDEDOR: cross-platform sandbox-evasion self-test suite for CHIMERA."
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
    test.add_argument(
        "--engine",
        choices=("auto", "native", "legacy"),
        default="auto",
        help="windows/linux: the native agent (auto uses it when built) or the frozen v1 agent",
    )
    test.add_argument("--agent", default=None, help="path to the native agent binary (windows/linux)")
    test.add_argument("--profile", choices=("quick", "standard", "deep"), default="standard")
    test.add_argument(
        "--only", nargs="+", metavar="PATTERN", help="id globs or class:/technique:/cost: selectors"
    )
    test.add_argument("--skip", nargs="+", metavar="PATTERN", help="selectors to leave out")
    test.add_argument("--no-network", action="store_true", help="skip checks that use the network")
    test.set_defaults(func=_cmd_test)

    report = subparsers.add_parser(
        "report",
        help="aggregate one or more previously-collected JSON reports into one unified HTML+JSON report",
    )
    report.add_argument("reports", nargs="+", help="paths to JSON reports produced by any PERDEDOR agent")
    report.add_argument(
        "-o",
        "--output",
        default="perdedor-report.html",
        help="path to write the unified HTML report (default: %(default)s)",
    )
    report.add_argument("--json", default=None, help="also write the unified aggregate as JSON to this path")
    report.set_defaults(func=_cmd_report)

    from perdedor_cli import assess_cmd

    assess_cmd.register(subparsers)

    from perdedor_cli import upstream

    upstream.register(subparsers)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Everything after "--" is handed to the macOS/iOS agent untouched (its target arguments).
    agent_extra: list[str] = []
    if "--" in argv:
        cut = argv.index("--")
        argv, agent_extra = argv[:cut], argv[cut + 1 :]
    parser = build_parser()
    args = parser.parse_args(argv)
    args.agent_args = agent_extra
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
