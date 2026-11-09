"""Entry point: ``perdedor-ios --ssh root@device [-i key] [-p port]`` or
``perdedor-ios --simulator UDID``.

* ``--ssh``: a jailbroken iPhone/iPad (rootful or rootless; OpenSSH from the
  bootstrap, often forwarded over USB with ``iproxy 2222 22``) or a Corellium
  virtual device's ssh endpoint. Commands come from the bootstrap (Procursus);
  /var/jb paths are added to PATH for rootless jailbreaks.
* ``--simulator``: an iOS Simulator on this Mac (``xcrun simctl list devices``);
  use ``booted`` for the booted one.

    perdedor-ios --ssh root@localhost -p 2222 -o ios-report.json
    perdedor-ios --simulator booted --no-network
"""

from __future__ import annotations

import argparse
import json
import sys

from perdedor_common.registry import add_selection_arguments, list_doc, parse_params, select
from perdedor_macos.__main__ import emit

from .device import IosTarget, SimulatorTransport, ios_ssh
from .runner import all_checks, run_scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="perdedor-ios")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--ssh", metavar="USER@HOST", help="jailbroken or Corellium device over ssh (key auth only)"
    )
    group.add_argument("--simulator", metavar="UDID", help="iOS Simulator device UDID (or 'booted')")
    parser.add_argument("-i", "--identity", help="ssh private key")
    parser.add_argument("-p", "--port", type=int, help="ssh port (2222 with iproxy)")
    parser.add_argument(
        "--ssh-option", action="append", default=[], metavar="OPT", help="extra ssh -o option"
    )
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
    if args.simulator:
        transport = SimulatorTransport(args.simulator)
        if not transport.resolve() and args.simulator != "booted":
            print(f"warning: simulator {args.simulator} not found by simctl", file=sys.stderr)
    elif args.ssh:
        extra = tuple(x for opt in args.ssh_option for x in ("-o", opt))
        transport = ios_ssh(args.ssh, args.identity, args.port, extra)
    else:
        parser.error("choose a target: --ssh USER@HOST or --simulator UDID")
    target = IosTarget(transport)
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
    emit(report, args.output, "ios")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
