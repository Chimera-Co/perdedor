#!/usr/bin/env python3
"""Verify a built native agent: its checks match the catalog, and a real run produces a valid report.

    python scripts/verify_native_agent.py native/build/perdedor-linux-x86_64 --platform linux
    python scripts/verify_native_agent.py perdedor-windows-x64.exe --platform windows --profile standard

Exits non-zero on any inconsistency. When GITHUB_STEP_SUMMARY is set (GitHub Actions), a markdown
summary of the run and its exposure score is appended to it.
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "common" / "python"))

from perdedor_common.catalog import load_catalog  # noqa: E402
from perdedor_common.exposure import assess  # noqa: E402
from perdedor_common.host import native_registry  # noqa: E402
from perdedor_common.validation import validate_report  # noqa: E402


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--platform", required=True, choices=["windows", "linux", "android", "macos", "ios"])
    ap.add_argument("--profile", default="quick", choices=["quick", "standard", "deep"])
    ap.add_argument("--timeout", type=float, default=900)
    ap.add_argument("--label", default=None, help="name shown in the job summary")
    args = ap.parse_args()

    binary = str(Path(args.binary).resolve())
    catalog = load_catalog()
    known = {c["id"]: c for c in catalog.checks.values() if c["platform"] == args.platform}

    listed = subprocess.run([binary, "--profile", "deep", "--list-checks"], capture_output=True, timeout=120)
    if listed.returncode != 0:
        fail(f"--list-checks exited {listed.returncode}: {listed.stderr.decode(errors='replace')[-400:]}")
    specs = json.loads(listed.stdout)
    ids = [i for s in specs for i in s["ids"]]
    if len(ids) != len(set(ids)):
        dupes = [i for i, n in collections.Counter(ids).items() if n > 1]
        fail(f"check ids registered more than once: {dupes}")
    unknown = sorted(set(ids) - set(known))
    if unknown:
        fail(f"{len(unknown)} check ids are not in the catalog for {args.platform}: {unknown[:20]}")
    wrong_tech = sorted(i for s in specs for i in s["ids"] if known[i]["technique"] != s["technique"])
    if wrong_tech:
        fail(f"technique differs between binary and catalog for: {wrong_tech[:20]}")
    not_impl = sorted(i for i in ids if known[i]["status"] != "implemented")
    if not_impl:
        fail(f"catalog does not mark these as implemented: {not_impl[:20]}")
    print(f"{len(ids)} checks in {len(specs)} probes, all in the catalog")

    # Controllers read the registry from the sources (perdedor_common.host.native_registry) to build
    # their check lists without running a guest binary; that reading must match the binary exactly.
    if args.platform in ("windows", "linux"):

        def key(spec):
            return (tuple(spec["ids"]), spec["technique"], spec["cost"], bool(spec["network"]))

        from_src = sorted(key(x) for x in native_registry(ROOT, args.platform))
        from_bin = sorted(key(x) for x in specs)
        if from_src != from_bin:
            fail(
                f"source registry differs from the binary: only in sources {sorted(set(from_src) - set(from_bin))[:5]}, "
                f"only in binary {sorted(set(from_bin) - set(from_src))[:5]}"
            )
        print("source registry matches the binary")

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.json"
        start = time.monotonic()
        run = subprocess.run(
            [binary, "--profile", args.profile, "-o", str(out)], capture_output=True, timeout=args.timeout
        )
        elapsed = time.monotonic() - start
        sys.stderr.write(run.stderr.decode(errors="replace"))
        if run.returncode != 0:
            fail(f"agent exited {run.returncode}")
        report = json.loads(out.read_text(encoding="utf-8"))

    validate_report(report, source=binary)
    if report["platform"] != args.platform:
        fail(f"report platform is {report['platform']!r}, expected {args.platform!r}")
    findings = report["findings"]
    fids = [f["id"] for f in findings]
    if len(fids) != len(set(fids)):
        fail("duplicate finding ids in the report")
    if set(fids) - set(ids):
        fail(f"report has findings for unregistered checks: {sorted(set(fids) - set(ids))[:10]}")
    if not math.isfinite(report["summary"]["weighted_score"]):
        fail("summary.weighted_score is not finite")
    statuses = collections.Counter(f["status"] for f in findings)
    watchdog = [
        f["id"] for f in findings if f["status"] == "error" and "watchdog" in (f.get("description") or "")
    ]
    a = assess(findings, args.platform, catalog, draws=200)

    label = args.label or Path(binary).name
    meta = report.get("agent_metadata", {})
    print(
        f"{label}: {len(findings)} findings in {elapsed:.1f}s {dict(statuses)}; "
        f"exposure {a.get('score')} ({a.get('verdict')}); metadata {json.dumps(meta)[:300]}"
    )
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        lines = [
            f"### {label} ({args.platform}, {args.profile})",
            "",
            f"{len(findings)} findings in {elapsed:.1f} s: "
            + ", ".join(f"{k} {v}" for k, v in sorted(statuses.items())),
            "",
        ]
        if a.get("score") is not None:
            lines += [
                f"Exposure score **{a['score']:.1f}/100** ({a['verdict']}), 90 % interval "
                f"{a['interval'][0]:.1f}-{a['interval'][1]:.1f}, coverage {a['coverage']:.0%}. "
                "A CI runner is itself a virtual machine, so detections here are expected.",
                "",
            ]
            if a["detected"]:
                lines += ["| technique | checks |", "|---|---|"]
                lines += [f"| {d['technique']} | {', '.join(d['checks'][:4])} |" for d in a["detected"][:15]]
                lines.append("")
        if watchdog:
            lines += [f"Watchdog expired for: {', '.join(watchdog)}", ""]
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
