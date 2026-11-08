#!/usr/bin/env python3
"""Run the native Linux agent against fixture root trees and check key verdicts.

Each fixture in native/tests/fixtures/linux/<name>.json describes a file tree
({"files": {path: content}, "dirs": [...], "links": {path: target}}) and the
findings it must produce ({"expect": {"detected": [...], "not_detected": [...]}}).
The tree is materialised in a temporary directory and passed to the agent through
PERDEDOR_ROOT, which every file-reading Linux check honours. Ids are given
without the "linux." prefix. Standard library only, so it runs wherever the
agent builds.

Usage: linux_fixtures.py <path-to-perdedor-linux-binary>
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures" / "linux"
# Generous bound: a full run against a fixture takes well under a second.
RUN_TIMEOUT_S = 120


def materialise(spec: dict, root: Path) -> None:
    for d in spec.get("dirs", []):
        (root / d.lstrip("/")).mkdir(parents=True, exist_ok=True)
    for path, content in spec.get("files", {}).items():
        p = root / path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    for path, target in spec.get("links", {}).items():
        p = root / path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, p)


def run(binary: str, root: Path) -> dict:
    env = dict(os.environ, PERDEDOR_ROOT=str(root))
    for var in ("container", "TZ", "LANG", "LC_ALL"):
        env.pop(var, None)
    out = subprocess.run(
        [binary, "--no-network", "--only", "linux.*"],
        env=env,
        capture_output=True,
        text=True,
        timeout=RUN_TIMEOUT_S,
        check=False,
    )
    if out.returncode not in (0, 1):
        raise RuntimeError(f"agent exited {out.returncode}: {out.stderr[-500:]}")
    return json.loads(out.stdout)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    binary = sys.argv[1]
    failures = 0
    for fx in sorted(FIXTURES.glob("*.json")):
        spec = json.loads(fx.read_text())
        with tempfile.TemporaryDirectory(prefix=f"perdedor-{fx.stem}-") as tmp:
            materialise(spec, Path(tmp))
            report = run(binary, Path(tmp))
        status = {f["id"].removeprefix("linux."): f["status"] for f in report["findings"]}
        bad = []
        for cid in spec["expect"].get("detected", []):
            if status.get(cid) != "detected":
                bad.append(f"{cid}: expected detected, got {status.get(cid, 'absent')}")
        for cid in spec["expect"].get("not_detected", []):
            if cid not in status:
                bad.append(f"{cid}: absent from the report")
            elif status[cid] == "detected":
                bad.append(f"{cid}: expected not detected")
        hits = sum(1 for s in status.values() if s == "detected")
        if bad:
            failures += 1
            print(f"FAIL {fx.stem} ({hits} detected)")
            for b in bad:
                print(f"  {b}")
        else:
            print(f"ok   {fx.stem} ({hits} detected)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
