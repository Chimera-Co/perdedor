#!/usr/bin/env python3
"""Every place that states the Perdedor version must agree (and match a release tag, if given).

python scripts/check_version.py            # consistency only
python scripts/check_version.py v2.0.0     # also require this tag
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "pyproject.toml": r'^version\s*=\s*"([^"]+)"',
    "common/python/perdedor_common/__init__.py": r'^__version__\s*=\s*"([^"]+)"',
    "common/python/perdedor_common/models.py": r'perdedor_version:\s*str\s*=\s*"([^"]+)"',
    "native/src/core/perdedor.hpp": r'kVersion\s*=\s*"([^"]+)"',
    "agents/windows/common/Perdedor.Common.psm1": r"\$PerdedorVersion\s*=\s*'([^']+)'",
}


def main() -> int:
    found = {}
    for rel, pattern in SOURCES.items():
        m = re.search(pattern, (ROOT / rel).read_text(encoding="utf-8"), re.M)
        if not m:
            print(f"FAIL: no version found in {rel}", file=sys.stderr)
            return 1
        found[rel] = m.group(1)
    versions = set(found.values())
    for rel, v in found.items():
        print(f"{v:<12} {rel}")
    if len(versions) != 1:
        print("FAIL: versions disagree", file=sys.stderr)
        return 1
    if len(sys.argv) > 1:
        tag = sys.argv[1].removeprefix("refs/tags/")
        if tag != f"v{versions.pop()}":
            print(f"FAIL: tag {tag} does not match version v{found['pyproject.toml']}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
