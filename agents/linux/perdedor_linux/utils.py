"""Small filesystem/process helpers shared by the Linux check modules.

Every function here fails soft (returns None / empty rather than raising) so
that one unreadable path never takes down an entire scan -- the caller turns
absence of data into a `skipped` or `error` finding as appropriate.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def read_text(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def any_signature_in(haystack: str | None, signatures: tuple[str, ...] | dict[str, str]) -> str | None:
    """Return the matched signature key, or None if haystack is empty/no match."""
    if not haystack:
        return None
    lowered = haystack.lower()
    for signature in signatures:
        if signature.lower() in lowered:
            return signature
    return None


def run(cmd: list[str], timeout: float = 5.0) -> str | None:
    """Run a command and return stdout, or None if it fails/is unavailable."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout
