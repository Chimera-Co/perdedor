"""Host-side helpers for running the native agent inside a guest.

A sandbox controller (a console, a CI job, a script) uses these to:

* build or reuse the statically linked agent for the guest's platform (``native_binary``),
* validate an operator's selection before it reaches the guest (``validate_selection``),
* turn that selection into agent arguments, one per line for ``--args-file`` (``agent_args``),
* describe the selectable checks for a user interface (``check_tree``).
"""

from __future__ import annotations

import fcntl
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .catalog import Catalog, load_catalog

PROFILES = ("quick", "standard", "deep")
SELECTOR_PREFIXES = ("class", "category", "technique", "cost", "tag", "id")
COSTS = ("fast", "medium", "slow")
TARGETS = {
    # target -> (make target, output file)
    "windows-x64": ("win64", "perdedor-windows-x64.exe"),
    "windows-x86": ("win32", "perdedor-windows-x86.exe"),
    "linux-x86_64": ("linux", "perdedor-linux-x86_64"),
}
CATEGORY_ORDER = ("environment_artifact", "timing", "behavioural_interaction", "design_specific")
_GLOB = re.compile(r"^[A-Za-z0-9_.*?\[\]!-]{1,160}$")
_PARAM_KEY = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)*$")
MAX_SELECTORS = 400
MAX_PARAMS = 64


class SelectionError(ValueError):
    """An operator selection the agent would reject; ``field`` names the offending option."""

    def __init__(self, message: str, field: str):
        super().__init__(message)
        self.field = field


class BuildError(RuntimeError):
    pass


def validate_selector(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise SelectionError(f"{field}: selectors must be strings, got {type(value).__name__}", field)
    v = value.strip()
    if ":" in v:
        prefix, rest = v.split(":", 1)
        if prefix not in SELECTOR_PREFIXES:
            raise SelectionError(
                f"{field}: unknown selector '{prefix}:' (use one of {', '.join(SELECTOR_PREFIXES)})", field)
        if prefix == "cost" and rest not in COSTS:
            raise SelectionError(f"{field}: cost must be one of {', '.join(COSTS)}", field)
        if not _GLOB.match(rest):
            raise SelectionError(f"{field}: '{v}' has characters a selector cannot contain", field)
        return v
    if not _GLOB.match(v):
        raise SelectionError(f"{field}: '{v}' is not a check id or glob", field)
    return v


def _as_list(raw: Any, field: str) -> list:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [p for p in re.split(r"[,\s]+", raw) if p]
    if not isinstance(raw, list):
        raise SelectionError(f"{field} must be a list of check ids or selectors", field)
    return raw


def validate_selection(options: Mapping[str, Any]) -> dict:
    """Normalise {profile, only, skip, params, network}; raise SelectionError on anything invalid."""
    profile = options.get("profile") or "standard"
    if profile not in PROFILES:
        raise SelectionError(f"profile must be one of {', '.join(PROFILES)}", "profile")
    sel: dict = {"profile": profile}
    for field in ("only", "skip"):
        raw = _as_list(options.get(field), field)
        if len(raw) > MAX_SELECTORS:
            raise SelectionError(f"{field}: at most {MAX_SELECTORS} entries", field)
        sel[field] = sorted({validate_selector(x, field) for x in raw})
    params = options.get("params") or {}
    if isinstance(params, list):  # ["key=value", ...]
        pairs = {}
        for p in params:
            if not isinstance(p, str) or "=" not in p:
                raise SelectionError(f"params: '{p}' is not key=value", "params")
            k, v = p.split("=", 1)
            pairs[k.strip()] = v.strip()
        params = pairs
    if not isinstance(params, dict) or len(params) > MAX_PARAMS:
        raise SelectionError(f"params must be a mapping of at most {MAX_PARAMS} entries", "params")
    clean = {}
    for k, v in params.items():
        if not isinstance(k, str) or not _PARAM_KEY.match(k):
            raise SelectionError(f"params: invalid key '{k}' (lowercase words joined by dots)", "params")
        if isinstance(v, bool) or not isinstance(v, (str, int, float)):
            raise SelectionError(f"params: value of '{k}' must be text or a number", "params")
        v = str(v)
        if len(v) > 200 or any(c in v for c in "\r\n\0"):
            raise SelectionError(f"params: value of '{k}' is too long or has control characters", "params")
        clean[k] = v
    sel["params"] = dict(sorted(clean.items()))
    network = options.get("network", True)
    if not isinstance(network, bool):
        raise SelectionError("network must be true or false", "network")
    sel["network"] = network
    return sel


def agent_args(selection: Mapping[str, Any], output: str) -> list[str]:
    """Agent arguments for a validated selection, suitable for an --args-file (one per line)."""
    args = ["-o", output, "--profile", selection["profile"]]
    if selection.get("only"):
        args += ["--only", *selection["only"]]
    if selection.get("skip"):
        args += ["--skip", *selection["skip"]]
    if selection.get("params"):
        args += ["--param", *[f"{k}={v}" for k, v in selection["params"].items()]]
    if not selection.get("network", True):
        args.append("--no-network")
    return args


def _newest_source(native: Path) -> float:
    newest = 0.0
    for root in (native / "src", native / "Makefile"):
        paths: Iterable[Path] = [root] if root.is_file() else root.rglob("*")
        for p in paths:
            if p.is_file():
                newest = max(newest, p.stat().st_mtime)
    return newest


def native_binary(repo_root: Path | str, target: str, *, timeout: float = 900) -> Path:
    """Path to the agent for ``target`` (see TARGETS), building it with ``make`` when it is missing
    or older than its sources. Builds are serialised with a lock file, so concurrent scans share one."""
    if target not in TARGETS:
        raise BuildError(f"unknown native target {target!r}; known: {', '.join(TARGETS)}")
    native = Path(repo_root) / "native"
    if not (native / "Makefile").is_file():
        raise BuildError(f"no native agent sources under {native}")
    make_target, name = TARGETS[target]
    build = native / "build"
    out = build / name
    build.mkdir(parents=True, exist_ok=True)
    with open(build / ".lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if out.is_file() and out.stat().st_mtime >= _newest_source(native):
            return out
        try:
            proc = subprocess.run(
                ["make", "-C", str(native), make_target], capture_output=True, text=True, timeout=timeout,
                env={**os.environ, "MAKEFLAGS": f"-j{os.cpu_count() or 2}"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BuildError(f"building the {target} agent failed: {exc}") from exc
        if proc.returncode != 0 or not out.is_file():
            tail = "\n".join((proc.stderr or proc.stdout).strip().splitlines()[-12:])
            raise BuildError(f"building the {target} agent failed (make {make_target}):\n{tail}")
        return out


def check_tree(platform: str, catalog: Catalog | None = None) -> list[dict]:
    """Selectable checks for a user interface, grouped category -> class -> checks."""
    catalog = catalog or load_catalog()
    groups: dict[str, dict[str, list]] = {}
    for c in sorted(catalog.checks_for(platform), key=lambda c: c["id"]):
        tech = catalog.technique(c["technique"]) or {}
        klass = tech.get("class", "other")
        cat = catalog.class_category(klass) if klass in catalog.classes else "other"
        groups.setdefault(cat, {}).setdefault(klass, []).append({
            "id": c["id"], "technique": c["technique"], "title": tech.get("title", c["technique"]),
            "cost": c.get("cost", "fast"), "network": bool(c.get("network", False)),
            "severity": c.get("severity"),
        })
    tree = []
    for cat in (*CATEGORY_ORDER, "other"):
        if cat not in groups:
            continue
        tree.append({
            "category": cat,
            "classes": [
                {"class": k, "title": catalog.classes.get(k, {}).get("title", k), "checks": v}
                for k, v in sorted(groups[cat].items())
            ],
        })
    return tree


def known_params() -> Sequence[dict]:
    """Agent parameters every build understands (native/src/core/registry.cpp)."""
    return [
        {"key": "watchdog.fast_s", "default": "10", "note": "time limit for a fast check, seconds"},
        {"key": "watchdog.medium_s", "default": "45", "note": "time limit for a medium check, seconds"},
        {"key": "watchdog.slow_s", "default": "240", "note": "time limit for a slow check, seconds"},
    ]
