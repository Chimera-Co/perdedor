"""Host-side helpers for running the native agent inside a guest.

A sandbox controller (a console, a CI job, a script) uses these to:

* build or reuse the statically linked agent for the guest's platform (``native_binary``),
* validate an operator's selection before it reaches the guest (``validate_selection``),
* turn that selection into agent arguments, one per line for ``--args-file`` (``agent_args``),
* describe the selectable checks for a user interface (``check_tree``).
"""

from __future__ import annotations

import os
import re
import subprocess
from fnmatch import fnmatchcase
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
                f"{field}: unknown selector '{prefix}:' (use one of {', '.join(SELECTOR_PREFIXES)})", field
            )
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
        try:  # Unix hosts build the agents; elsewhere (Windows) there is nothing to serialise against
            import fcntl

            fcntl.flock(lock, fcntl.LOCK_EX)
        except ImportError:
            pass
        if out.is_file() and out.stat().st_mtime >= _newest_source(native):
            return out
        try:
            proc = subprocess.run(
                ["make", "-C", str(native), make_target],
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, "MAKEFLAGS": f"-j{os.cpu_count() or 2}"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BuildError(f"building the {target} agent failed: {exc}") from exc
        if proc.returncode != 0 or not out.is_file():
            tail = "\n".join((proc.stderr or proc.stdout).strip().splitlines()[-12:])
            raise BuildError(f"building the {target} agent failed (make {make_target}):\n{tail}")
        return out


_PLATFORM_SOURCES = {"windows": ("common", "windows"), "linux": ("common", "linux")}
_ID_PREFIX = {"windows": "win", "linux": "linux"}
_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _split_args(body: str) -> list[str]:
    args, depth, cur, quote = [], 0, [], False
    for i, ch in enumerate(body):
        if quote:
            cur.append(ch)
            if ch == '"' and body[i - 1] != "\\":
                quote = False
            continue
        if ch == '"':
            quote = True
        elif ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    args.append("".join(cur).strip())
    return args


def native_registry(repo_root: Path | str, platform: str) -> list[dict]:
    """The checks the native agent registers for ``platform``, read from its sources (every
    PERDEDOR_REGISTER(fn, technique, cost, network, ids...) under src/common and src/<platform>),
    so a controller can list them without running a guest binary. Empty if there is no native tree."""
    if platform not in _PLATFORM_SOURCES:
        return []
    src = Path(repo_root) / "native" / "src"
    out = []
    for sub in _PLATFORM_SOURCES[platform]:
        for path in sorted((src / sub).glob("*.cpp")):
            text = path.read_text(encoding="utf-8", errors="replace")
            pos = 0
            while (start := text.find("PERDEDOR_REGISTER(", pos)) != -1:
                i = start + len("PERDEDOR_REGISTER(")
                depth, j, quote = 1, i, False
                while j < len(text) and depth:
                    ch = text[j]
                    if quote:
                        if ch == '"' and text[j - 1] != "\\":
                            quote = False
                    elif ch == '"':
                        quote = True
                    elif ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                    j += 1
                pos = j
                args = _split_args(text[i : j - 1])
                if len(args) < 5:
                    continue
                lits = [_STRING.fullmatch(a) for a in args[1:3]]
                ids = [m.group(1) for a in args[4:] if (m := _STRING.fullmatch(a))]
                if not all(lits) or not ids:
                    continue
                out.append(
                    {
                        "ids": [f"{_ID_PREFIX[platform]}.{x}" for x in ids],
                        "technique": lits[0].group(1),
                        "cost": lits[1].group(1),
                        "network": args[3] == "true",
                        "source": f"{path.relative_to(src).as_posix()}",
                    }
                )
    return out


def native_coverage(repo_root: Path | str, platform: str, catalog: Catalog | None = None) -> float:
    """Share of the catalog's implemented checks for ``platform`` that the native agent registers."""
    catalog = catalog or load_catalog()
    wanted = {c["id"] for c in catalog.checks_for(platform)}
    if not wanted:
        return 0.0
    have = {i for spec in native_registry(repo_root, platform) for i in spec["ids"]}
    return len(wanted & have) / len(wanted)


def check_tree(
    platform: str, catalog: Catalog | None = None, repo_root: Path | str | None = None
) -> list[dict]:
    """Selectable checks for a user interface, grouped category -> class -> checks. With ``repo_root``,
    cost and network come from the native registry; checks only the native agent has are included."""
    catalog = catalog or load_catalog()
    native = {
        i: spec for spec in (native_registry(repo_root, platform) if repo_root else []) for i in spec["ids"]
    }
    entries = {c["id"]: c for c in catalog.checks_for(platform)}
    for cid, spec in native.items():
        entries.setdefault(cid, {"id": cid, "technique": spec["technique"]})
    groups: dict[str, dict[str, list]] = {}
    for c in sorted(entries.values(), key=lambda c: c["id"]):
        tech = catalog.technique(c["technique"]) or {}
        spec = native.get(c["id"], {})
        klass = tech.get("class", "other")
        cat = catalog.class_category(klass) if klass in catalog.classes else "other"
        groups.setdefault(cat, {}).setdefault(klass, []).append(
            {
                "id": c["id"],
                "technique": c["technique"],
                "title": tech.get("title", c["technique"]),
                # cost/network live in the native registry; the catalog states them only when known
                "cost": spec.get("cost", c.get("cost")),
                "network": spec.get("network", c.get("network")),
                "native": c["id"] in native,
                "tier": tech.get("tier"),
            }
        )
    tree = []
    for cat in (*CATEGORY_ORDER, "other"):
        if cat not in groups:
            continue
        tree.append(
            {
                "category": cat,
                "classes": [
                    {"class": k, "title": catalog.classes.get(k, {}).get("title", k), "checks": v}
                    for k, v in sorted(groups[cat].items())
                ],
            }
        )
    return tree


def _matches(pattern: str, check_id: str, technique: str, catalog: Catalog) -> bool | None:
    """Mirror of the native pattern_matches (native/src/core/registry.cpp) over catalog data.
    Returns None for cost:/tag: selectors, which only the native registry can answer."""
    if ":" not in pattern:
        return fnmatchcase(check_id, pattern)
    kind, value = pattern.split(":", 1)
    value = value.strip()
    tech = catalog.technique(technique) or {}
    klass = tech.get("class", "")
    if kind == "id":
        return fnmatchcase(check_id, value)
    if kind == "technique":
        return fnmatchcase(technique, value)
    if kind == "class":
        return fnmatchcase(klass, value)
    if kind == "category":
        return fnmatchcase(catalog.class_category(klass) if klass in catalog.classes else "", value)
    return None


def select_findings(
    findings: Sequence[Mapping[str, Any]], selection: Mapping[str, Any], catalog: Catalog | None = None
) -> tuple[list, list[str]]:
    """Apply a selection's only/skip to the findings of an agent that cannot select checks itself
    (the v1 agents always run their full suite). Returns (kept findings, notes for the operator).
    Profiles do not apply after the fact; cost:/tag: selectors are reported as not applicable."""
    catalog = catalog or load_catalog()
    notes, unanswerable = [], set()
    only, skip = list(selection.get("only") or []), list(selection.get("skip") or [])
    kept = []
    for f in findings:
        cid, tech = f.get("id", ""), f.get("technique") or (catalog.check(f.get("id", "")) or {}).get(
            "technique", ""
        )
        if only:
            hits = [_matches(p, cid, tech, catalog) for p in only]
            unanswerable.update(p for p, h in zip(only, hits, strict=True) if h is None)
            if not any(hits):
                continue
        hits = [_matches(p, cid, tech, catalog) for p in skip]
        unanswerable.update(p for p, h in zip(skip, hits, strict=True) if h is None)
        if any(hits):
            continue
        kept.append(f)
    if selection.get("profile", "standard") != "standard" or only or skip:
        notes.append("This agent always runs its full suite; the selection was applied to its results.")
    if unanswerable:
        notes.append(
            f"Not applicable to this agent's results (no cost/tag data): {', '.join(sorted(unanswerable))}"
        )
    return kept, notes


def known_params() -> Sequence[dict]:
    """Agent parameters every build understands (native/src/core/registry.cpp)."""
    return [
        {"key": "watchdog.fast_s", "default": "10", "note": "time limit for a fast check, seconds"},
        {"key": "watchdog.medium_s", "default": "45", "note": "time limit for a medium check, seconds"},
        {"key": "watchdog.slow_s", "default": "240", "note": "time limit for a slow check, seconds"},
    ]
