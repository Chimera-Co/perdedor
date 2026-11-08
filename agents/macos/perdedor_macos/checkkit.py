"""Small helpers that turn a probe function into a registered check.

A probe takes ``(target, ctx)`` and returns one of:

* :class:`Verdict` -- the probe looked; ``detected`` says whether the tell is present;
* :class:`Skip` -- not applicable on this target (wrong architecture, no Wi-Fi hardware...);
* :class:`Fail` -- the probe should have worked and did not.

:func:`build` wraps it into a ``CheckSpec`` whose finding carries the right
category (from the technique's class), platform, severity and remediation.
An unreachable target always yields ``error``, never ``clean``.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import time
from typing import Any

from perdedor_common import FindingFactory
from perdedor_common.models import Finding, Platform, Severity
from perdedor_common.registry import CLASS_CATEGORY, CheckSpec, RunContext, spec

from . import parsing
from .target import Target
from .transport import join_paths

UNREACHABLE = "target unreachable: ssh/simctl failed or the command timed out"


@dataclass(frozen=True)
class Verdict:
    detected: bool
    evidence: Any = None
    measurement: dict | None = None
    confidence: float | None = None
    severity: Severity | None = None  # override (e.g. decisive vendor string)


@dataclass(frozen=True)
class Skip:
    reason: str


@dataclass(frozen=True)
class Fail:
    reason: str


Result = Verdict | Skip | Fail
Probe = Callable[[Target, RunContext], Result]


@dataclass(frozen=True)
class Meta:
    id: str
    technique: str
    name: str
    description: str
    severity: Severity
    remediation: str


def _factory(platform: Platform, technique: str) -> FindingFactory:
    return FindingFactory(category=CLASS_CATEGORY[technique.split(".", 1)[0]], platform=platform)


def to_finding(platform: Platform, meta: Meta, result: Result) -> Finding:
    f = _factory(platform, meta.technique)
    if isinstance(result, Skip):
        return f.skipped(meta.id, meta.name, meta.description, meta.severity, result.reason)
    if isinstance(result, Fail):
        return f.error(meta.id, meta.name, meta.description, meta.severity, result.reason)
    severity = result.severity or meta.severity
    finding = f.bool_check(
        meta.id,
        meta.name,
        meta.description,
        severity,
        is_detected=result.detected,
        evidence=result.evidence,
        remediation=meta.remediation,
    )
    if result.measurement is not None or result.confidence is not None:
        from dataclasses import replace

        finding = replace(finding, measurement=result.measurement, confidence=result.confidence)
    return finding


def build(
    platform: Platform,
    meta: Meta,
    probe: Probe,
    *,
    cost: str = "medium",
    network: bool = False,
    tags: Sequence[str] = (),
) -> CheckSpec:
    def run(ctx: RunContext) -> Finding:
        target = ctx.target
        if target is None:
            return to_finding(platform, meta, Fail("no target configured"))
        target.deadline = time.monotonic() + (100 if cost == "slow" else 9)
        if not target.reachable():
            return to_finding(platform, meta, Fail(UNREACHABLE))
        target.transport.deadline = target.deadline
        return to_finding(platform, meta, probe(target, ctx))

    run.__name__ = "check_" + meta.id.rsplit(".", 1)[-1]
    run.__doc__ = meta.description
    run.metadata = meta
    return spec(meta.id, run, meta.technique, cost=cost, network=network, tags=tags)


# -- reusable probe factories ---------------------------------------------------------


def paths_probe(paths: Sequence[str], prefixes: Sequence[str] = ("",)) -> Probe:
    """Detected when any of ``paths`` (under any prefix) exists."""
    candidates = join_paths(prefixes, paths)

    def probe(target: Target, ctx: RunContext) -> Result:
        found = target.exists(candidates)
        if found is None:
            return Fail(UNREACHABLE)
        hits = [p for p in candidates if p in found]
        return Verdict(bool(hits), {"found": hits, "checked": len(candidates)})

    return probe


def process_probe(names: Sequence[str]) -> Probe:
    """Detected when a running process matches one of ``names``."""

    def probe(target: Target, ctx: RunContext) -> Result:
        procs = target.processes()
        if procs is None:
            return Fail(UNREACHABLE + " (ps)")
        hits = parsing.matching_processes(procs, names)
        return Verdict(bool(hits), {"processes": hits[:20], "total_processes": len(procs)})

    return probe


def sysctl_value(target: Target, name: str) -> tuple[str | None, Result | None]:
    """(value, None) or (None, Fail) when sysctl itself could not run."""
    values = target.sysctl()
    if values is None:
        return None, Fail(UNREACHABLE + " (sysctl)")
    return values.get(name), None


def app_bundles(target: Target, directories: Sequence[str]) -> tuple[list[str], list[str]]:
    """``*.app`` names found in ``directories`` (one level, plus one level
    below for container layouts such as /var/containers/Bundle/Application/<UUID>/X.app)
    and the directories that could not be read."""
    names: list[str] = []
    unreadable: list[str] = []
    for directory in directories:
        listing = target.listdir(directory)
        if listing is None or listing.entries is None:
            if listing is None or listing.error != "missing":
                unreadable.append(directory)
            continue
        for entry in listing.entries:
            if entry.endswith(".app"):
                names.append(entry)
    return names, unreadable


def count_entries(target: Target, path: str) -> tuple[int | None, str | None]:
    """(visible entry count, None) or (None, reason)."""
    listing = target.listdir(path)
    if listing is None:
        return None, UNREACHABLE
    if listing.entries is None:
        return None, f"{path}: {listing.error}"
    return len([e for e in listing.entries if not e.startswith(".")]), None
