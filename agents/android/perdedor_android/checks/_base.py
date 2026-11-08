"""Shared machinery for the Android check modules.

A check is a function ``fn(dev: Device, ctx: RunContext) -> Verdict`` that is
registered with ``Checks.check(...)``. The wrapper

* returns ``error`` when no device is reachable (never ``clean``),
* turns ``Skip`` into ``skipped`` and ``ProbeError`` into ``error``,
* builds the Finding in the category of the technique's class,
* attaches the remediation only when the tell is present.

Underscore modules are not scanned by ``perdedor_common.discovery``.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from perdedor_common.models import Finding, Platform, Severity, Status
from perdedor_common.registry import CLASS_CATEGORY, CheckSpec, RunContext, spec

from .. import signatures
from ..adb import AdbTransport, Device

UNREACHABLE = "adb command failed or no device reachable at the given serial"
_DEVICE_ATTR = "_perdedor_android_device"


class Skip(Exception):
    """The probe does not apply here (feature absent, wrong ABI...)."""


class ProbeError(Exception):
    """The probe should have worked and could not collect its data."""


@dataclass
class Verdict:
    detected: bool
    evidence: Any = None
    confidence: float | None = None
    measurement: dict | None = None
    severity: Severity | None = None  # override the registered severity (rare)


def device_for(ctx: RunContext) -> Device:
    """One cached Device per scan. ``ctx.target`` is an adb serial, None (default
    device) or a transport object (tests)."""
    dev = getattr(ctx, _DEVICE_ATTR, None)
    if dev is None:
        target = ctx.target
        transport = target if hasattr(target, "shell") else AdbTransport(target)
        dev = Device(transport, path_universe=signatures.all_paths())
        setattr(ctx, _DEVICE_ATTR, dev)
    return dev


class Checks:
    """Per-module registry: ``CHECKS = REG.specs``."""

    def __init__(self) -> None:
        self.specs: list[CheckSpec] = []

    def check(
        self,
        check_id: str,
        technique: str,
        *,
        name: str,
        description: str,
        severity: Severity,
        remediation: str,
        cost: str = "medium",
        network: bool = False,
        tags: Sequence[str] = (),
    ) -> Callable:
        category = CLASS_CATEGORY[technique.split(".", 1)[0]]

        def deco(fn: Callable[[Device, RunContext], Verdict]) -> Callable:
            def make(status: Status, sev: Severity, **kw: Any) -> Finding:
                return Finding(
                    id=check_id,
                    category=category,
                    platform=Platform.ANDROID,
                    name=name,
                    description=description,
                    status=status,
                    severity=sev,
                    **kw,
                )

            def run(ctx: RunContext) -> Finding:
                dev = device_for(ctx)
                if not dev.reachable():
                    return make(Status.ERROR, severity, error_detail=UNREACHABLE)
                dev.deadline = time.monotonic() + (100 if cost == "slow" else 9)
                try:
                    verdict = fn(dev, ctx)
                except Skip as exc:
                    return make(Status.SKIPPED, severity, error_detail=str(exc))
                except ProbeError as exc:
                    return make(Status.ERROR, severity, error_detail=str(exc))
                sev = verdict.severity or severity
                return make(
                    Status.DETECTED if verdict.detected else Status.CLEAN,
                    sev,
                    evidence=verdict.evidence,
                    remediation=remediation if verdict.detected else None,
                    confidence=verdict.confidence,
                    measurement=verdict.measurement,
                )

            run.catalog_metadata = {"severity": severity.value, "remediation": remediation}
            run.__name__ = fn.__name__
            run.__doc__ = fn.__doc__
            self.specs.append(spec(check_id, run, technique, cost=cost, network=network, tags=tags))
            return fn

        return deco


# --------------------------------------------------------------------------- helpers used by checks


def need(value: Any, what: str) -> Any:
    """Raise ProbeError when a read returned None."""
    if value is None:
        raise ProbeError(f"could not read {what}")
    return value


def props(dev: Device) -> dict[str, str]:
    return need(dev.props(), "the system property dump (getprop)")


def token_re(tokens: Iterable[str]) -> re.Pattern[str]:
    """Case-insensitive match of any token that starts a word (``nox`` matches
    ``nox_x86`` but not ``equinox``)."""
    alts = "|".join(re.escape(t) for t in sorted(set(tokens), key=len, reverse=True))
    return re.compile(rf"(?<![a-z0-9])(?:{alts})", re.IGNORECASE)


def substr_hits(value: str, tokens: Iterable[str]) -> list[str]:
    low = value.lower()
    return [t for t in tokens if t.lower() in low]


def existing(dev: Device, paths: Iterable[str]) -> list[str]:
    return need(dev.existing(paths), "path existence on the device")


def packages(dev: Device, kind: str = "all") -> list[str]:
    return need(dev.packages(kind), f"the package list (pm list packages, {kind})")


def features(dev: Device) -> set[str]:
    return need(dev.features(), "the feature list (pm list features)")


def settings(dev: Device, namespace: str) -> dict[str, str]:
    return need(dev.settings(namespace), f"settings list {namespace}")


def processes(dev: Device) -> list[dict[str, str]]:
    return need(dev.processes(), "the process list (ps)")


def prop_hits(values: dict[str, str], keys: Iterable[str], pattern: re.Pattern[str]) -> dict[str, str]:
    """Properties among ``keys`` whose value matches ``pattern``."""
    return {k: values[k] for k in keys if values.get(k) and pattern.search(values[k])}


def to_int(value: str | None) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None
