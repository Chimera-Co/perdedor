"""Check registry and operator selection, shared by every Python agent.

Each agent module declares its checks as ``CheckSpec`` entries instead of a
bare ``run_all()`` list, so the runner knows *before* running anything which
technique and class a check implements, how expensive it is and whether it
touches the network. That is what lets an operator choose exactly what runs:

    --profile quick|standard|deep     cost ceiling (deep also unlocks waits)
    --only PATTERN ...                keep matching checks (OR)
    --skip PATTERN ...                drop matching checks (wins over --only)
    --param key=value ...             tune individual probes (iterations...)
    --no-network                      drop checks that send packets

A PATTERN is an fnmatch glob tested against the check id, or a qualified
selector: ``class:timing``, ``category:design_specific``,
``technique:cpu.*``, ``cost:slow``, ``tag:needs-root``.

The PowerShell agent mirrors these semantics in Perdedor.Common.psm1
(Select-PerdedorChecks); tests/test_registry.py pins both to the same cases.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import inspect
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .models import Category, Finding, Platform, Severity, Status

COSTS = ("fast", "medium", "slow")
PROFILES = {
    # profile -> highest cost it runs
    "quick": "fast",
    "standard": "medium",
    "deep": "slow",
}

# Classes roll up into the four detection categories (catalog/classes.json).
CLASS_CATEGORY = {
    "cpu": Category.ENVIRONMENT_ARTIFACT,
    "firmware": Category.ENVIRONMENT_ARTIFACT,
    "hardware": Category.ENVIRONMENT_ARTIFACT,
    "resources": Category.ENVIRONMENT_ARTIFACT,
    "guest_tools": Category.ENVIRONMENT_ARTIFACT,
    "artifacts": Category.ENVIRONMENT_ARTIFACT,
    "container": Category.ENVIRONMENT_ARTIFACT,
    "emulator": Category.ENVIRONMENT_ARTIFACT,
    "mobile_device": Category.ENVIRONMENT_ARTIFACT,
    "timing": Category.TIMING,
    "human": Category.BEHAVIOURAL_INTERACTION,
    "wear_and_tear": Category.BEHAVIOURAL_INTERACTION,
    "identity": Category.DESIGN_SPECIFIC,
    "analysis_tools": Category.DESIGN_SPECIFIC,
    "debugger": Category.DESIGN_SPECIFIC,
    "instrumentation": Category.DESIGN_SPECIFIC,
    "network": Category.DESIGN_SPECIFIC,
    "os_config": Category.DESIGN_SPECIFIC,
    "integrity": Category.DESIGN_SPECIFIC,
}


@dataclass
class RunContext:
    """Handed to every check function that accepts a ``ctx`` parameter."""

    platform: Platform
    profile: str = "standard"
    params: dict[str, str] = field(default_factory=dict)
    network: bool = True
    target: Any = None  # adb serial / ssh transport for remote agents

    def param(self, key: str, default: Any, cast: Callable[[str], Any] | None = None) -> Any:
        """Operator override for a probe parameter, cast to the default's type."""
        if key not in self.params:
            return default
        caster = cast or (type(default) if default is not None else str)
        if caster is bool:
            return self.params[key].lower() in ("1", "true", "yes", "on")
        try:
            return caster(self.params[key])
        except (TypeError, ValueError):
            return default

    @property
    def deep(self) -> bool:
        return self.profile == "deep"


@dataclass(frozen=True)
class CheckSpec:
    """One registered check. ``ids`` lists every finding id the function can
    emit (most emit exactly one; table-driven probes such as the Linux DMI
    fields emit several)."""

    ids: tuple[str, ...]
    func: Callable[..., Finding | Iterable[Finding]]
    technique: str
    check_class: str
    cost: str = "fast"
    network: bool = False
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.cost not in COSTS:
            raise ValueError(f"{self.ids[0]}: cost '{self.cost}' not in {COSTS}")
        if self.check_class not in CLASS_CATEGORY:
            raise ValueError(f"{self.ids[0]}: unknown class '{self.check_class}'")
        if not self.technique.startswith(self.check_class + "."):
            raise ValueError(f"{self.ids[0]}: technique '{self.technique}' is not in class '{self.check_class}'")

    @property
    def id(self) -> str:
        return self.ids[0]

    @property
    def category(self) -> Category:
        return CLASS_CATEGORY[self.check_class]


def spec(
    ids: str | Sequence[str],
    func: Callable[..., Finding | Iterable[Finding]],
    technique: str,
    *,
    cost: str = "fast",
    network: bool = False,
    tags: Sequence[str] = (),
) -> CheckSpec:
    """Shorthand used by check modules: ``spec("linux.env.x", check_x, "cpu.brand_string")``."""
    ids_t = (ids,) if isinstance(ids, str) else tuple(ids)
    return CheckSpec(
        ids=ids_t,
        func=func,
        technique=technique,
        check_class=technique.split(".", 1)[0],
        cost=cost,
        network=network,
        tags=tuple(tags),
    )


def _matches(pattern: str, check: CheckSpec, finding_id: str | None = None) -> bool:
    kind, sep, value = pattern.partition(":")
    if not sep:
        ids = (finding_id,) if finding_id else check.ids
        return any(fnmatch.fnmatchcase(i, pattern) for i in ids)
    value = value.strip()
    if kind == "class":
        return fnmatch.fnmatchcase(check.check_class, value)
    if kind == "category":
        return fnmatch.fnmatchcase(check.category.value, value)
    if kind == "technique":
        return fnmatch.fnmatchcase(check.technique, value)
    if kind == "cost":
        return check.cost == value
    if kind == "tag":
        return value in check.tags
    if kind == "id":
        return any(fnmatch.fnmatchcase(i, value) for i in check.ids)
    raise ValueError(f"unknown selector '{kind}:' in pattern '{pattern}'")


def select(
    checks: Iterable[CheckSpec],
    *,
    profile: str = "standard",
    only: Sequence[str] = (),
    skip: Sequence[str] = (),
    network: bool = True,
) -> list[CheckSpec]:
    """Apply profile, network and only/skip filters. An explicit --only match
    overrides the profile's cost ceiling (asking for a slow check by name runs
    it), but never --skip or --no-network."""
    if profile not in PROFILES:
        raise ValueError(f"profile '{profile}' not in {sorted(PROFILES)}")
    ceiling = COSTS.index(PROFILES[profile])
    chosen = []
    for check in checks:
        explicitly = bool(only) and any(_matches(p, check) for p in only)
        if only and not explicitly:
            continue
        if not explicitly and COSTS.index(check.cost) > ceiling:
            continue
        if any(_matches(p, check) for p in skip):
            continue
        if check.network and not network:
            continue
        chosen.append(check)
    return chosen


def _call(check: CheckSpec, ctx: RunContext) -> list[Finding]:
    params = inspect.signature(check.func).parameters
    if "ctx" in params:
        result = check.func(ctx=ctx)
    elif params:
        # Older check functions take the adb serial / target positionally.
        result = check.func(ctx.target)
    else:
        result = check.func()
    if isinstance(result, Finding):
        return [result]
    return list(result)


def run_checks(checks: Sequence[CheckSpec], ctx: RunContext) -> list[Finding]:
    """Run each check, stamp catalog metadata and timing onto its findings,
    and turn an unexpected exception into one ``error`` finding instead of
    aborting the scan."""
    findings: list[Finding] = []
    for check in checks:
        started = time.perf_counter()
        try:
            produced = _call(check, ctx)
        except Exception as exc:  # noqa: BLE001 - one broken probe must not end the scan
            produced = [
                Finding(
                    id=check.id,
                    category=check.category,
                    platform=ctx.platform,
                    name=check.id,
                    description=f"Probe {check.func.__name__} raised before producing a result.",
                    status=Status.ERROR,
                    severity=Severity.INFO,
                    error_detail=f"{type(exc).__name__}: {exc}",
                )
            ]
        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        share = elapsed / max(1, len(produced))
        for finding in produced:
            findings.append(
                dataclasses.replace(
                    finding,
                    technique=finding.technique or check.technique,
                    check_class=finding.check_class or check.check_class,
                    duration_ms=finding.duration_ms if finding.duration_ms is not None else share,
                )
            )
    return findings


def selection_doc(profile: str, only: Sequence[str], skip: Sequence[str], params: dict, network: bool) -> dict:
    return {
        "profile": profile,
        "only": list(only),
        "skip": list(skip),
        "params": dict(params),
        "network": network,
    }


def parse_params(pairs: Sequence[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key.strip():
            raise ValueError(f"--param expects key=value, got '{pair}'")
        out[key.strip()] = value.strip()
    return out


def add_selection_arguments(parser) -> None:
    """argparse flags every agent exposes, identical across platforms."""
    parser.add_argument("--profile", choices=sorted(PROFILES), default="standard", help="cost ceiling")
    parser.add_argument("--only", nargs="+", default=[], metavar="PATTERN", help="run only matching checks")
    parser.add_argument("--skip", nargs="+", default=[], metavar="PATTERN", help="never run matching checks")
    parser.add_argument("--param", nargs="+", default=[], metavar="KEY=VALUE", help="probe parameters")
    parser.add_argument("--no-network", action="store_true", help="skip checks that send network traffic")
    parser.add_argument("--list-checks", action="store_true", help="print the registered checks and exit")


def list_doc(checks: Sequence[CheckSpec]) -> list[dict]:
    return [
        {
            "ids": list(c.ids),
            "technique": c.technique,
            "class": c.check_class,
            "category": c.category.value,
            "cost": c.cost,
            "network": c.network,
            "tags": list(c.tags),
        }
        for c in checks
    ]
