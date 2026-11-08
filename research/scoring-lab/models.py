"""Candidate scoring models for the Perdedor scoring lab.

Every model maps the same input, a list of findings, onto a score in [0, 100] where 100 means the
environment showed malware nothing it could use. Findings carry at least ``technique`` and ``status``
("clean", "detected", "error", "skipped"); ``tool``, ``id`` and ``confidence`` are optional.

Parameters come from the catalog: per technique a prevalence ``p`` (share of evasive samples that
use the technique, from its tier in catalog/classes.json) and a discrimination ``q`` (how reliably a
positive on our check means the malware's own version of the check fires too). The *hazard* of a
detected technique is ``h = p * q * confidence``.

M0  severity penalty            today's formula: 100 (1 - sum detected severity / applicable checks)
M1  weighted pass rate          100 (1 - sum detected weight / sum applicable weight)
M2  points                      VMAware-style points per technique, 150 points = certain VM
M3  noisy-OR exposure           100 * prod(1 - p q h): chance a random evasive sample sees no tell
M4  family survival             weighted share of known families none of whose techniques fire
M5  hybrid with uncertainty     M4 (or M3) plus Monte-Carlo interval and coverage-imputed estimate
M6  weakest class               min over classes of the prevalence-weighted class pass rate
"""

from __future__ import annotations

import json
import math
import random
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parents[2]
APPLICABLE = ("clean", "detected")
DRAWS = 300  # Monte-Carlo draws for M5; the lab lowers it for the robustness sweep


# ---------------------------------------------------------------------------------------------
# catalog parameters
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Technique:
    key: str
    klass: str
    category: str
    p: float
    q: float
    tier: str
    platforms: Tuple[str, ...]


@dataclass
class Params:
    techniques: Dict[str, Technique]
    severity_weights: Dict[str, float]
    families: List[dict] = field(default_factory=list)

    @classmethod
    def load(cls, root: Path = ROOT, threats: Optional[Path] = None) -> "Params":
        classes = json.loads((root / "catalog" / "classes.json").read_text())
        tiers = {k: v["p"] for k, v in classes["prevalence_tiers"].items()}
        cat_of = {k: v["category"] for k, v in classes["classes"].items()}
        techs = {}
        for t in json.loads((root / "catalog" / "techniques.json").read_text())["techniques"]:
            techs[t["key"]] = Technique(
                t["key"],
                t["class"],
                cat_of[t["class"]],
                tiers[t["tier"]],
                float(t["discrimination"]),
                t["tier"],
                tuple(t["platforms"]),
            )
        fams: List[dict] = []
        path = threats or root / "catalog" / "threats.json"
        if path.exists():
            data = json.loads(path.read_text())
            fams = [f for f in data.get("threats", []) if f.get("techniques")]
        return cls(techs, dict(classes["severity_weights"]), fams)

    def for_platform(self, platform: str) -> List[Technique]:
        return [t for t in self.techniques.values() if platform in t.platforms]

    def severity_of(self, key: str) -> str:
        """Severity a check of this technique would carry, derived from its discrimination."""
        q = self.techniques[key].q
        if q >= 0.85:
            return "high"
        if q >= 0.6:
            return "medium"
        if q >= 0.35:
            return "low"
        return "info"


# ---------------------------------------------------------------------------------------------
# aggregation: checks -> techniques
# ---------------------------------------------------------------------------------------------


@dataclass
class Obs:
    """What all checks of one technique said in one run."""

    technique: str
    checks: int = 0
    detected: int = 0
    hit: float = 0.0  # max confidence among detected checks (0 when every check was clean)
    tools: Set[str] = field(default_factory=set)
    det_tools: Set[str] = field(default_factory=set)

    @property
    def tested(self) -> bool:
        return self.checks > 0


def aggregate(findings: Iterable[Mapping]) -> Dict[str, Obs]:
    out: Dict[str, Obs] = {}
    for f in findings:
        if f.get("status") not in APPLICABLE or not f.get("technique"):
            continue
        o = out.setdefault(f["technique"], Obs(f["technique"]))
        o.checks += 1
        o.tools.add(f.get("tool", "?"))
        if f["status"] == "detected":
            o.detected += 1
            o.det_tools.add(f.get("tool", "?"))
            conf = f.get("confidence")
            o.hit = max(o.hit, 1.0 if conf is None else float(conf))
    return out


# ---------------------------------------------------------------------------------------------
# models
# ---------------------------------------------------------------------------------------------


@dataclass
class Result:
    score: Optional[float]
    detail: Dict = field(default_factory=dict)


def m0_severity_penalty(findings: Sequence[Mapping], P: Params) -> Result:
    app = [f for f in findings if f.get("status") in APPLICABLE and f.get("technique") in P.techniques]
    if not app:
        return Result(None)
    pen = sum(P.severity_weights[P.severity_of(f["technique"])] for f in app if f["status"] == "detected")
    return Result(max(0.0, 100.0 * (1 - pen / len(app))))


def m1_weighted_pass(findings: Sequence[Mapping], P: Params) -> Result:
    app = [f for f in findings if f.get("status") in APPLICABLE and f.get("technique") in P.techniques]
    if not app:
        return Result(None)

    def w(f: Mapping) -> float:
        return P.severity_weights[P.severity_of(f["technique"])]

    tot = sum(w(f) for f in app)
    det = sum(w(f) for f in app if f["status"] == "detected")
    return Result(100.0 * (1 - det / tot))


def m2_points(findings: Sequence[Mapping], P: Params, threshold: float = 150.0) -> Result:
    obs = aggregate(findings)
    if not obs:
        return Result(None)
    pts = sum(round(100 * P.techniques[k].q) * o.hit for k, o in obs.items() if k in P.techniques)
    return Result(100.0 * max(0.0, 1 - pts / threshold), {"points": pts})


def hazard(o: Obs, t: Technique) -> float:
    return t.p * t.q * o.hit


def m3_noisy_or(findings: Sequence[Mapping], P: Params) -> Result:
    obs = aggregate(findings)
    if not obs:
        return Result(None)
    surv = 1.0
    loss_by_class: Dict[str, float] = {}
    for k, o in obs.items():
        t = P.techniques.get(k)
        if not t:
            continue
        h = hazard(o, t)
        surv *= 1 - h
        if h > 0:
            loss_by_class[t.klass] = loss_by_class.get(t.klass, 0.0) - math.log(1 - h)
    return Result(100.0 * surv, {"loss_by_class": loss_by_class})


def pseudo_families(P: Params, platform: str, n: int = 400, seed: int = 7) -> List[dict]:
    """Stand-in threat model: families that pick each technique independently with probability p.
    Used only until catalog/threats.json holds sourced families."""
    rng = random.Random(seed)
    techs = P.for_platform(platform)
    fams = []
    for i in range(n):
        ts = [t.key for t in techs if rng.random() < t.p]
        if ts:
            fams.append({"name": f"pseudo-{i}", "weight": 1.0, "techniques": ts, "platforms": [platform]})
    return fams


def families_for(P: Params, platform: str) -> Tuple[List[dict], bool]:
    real = [f for f in P.families if platform in f.get("platforms", [])]
    if len(real) >= 10:
        return real, True
    return pseudo_families(P, platform), False


def m4_family_survival(
    findings: Sequence[Mapping], P: Params, platform: str = "windows", families: Optional[List[dict]] = None
) -> Result:
    obs = aggregate(findings)
    if not obs:
        return Result(None)
    fams, sourced = (families, True) if families is not None else families_for(P, platform)
    num = den = 0.0
    per_family = []
    for f in fams:
        s = 1.0
        tested = 0
        for k in f["techniques"]:
            o = obs.get(k)
            t = P.techniques.get(k)
            if o is None or t is None:
                continue
            tested += 1
            s *= 1 - t.q * o.hit
        w = float(f.get("weight", 1.0))
        num += w * s
        den += w
        per_family.append((f["name"], s, tested, len(f["techniques"])))
    if not den:
        return Result(None)
    return Result(100.0 * num / den, {"sourced_threats": sourced, "families": per_family})


def class_pass_rates(findings: Sequence[Mapping], P: Params) -> Dict[str, float]:
    """Prevalence-weighted pass rate inside each class: of the class's techniques that malware uses,
    weighted by how often it uses them, the share that passed."""
    obs = aggregate(findings)
    num: Dict[str, float] = {}
    den: Dict[str, float] = {}
    for k, o in obs.items():
        t = P.techniques.get(k)
        if not t:
            continue
        num[t.klass] = num.get(t.klass, 0.0) + t.p * (1 - t.q * o.hit)
        den[t.klass] = den.get(t.klass, 0.0) + t.p
    return {c: 100.0 * num[c] / den[c] for c in den if den[c] > 0}


def m6_weakest_class(findings: Sequence[Mapping], P: Params) -> Result:
    rates = class_pass_rates(findings, P)
    if not rates:
        return Result(None)
    c = min(rates, key=rates.get)
    return Result(rates[c], {"class": c})


def _beta(rng: random.Random, mean: float, kappa: float) -> float:
    mean = min(max(mean, 1e-4), 1 - 1e-4)
    return rng.betavariate(mean * kappa, (1 - mean) * kappa)


def m5_hybrid(
    findings: Sequence[Mapping],
    P: Params,
    platform: str = "windows",
    draws: Optional[int] = None,
    seed: int = 11,
    kappa: float = 12.0,
) -> Result:
    """Point estimate = M4 when a sourced threat model exists, else M3. The interval and the
    coverage-imputed estimate come from Monte-Carlo draws in which
      * p and q are uncertain (Beta around the catalog value, concentration kappa),
      * every untested technique of the platform is imputed as detected with the detection rate
        observed for tested techniques of the same class (Beta posterior, pooled with the global rate).
    """
    draws = draws or DRAWS
    obs = aggregate(findings)
    if not obs:
        return Result(None)
    fams, sourced = families_for(P, platform)
    techs = {t.key: t for t in P.for_platform(platform)}
    techs.update({k: P.techniques[k] for k in obs if k in P.techniques})

    tested = {k: o for k, o in obs.items() if k in techs}
    H = sum(1 for o in tested.values() if o.hit > 0)
    C = len(tested) - H
    cls_h: Dict[str, int] = {}
    cls_n: Dict[str, int] = {}
    for k, o in tested.items():
        c = techs[k].klass
        cls_n[c] = cls_n.get(c, 0) + 1
        cls_h[c] = cls_h.get(c, 0) + (1 if o.hit > 0 else 0)

    def survival(hits: Dict[str, float], p: Dict[str, float], q: Dict[str, float]) -> float:
        if sourced:
            num = den = 0.0
            for f in fams:
                s = 1.0
                for k in f["techniques"]:
                    if k in hits:
                        s *= 1 - q[k] * hits[k]
                w = float(f.get("weight", 1.0))
                num += w * s
                den += w
            return num / den if den else 1.0
        s = 1.0
        for k, h in hits.items():
            s *= 1 - p[k] * q[k] * h
        return s

    base_hits = {k: o.hit for k, o in tested.items()}
    point = 100.0 * survival(base_hits, {k: techs[k].p for k in techs}, {k: techs[k].q for k in techs})

    # Common random numbers: the uncertainty draws (p, q) and the per-technique uniforms used for
    # imputation are fixed by the seed and do not depend on the findings, so two runs that differ in
    # one finding are compared on the same draws (this keeps the estimate monotonic).
    keys = sorted(techs)
    rng = random.Random(seed)
    draws_pq = [
        ({k: _beta(rng, techs[k].p, kappa) for k in keys}, {k: _beta(rng, techs[k].q, kappa) for k in keys})
        for _ in range(draws)
    ]
    uniforms = [{k: rng.random() for k in keys} for _ in range(draws)]
    # Detection rate of untested techniques: the class's observed rate, shrunk towards the global
    # rate with the weight of `shrink` techniques (empirical Bayes; no flat prior, which would pull
    # sparse classes towards 50 %).
    shrink = 2.0
    g = (H + 0.5) / (H + C + 1.0)
    rate = {}
    for k in keys:
        if k in tested:
            continue
        c = techs[k].klass
        n_c, h_c = cls_n.get(c, 0), cls_h.get(c, 0)
        rate[k] = (h_c + shrink * g) / (n_c + shrink)
    observed_draws, imputed_draws, expected_draws = [], [], []
    for (p, q), u in zip(draws_pq, uniforms, strict=True):
        hits = dict(base_hits)
        observed_draws.append(100.0 * survival(hits, p, q))
        exp_hits = dict(base_hits)
        for k, r in rate.items():
            hits[k] = 1.0 if u[k] < r else 0.0
            exp_hits[k] = r
        imputed_draws.append(100.0 * survival(hits, p, q))
        expected_draws.append(100.0 * survival(exp_hits, p, q))

    def pct(xs: List[float], q_: float) -> float:
        xs = sorted(xs)
        i = min(len(xs) - 1, max(0, int(round(q_ * (len(xs) - 1)))))
        return xs[i]

    weight_all = sum(t.p * t.q for t in techs.values())
    weight_tested = sum(techs[k].p * techs[k].q for k in tested)
    return Result(
        point,
        {
            "sourced_threats": sourced,
            "observed_interval": (pct(observed_draws, 0.05), pct(observed_draws, 0.95)),
            "imputed_median": pct(imputed_draws, 0.5),
            "imputed_expected": statistics.median(expected_draws),
            "imputed_interval": (pct(imputed_draws, 0.05), pct(imputed_draws, 0.95)),
            "coverage": weight_tested / weight_all if weight_all else 0.0,
        },
    )


def m5_imputed(findings: Sequence[Mapping], P: Params, platform: str = "windows") -> Result:
    r = m5_hybrid(findings, P, platform)
    return Result(r.detail.get("imputed_expected") if r.score is not None else None, r.detail)


MODELS: Dict[str, Callable[..., Result]] = {
    "M0 severity penalty": m0_severity_penalty,
    "M1 weighted pass rate": m1_weighted_pass,
    "M2 points (VMAware-style)": m2_points,
    "M3 noisy-OR exposure": m3_noisy_or,
    "M4 family survival": m4_family_survival,
    "M5 hybrid (point)": m5_hybrid,
    "M5 hybrid (coverage-imputed)": m5_imputed,
    "M6 weakest class": m6_weakest_class,
}

PLATFORM_AWARE = {"M4 family survival", "M5 hybrid (point)", "M5 hybrid (coverage-imputed)"}


def run_model(name: str, findings: Sequence[Mapping], P: Params, platform: str = "windows") -> Result:
    fn = MODELS[name]
    if name in PLATFORM_AWARE:
        return fn(findings, P, platform=platform)
    return fn(findings, P)
