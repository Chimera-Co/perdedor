"""Perdedor exposure model: how much of the evasive-malware population an environment gives away.

The headline score answers one question: *of the evasive malware we know about, what share would
see no sign of analysis in this environment and run normally?* (0-100, higher is better). It was
chosen in research/scoring-lab against eleven axioms and nine labelled hardening experiments; see
docs/SCORING.md for the comparison and the reasons.

Model
-----
For every technique ``i`` the catalog gives a prevalence ``p_i`` (share of evasive samples that use
it) and a discrimination ``q_i`` (how reliably our check firing means the malware's own version
fires). A run tells us, per technique, the strongest detection ``h_i`` in [0, 1] (0 = every check
clean, else the highest confidence of a detected check), or nothing when no check ran.

* Untested techniques of the platform are not assumed clean: each gets the expected detection rate
  ``r_i`` of its class (empirical Bayes: the class's observed rate shrunk towards the run's global
  rate with the weight of two techniques). That keeps quick profiles from scoring better than full
  ones.
* With a sourced threat model (catalog/threats.json, >= 10 families on the platform) the score is
  the weighted share of families none of whose techniques fire. A family's technique list holds
  what public analyses *name*, a lower bound, so each family also uses every unlisted technique
  with the residual rate that makes the population match the measured prevalence::

      share_i = sum_{f: i in T_f} w_f / sum_f w_f
      u_i     = max(0, p_i - share_i) / (1 - share_i)
      S = 100 * sum_f w_f * prod_{i in T_f} (1 - q_i h_i) * prod_{i not in T_f} (1 - u_i q_i h_i) / sum_f w_f

  (calibrated family form, model 2; the raw form of model 1 let under-reported techniques such as
  the CPUID hypervisor bit pass a sandbox that exposes them).

* Without one it is the noisy-OR survival of a sample that uses each technique with chance p_i::

      S = 100 * prod_i (1 - p_i q_i h_i)

* A 90 % credible interval comes from Monte-Carlo draws of p and q (Beta around the catalog value)
  and of the untested techniques' outcomes (Bernoulli with rate r_i).

Per class and per category the model reports the class's own survival ``100 * prod_{i in c}
(1 - p_i q_i h_i)`` (classes multiply up to the noisy-OR headline) and how many of the headline's
lost points the class accounts for (its share of the log-loss).

The epistemic pillars (credibility, transferability, dependability, confirmability; Lincoln and
Guba's trustworthiness criteria) grade how far the number can be trusted. They are reported next
to the score and never folded into it.
"""

from __future__ import annotations

import math
import random
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .catalog import Catalog, load_catalog

MODEL_ID = "perdedor-exposure-2"
PASS_THRESHOLD = 90.0
WARN_THRESHOLD = 70.0
MIN_SOURCED_FAMILIES = 10
SHRINK = 2.0
KAPPA = 12.0
APPLICABLE = ("clean", "detected")
MEANING = (
    "Share of known evasive malware expected to see no sign of analysis here and run normally "
    "(untested techniques estimated from tested ones)."
)


# ---------------------------------------------------------------------------------------------
# inputs
# ---------------------------------------------------------------------------------------------


def _as_dict(f: Any) -> Mapping:
    if isinstance(f, Mapping):
        return f
    if hasattr(f, "to_dict"):
        return f.to_dict()
    raise TypeError(f"finding of type {type(f).__name__} is neither a mapping nor has to_dict()")


@dataclass
class TechniqueObs:
    key: str
    checks: list[str] = field(default_factory=list)
    detected_checks: list[str] = field(default_factory=list)
    tools: set[str] = field(default_factory=set)
    detected_tools: set[str] = field(default_factory=set)
    hit: float = 0.0
    with_evidence: int = 0

    @property
    def contradictory(self) -> bool:
        return 0 < len(self.detected_checks) < len(self.checks)


def observe(findings: Iterable[Any], catalog: Catalog) -> dict[str, TechniqueObs]:
    """Group applicable findings by technique (from the finding, else from the check catalog)."""
    out: dict[str, TechniqueObs] = {}
    for raw in findings:
        f = _as_dict(raw)
        if f.get("status") not in APPLICABLE:
            continue
        key = f.get("technique") or (catalog.check(f.get("id", "")) or {}).get("technique")
        if not key or key not in catalog.techniques:
            continue
        o = out.setdefault(key, TechniqueObs(key))
        o.checks.append(f.get("id", "?"))
        tool = f.get("tool") or "perdedor"
        o.tools.add(tool)
        if f.get("evidence") or f.get("measurement"):
            o.with_evidence += 1
        if f["status"] == "detected":
            o.detected_checks.append(f.get("id", "?"))
            o.detected_tools.add(tool)
            conf = f.get("confidence")
            o.hit = max(o.hit, 1.0 if conf is None else min(1.0, max(0.0, float(conf))))
    return out


# ---------------------------------------------------------------------------------------------
# the model
# ---------------------------------------------------------------------------------------------


@dataclass
class _Space:
    """Everything the survival functions need for one platform."""

    keys: list[str]
    p: dict[str, float]
    q: dict[str, float]
    klass: dict[str, str]
    tested: dict[str, float]  # key -> h
    rate: dict[str, float]  # untested key -> expected detection rate
    families: list[dict]
    sourced: bool
    share: dict[str, float] = field(default_factory=dict)  # family-weight share citing each key


def _space(obs: Mapping[str, TechniqueObs], catalog: Catalog, platform: str) -> _Space:
    techs = {t["key"]: t for t in catalog.techniques_for(platform)}
    for key in obs:  # a finding may name a technique the catalog files under other platforms
        techs.setdefault(key, catalog.techniques[key])
    keys = sorted(techs)
    tested = {k: obs[k].hit for k in keys if k in obs}
    hits = sum(1 for h in tested.values() if h > 0)
    g = (hits + 0.5) / (len(tested) + 1.0)
    n_c: dict[str, int] = {}
    h_c: dict[str, int] = {}
    for k, h in tested.items():
        c = techs[k]["class"]
        n_c[c] = n_c.get(c, 0) + 1
        h_c[c] = h_c.get(c, 0) + (h > 0)
    # Second-order (Jensen) correction: every untested technique of a class shares one estimated
    # rate, and survival is convex in that rate, so plugging in the estimate is optimistic by about
    # 1/2 A^2 Var(r). Raising the rate by 1/2 A Var(r), with A the class's untested weight, removes
    # that bias (measured in the lab: 40 % fewer techniques no longer raise the score on average).
    untested_weight: dict[str, float] = {}
    for k in keys:
        if k not in tested:
            c = techs[k]["class"]
            untested_weight[c] = untested_weight.get(c, 0.0) + catalog.prevalence(k) * float(
                techs[k]["discrimination"]
            )
    rate = {}
    for k in keys:
        if k not in tested:
            c = techs[k]["class"]
            n = n_c.get(c, 0) + SHRINK
            r = (h_c.get(c, 0) + SHRINK * g) / n
            var = r * (1 - r) / (n + 1)
            rate[k] = min(1.0, r + 0.5 * untested_weight[c] * var)
    fams = [f for f in catalog.threats if platform in f.get("platforms", []) and f.get("techniques")]
    sourced = len(fams) >= MIN_SOURCED_FAMILIES
    share: dict[str, float] = {}
    if sourced:
        total = sum(float(f.get("weight", 1.0)) for f in fams)
        for f in fams:
            for k in set(f["techniques"]):
                share[k] = share.get(k, 0.0) + float(f.get("weight", 1.0)) / total
    return _Space(
        keys=keys,
        p={k: catalog.prevalence(k) for k in keys},
        q={k: float(techs[k]["discrimination"]) for k in keys},
        klass={k: techs[k]["class"] for k in keys},
        tested=tested,
        rate=rate,
        families=fams if sourced else [],
        sourced=sourced,
        share=share,
    )


def _residual(sp: _Space, k: str, p: Mapping[str, float]) -> float:
    """Chance a family whose sources do not name technique ``k`` uses it anyway (see module doc)."""
    share = min(sp.share.get(k, 0.0), 0.999)
    return max(0.0, p[k] - share) / (1.0 - share)


def _family_survival(sp: _Space, f: Mapping, hits: Mapping[str, float], p, q, base: float) -> float:
    """One family's survival given ``base`` = prod over all keys of (1 - u_k q_k h_k)."""
    s = base
    for k in set(f["techniques"]):
        h = hits.get(k, 0.0)
        if h:
            s *= (1.0 - q[k] * h) / (1.0 - _residual(sp, k, p) * q[k] * h)
    return s


def _family_base(sp: _Space, hits: Mapping[str, float], p, q) -> float:
    base = 1.0
    for k, h in hits.items():
        if h and k in q:
            base *= 1.0 - _residual(sp, k, p) * q[k] * h
    return base


def _survival(sp: _Space, hits: Mapping[str, float], p: Mapping[str, float], q: Mapping[str, float]) -> float:
    if sp.sourced:
        base = _family_base(sp, hits, p, q)
        num = den = 0.0
        for f in sp.families:
            w = float(f.get("weight", 1.0))
            num += w * _family_survival(sp, f, hits, p, q, base)
            den += w
        return num / den if den else 1.0
    s = 1.0
    for k, h in hits.items():
        if h:
            s *= 1.0 - p[k] * q[k] * h
    return s


def _beta(rng: random.Random, mean: float, kappa: float) -> float:
    mean = min(max(mean, 1e-4), 1 - 1e-4)
    return rng.betavariate(mean * kappa, (1 - mean) * kappa)


def _pct(xs: Sequence[float], q: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, max(0, round(q * (len(xs) - 1))))]


def _grade(v: float | None) -> str:
    if v is None:
        return "n/a"
    return "A" if v >= 0.9 else "B" if v >= 0.75 else "C" if v >= 0.5 else "D"


def _verdict(score: float) -> str:
    return "pass" if score >= PASS_THRESHOLD else "warn" if score >= WARN_THRESHOLD else "fail"


def assess(
    findings: Iterable[Any],
    platform: str,
    catalog: Catalog | None = None,
    *,
    runs: Sequence[Iterable[Any]] | None = None,
    draws: int = 400,
    seed: int = 20261108,
) -> dict:
    """Score one run. ``runs`` (optional) are repeated runs of the same environment, including this
    one, used only for the dependability pillar."""
    catalog = catalog or load_catalog()
    findings = [_as_dict(f) for f in findings]
    obs = observe(findings, catalog)
    if not obs:
        return {
            "model": MODEL_ID,
            "platform": platform,
            "score": None,
            "reason": "no applicable findings: nothing was measured, so nothing can be scored",
        }
    sp = _space(obs, catalog, platform)

    expected = dict(sp.tested)
    expected.update(sp.rate)
    score = 100.0 * _survival(sp, expected, sp.p, sp.q)
    observed = 100.0 * _survival(sp, sp.tested, sp.p, sp.q)

    rng = random.Random(seed)
    samples = []
    for _ in range(draws):
        p = {k: _beta(rng, sp.p[k], KAPPA) for k in sp.keys}
        q = {k: _beta(rng, sp.q[k], KAPPA) for k in sp.keys}
        hits = dict(sp.tested)
        for k, r in sp.rate.items():
            hits[k] = 1.0 if rng.random() < r else 0.0
        samples.append(100.0 * _survival(sp, hits, p, q))

    weight_all = sum(sp.p[k] * sp.q[k] for k in sp.keys)
    weight_tested = sum(sp.p[k] * sp.q[k] for k in sp.tested)
    coverage = weight_tested / weight_all if weight_all else 0.0

    classes = _class_view(sp, expected, score, catalog)
    categories = _category_view(classes, catalog)
    detected = [
        {
            "technique": k,
            "title": catalog.techniques[k]["title"],
            "class": sp.klass[k],
            "confidence": round(o.hit, 3),
            "prevalence": sp.p[k],
            "discrimination": sp.q[k],
            "hazard": round(sp.p[k] * sp.q[k] * o.hit, 4),
            "checks": o.detected_checks,
            "tools": sorted(o.detected_tools),
            "attack": catalog.techniques[k].get("attack", []),
        }
        for k, o in sorted(obs.items(), key=lambda kv: -sp.p[kv[0]] * sp.q[kv[0]] * kv[1].hit)
        if o.hit > 0
    ]
    untested = sorted(sp.rate, key=lambda k: -sp.p[k] * sp.q[k] * sp.rate[k])
    return {
        "model": MODEL_ID,
        "platform": platform,
        "score": round(score, 2),
        "verdict": _verdict(score),
        "meaning": MEANING,
        "observed": round(observed, 2),
        "interval": [round(_pct(samples, 0.05), 2), round(_pct(samples, 0.95), 2)],
        "coverage": round(coverage, 3),
        "techniques": {
            "platform": len(sp.keys),
            "tested": len(sp.tested),
            "detected": sum(1 for h in sp.tested.values() if h > 0),
            "untested": len(sp.rate),
        },
        "threat_model": {
            "source": "catalog/threats.json" if sp.sourced else "technique prevalence tiers",
            "families": len(sp.families),
        },
        "classes": classes,
        "categories": categories,
        "detected": detected,
        "untested_top": [
            {
                "technique": k,
                "title": catalog.techniques[k]["title"],
                "class": sp.klass[k],
                "expected_rate": round(sp.rate[k], 3),
            }
            for k in untested[:15]
        ],
        "families": _family_view(sp, obs, catalog) if sp.sourced else [],
        "pillars": pillars(obs, sp, findings, runs, catalog, platform),
        "thresholds": {"pass": PASS_THRESHOLD, "warn": WARN_THRESHOLD},
    }


def _class_view(sp: _Space, expected: Mapping[str, float], score: float, catalog: Catalog) -> dict:
    loss: dict[str, float] = {}
    surv_obs: dict[str, float] = {}
    surv_exp: dict[str, float] = {}
    counts: dict[str, dict[str, int]] = {}
    for k in sp.keys:
        c = sp.klass[k]
        cnt = counts.setdefault(c, {"techniques": 0, "tested": 0, "detected": 0, "untested": 0})
        cnt["techniques"] += 1
        if k in sp.tested:
            cnt["tested"] += 1
            cnt["detected"] += sp.tested[k] > 0
            surv_obs[c] = surv_obs.get(c, 1.0) * (1 - sp.p[k] * sp.q[k] * sp.tested[k])
        else:
            cnt["untested"] += 1
        h = sp.p[k] * sp.q[k] * expected.get(k, 0.0)
        surv_exp[c] = surv_exp.get(c, 1.0) * (1 - h)
        loss[c] = loss.get(c, 0.0) - math.log(max(1e-12, 1 - h))
    total_loss = sum(loss.values())
    lost = 100.0 - score
    out = {}
    for c, cnt in sorted(counts.items()):
        out[c] = {
            "title": catalog.classes[c]["title"],
            "category": catalog.classes[c]["category"],
            "score": round(100.0 * surv_exp.get(c, 1.0), 2),
            "observed": round(100.0 * surv_obs[c], 2) if c in surv_obs else None,
            "points_lost": round(lost * loss[c] / total_loss, 2) if total_loss else 0.0,
            **cnt,
        }
    return out


def _category_view(classes: Mapping[str, dict], catalog: Catalog) -> dict:
    out: dict[str, dict] = {}
    for c, v in classes.items():
        cat = out.setdefault(
            v["category"],
            {
                "score": 100.0,
                "points_lost": 0.0,
                "classes": [],
                "techniques": 0,
                "tested": 0,
                "detected": 0,
                "untested": 0,
            },
        )
        cat["score"] *= v["score"] / 100.0
        cat["points_lost"] += v["points_lost"]
        cat["classes"].append(c)
        for n in ("techniques", "tested", "detected", "untested"):
            cat[n] += v[n]
    for cat in out.values():
        cat["score"] = round(cat["score"], 2)
        cat["points_lost"] = round(cat["points_lost"], 2)
    return out


def _family_view(sp: _Space, obs: Mapping[str, TechniqueObs], catalog: Catalog, top: int = 20) -> list:
    rows = []
    base = _family_base(sp, sp.tested, sp.p, sp.q)
    for f in sp.families:
        s = _family_survival(sp, f, sp.tested, sp.p, sp.q, base)
        triggered, unknown = [], []
        for k in f["techniques"]:
            h = sp.tested.get(k)
            if h is None:
                unknown.append(k)
            elif h > 0:
                triggered.append(k)
        rows.append(
            {
                "name": f["name"],
                "type": f.get("type"),
                "weight": f.get("weight", 1.0),
                "survival": round(100.0 * s, 1),
                "triggered": triggered,
                "untested": unknown,
                "actors": f.get("actors", []),
            }
        )
    rows.sort(key=lambda r: (r["survival"], -float(r["weight"] or 1)))
    return rows[:top]


# ---------------------------------------------------------------------------------------------
# epistemic pillars
# ---------------------------------------------------------------------------------------------


def pillars(
    obs: Mapping[str, TechniqueObs],
    sp: _Space,
    findings: Sequence[Mapping],
    runs: Sequence[Iterable[Any]] | None,
    catalog: Catalog,
    platform: str,
) -> dict:
    w = {k: sp.p[k] * sp.q[k] for k in sp.tested}
    wt = sum(w.values()) or 1.0

    # Credibility: how much of the verdict rests on more than one independent check that agree.
    corroborated = sum(w[k] for k, o in obs.items() if k in w and len(o.checks) >= 2 and not o.contradictory)
    contradictory = sum(w[k] for k, o in obs.items() if k in w and o.contradictory)
    cred = max(0.0, (corroborated - 0.5 * contradictory) / wt)

    # Transferability: is the population we score against sourced, and how much of it did we test?
    if sp.sourced:
        num = den = 0.0
        for f in sp.families:
            n = len(f["techniques"])
            num += float(f.get("weight", 1.0)) * (
                sum(k in sp.tested for k in f["techniques"]) / n if n else 0
            )
            den += float(f.get("weight", 1.0))
        trans = num / den if den else 0.0
        trans_basis = f"{len(sp.families)} sourced families; share of their techniques that were tested"
    else:
        weight_all = sum(sp.p[k] * sp.q[k] for k in sp.keys) or 1.0
        trans = 0.5 * sum(w.values()) / weight_all
        trans_basis = "no sourced threat model for this platform: tier prevalence only (halved)"

    # Dependability: do repeated runs of the same environment agree?
    dep = None
    dep_basis = "single run; repeat the scan (trials > 1) to assess"
    if runs and len(runs) >= 2:
        verdicts = [{k: o.hit > 0 for k, o in observe(r, catalog).items()} for r in runs]
        common = set.intersection(*(set(v) for v in verdicts))
        if common:
            agree = sum(1 for k in common if len({v[k] for v in verdicts}) == 1)
            dep = agree / len(common)
            dep_basis = (
                f"{len(runs)} runs; share of {len(common)} techniques with the same verdict in every run"
            )

    # Confirmability: can every verdict be traced to recorded evidence?
    applicable = [f for f in findings if f.get("status") in APPLICABLE]
    with_ev = sum(1 for f in applicable if f.get("evidence") or f.get("measurement"))
    conf = with_ev / len(applicable) if applicable else 0.0

    vals = {"credibility": cred, "transferability": trans, "dependability": dep, "confirmability": conf}
    known = [v for v in vals.values() if v is not None]
    return {
        "credibility": {
            "value": round(cred, 3),
            "grade": _grade(cred),
            "basis": "share of tested weight resting on >= 2 agreeing checks (contradictions count against)",
        },
        "transferability": {"value": round(trans, 3), "grade": _grade(trans), "basis": trans_basis},
        "dependability": {
            "value": None if dep is None else round(dep, 3),
            "grade": _grade(dep),
            "basis": dep_basis,
        },
        "confirmability": {
            "value": round(conf, 3),
            "grade": _grade(conf),
            "basis": "share of applicable findings that recorded evidence or a measurement",
        },
        "overall": _grade(min(known) if known else None),
    }


# ---------------------------------------------------------------------------------------------
# hardening planner
# ---------------------------------------------------------------------------------------------


def _technique_fix(key: str, obs: TechniqueObs | None, catalog: Catalog) -> dict:
    fixes = [(catalog.check(c) or {}).get("fix") for c in (obs.detected_checks if obs else [])]
    fixes = [f for f in fixes if f]
    if fixes:
        best = min(fixes, key=lambda f: int(f.get("effort", 3)))
        return {
            "layer": best.get("layer"),
            "effort": int(best.get("effort", 3)),
            "how": best.get("how"),
            "chimera": best.get("chimera"),
        }
    return {"layer": None, "effort": 3, "how": None, "chimera": None}


def plan(
    findings: Iterable[Any], platform: str, catalog: Catalog | None = None, *, max_steps: int = 25
) -> dict:
    """Order the detected techniques into a hardening roadmap: at every step pick the fix with the
    largest score gain per unit of effort (greedy on the exposure model, untested techniques held at
    their current estimate), and report the score after each step."""
    catalog = catalog or load_catalog()
    findings = [_as_dict(f) for f in findings]
    obs = observe(findings, catalog)
    if not obs:
        return {"model": MODEL_ID, "platform": platform, "steps": [], "start": None}
    sp = _space(obs, catalog, platform)
    hits = dict(sp.tested)
    hits.update(sp.rate)
    current = 100.0 * _survival(sp, hits, sp.p, sp.q)
    start = current
    todo = {k for k, h in sp.tested.items() if h > 0}
    fixes = {k: _technique_fix(k, obs.get(k), catalog) for k in todo}
    steps = []
    while todo and len(steps) < max_steps:
        best = None
        for k in sorted(todo):
            trial = dict(hits)
            trial[k] = 0.0
            gain = 100.0 * _survival(sp, trial, sp.p, sp.q) - current
            ratio = gain / fixes[k]["effort"]
            if best is None or ratio > best[0] + 1e-12:
                best = (ratio, k, gain)
        _, k, gain = best
        hits[k] = 0.0
        current += gain
        todo.discard(k)
        t = catalog.techniques[k]
        steps.append(
            {
                "step": len(steps) + 1,
                "technique": k,
                "title": t["title"],
                "class": t["class"],
                "category": catalog.class_category(t["class"]),
                "gain": round(gain, 2),
                "score_after": round(current, 2),
                **fixes[k],
                "checks": obs[k].detected_checks,
            }
        )
    measure = sorted(sp.rate, key=lambda k: -sp.p[k] * sp.q[k] * sp.rate[k])[:10]
    return {
        "model": MODEL_ID,
        "platform": platform,
        "start": round(start, 2),
        "end": round(current, 2),
        "steps": steps,
        "measure_next": [
            {
                "technique": k,
                "title": catalog.techniques[k]["title"],
                "class": sp.klass[k],
                "expected_rate": round(sp.rate[k], 3),
                "implemented_checks": [c["id"] for c in catalog.checks_for(platform) if c["technique"] == k],
            }
            for k in measure
        ],
    }


def headline(report: Mapping) -> dict | None:
    """Exposure headline of one agent report: score, verdict, interval and overall trust grade.

    None when the report cannot be scored (unknown platform, no catalog, nothing tested). Agents and
    renderers use this for their one-line summary; ``perdedor score`` gives the full breakdown.
    """
    try:
        a = assess(report["findings"], report["platform"], load_catalog())
    except Exception:  # noqa: BLE001 - a summary line must never break a scan or a render
        return None
    if a.get("score") is None:
        return None
    return {
        "score": round(a["score"], 1),
        "verdict": a["verdict"],
        "interval": [round(x, 1) for x in a["interval"]],
        "trust": a["pillars"]["overall"],
    }


def headline_text(report: Mapping) -> str:
    """One line for terminals: counts, then the exposure score or how to get it."""
    s = report["summary"]
    counts = (
        f"{s['raw_score']} clean, {s['detected']} detected ({s['errored']} errored, {s['skipped']} skipped)"
    )
    h = headline(report)
    if h is None:
        return f"{counts}. Exposure score: perdedor score <report.json>"
    return (
        f"{counts}. Exposure {h['score']:.1f}/100 [{h['verdict'].upper()}], "
        f"90 % interval {h['interval'][0]:.1f}-{h['interval'][1]:.1f}, trust {h['trust']}"
    )
