"""Perdedor scoring lab: evaluate candidate scoring models against stated axioms.

    python3 research/scoring-lab/lab.py                       # synthetic axioms only
    python3 research/scoring-lab/lab.py --arms DIR --out DIR  # plus labelled hardening arms

Synthetic axioms use random environments drawn from the technique catalog, so they can be rerun by
anyone. The real-data evaluation reads labelled hardening experiments (one ``checks.jsonl`` per
experiment, rows ``{arm, run, scan, tool, id, status}``); those files describe a particular
sandbox and are not part of this repository. Results are written as JSON and Markdown.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import sys
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

import models as M  # noqa: E402
from models import Params, Technique, aggregate, class_pass_rates, run_model  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "common" / "python"))
from perdedor_common.equivalents import ToolMap  # noqa: E402

TOOLS = ("perdedor", "alkhaser", "pafish", "vmaware")


# ---------------------------------------------------------------------------------------------
# synthetic environments
# ---------------------------------------------------------------------------------------------


def synthetic_env(
    P: Params,
    rng: random.Random,
    platform: str = "windows",
    tested_share: float = 0.8,
    hit_rate: Optional[float] = None,
) -> List[dict]:
    rate = rng.uniform(0.02, 0.5) if hit_rate is None else hit_rate
    out = []
    for t in P.for_platform(platform):
        if rng.random() > tested_share:
            continue
        detected = rng.random() < rate
        for j in range(rng.randint(1, 3)):
            tool = rng.choice(TOOLS)
            # redundant checks of one technique mostly agree
            st = "detected" if (detected and (j == 0 or rng.random() < 0.7)) else "clean"
            out.append({"tool": tool, "id": f"{tool}.{t.key}.{j}", "technique": t.key, "status": st})
    return out


def score(name: str, env: Sequence[Mapping], P: Params) -> Optional[float]:
    return run_model(name, env, P).score


def axiom_monotonic(P: Params, names: Sequence[str], trials: int, rng: random.Random) -> Dict[str, dict]:
    """A1: turning a clean technique into a detected one never raises the score, and lowers it."""
    res = {n: {"never_up": 0, "strictly_down": 0, "n": 0} for n in names}
    for _ in range(trials):
        env = synthetic_env(P, rng)
        obs = aggregate(env)
        clean = [k for k, o in obs.items() if o.hit == 0]
        if not clean:
            continue
        k = rng.choice(clean)
        env2 = [dict(f, status="detected") if f["technique"] == k else f for f in env]
        for n in names:
            a, b = score(n, env, P), score(n, env2, P)
            res[n]["n"] += 1
            res[n]["never_up"] += b <= a + 1e-9
            res[n]["strictly_down"] += b < a - 1e-9
    return {
        n: {"never_up": r["never_up"] / r["n"], "strictly_down": r["strictly_down"] / r["n"]}
        for n, r in res.items()
    }


def axiom_no_dilution(P: Params, names: Sequence[str], trials: int, rng: random.Random) -> Dict[str, dict]:
    """A2: adding redundant clean checks of techniques already tested must not change the score.
    (A tool that adds twenty trivial checks must not be able to buy a better score.)"""
    res = {n: [] for n in names}
    for _ in range(trials):
        env = synthetic_env(P, rng)
        tested = sorted({f["technique"] for f in env})
        extra = [
            {"tool": "padding", "id": f"pad.{i}", "technique": rng.choice(tested), "status": "clean"}
            for i in range(20)
        ]
        for n in names:
            res[n].append(score(n, env + extra, P) - score(n, env, P))
    return {n: {"mean_gain": statistics.mean(v), "max_gain": max(v)} for n, v in res.items()}


def axiom_severity(P: Params, names: Sequence[str]) -> Dict[str, dict]:
    """A3: one detection of a very common, highly discriminating technique (CPUID hypervisor bit)
    must cost more than five detections of rarely used, weakly discriminating techniques, and must
    by itself take a clean environment below the 90 warning line."""
    base = [
        {"tool": "x", "id": f"c.{t.key}", "technique": t.key, "status": "clean"}
        for t in P.for_platform("windows")
    ]
    strong = "cpu.hypervisor_bit"
    weak = [t.key for t in P.for_platform("windows") if t.tier in ("rare", "research") and t.q <= 0.6][:5]
    if len(weak) < 5:
        weak = [t.key for t in sorted(P.for_platform("windows"), key=lambda t: (t.p * t.q))[:5]]
    one = [dict(f, status="detected") if f["technique"] == strong else f for f in base]
    five = [dict(f, status="detected") if f["technique"] in weak else f for f in base]
    out = {}
    for n in names:
        s1, s5 = score(n, one, P), score(n, five, P)
        out[n] = {"one_strong": s1, "five_weak": s5, "dominance": s1 < s5, "below_warn": s1 < 90}
    return out


def axiom_coverage(P: Params, names: Sequence[str], trials: int, rng: random.Random) -> Dict[str, dict]:
    """A8: running fewer checks must not make an environment look better. Drop 40 % of the tested
    techniques at random (as a smaller profile would) and measure how much the score rises."""
    res = {n: [] for n in names}
    for _ in range(trials):
        env = synthetic_env(P, rng, tested_share=0.95)
        techs = sorted({f["technique"] for f in env})
        keep = set(rng.sample(techs, int(len(techs) * 0.6)))
        small = [f for f in env if f["technique"] in keep]
        for n in names:
            res[n].append(score(n, small, P) - score(n, env, P))
    return {
        n: {"mean_rise": statistics.mean(v), "p90_rise": sorted(v)[int(0.9 * (len(v) - 1))]}
        for n, v in res.items()
    }


def axiom_range(P: Params, names: Sequence[str], rng: random.Random) -> Dict[str, dict]:
    """A10: the score uses its range: a fully clean environment scores 100, an environment where a
    third of the techniques fire scores clearly lower than one where a tenth fire."""
    out = {}
    envs = {
        r: [synthetic_env(P, random.Random(i), tested_share=0.95, hit_rate=r) for i in range(15)]
        for r in (0.0, 0.1, 0.33, 0.66)
    }
    for n in names:
        med = {r: statistics.median(score(n, e, P) for e in es) for r, es in envs.items()}
        out[n] = {f"hit_{int(r * 100)}": round(v, 2) for r, v in med.items()}
        out[n]["spread_10_33"] = round(med[0.1] - med[0.33], 2)
    return out


# ---------------------------------------------------------------------------------------------
# labelled hardening arms
# ---------------------------------------------------------------------------------------------

ARM_OF_SET = {
    "m4-2026-10-19": None,  # arms named in the file
    "m4-h2-2026-10-19": "H2a",
    "m4-h2b-2026-10-19": "H2b",
    "m4-h2c-2026-10-20": "H2c",
    "m4-h3-2026-10-20": "H3a",
    "m4-h3b-2026-10-20": "H3b",
    "m4-clock-2026-10-20": "H3b+clock",
}
ARM_ORDER = ["H1", "H1S", "H1SH", "H2a", "H2b", "H2c", "H3a", "H3b", "H3b+clock"]
# (worse, better): each pair is one fix whose effect the experiments measured
EXPECTED = [
    ("H1", "H1S"),
    ("H1S", "H1SH"),
    ("H1", "H1SH"),
    ("H1SH", "H2c"),
    ("H2a", "H2c"),
    ("H2b", "H2c"),
    ("H2c", "H3b"),
    ("H3a", "H3b"),
    ("H3b+clock", "H3b"),
    ("H1", "H3b"),
]


def load_arms(directory: Path, tm: ToolMap) -> Tuple[Dict[str, Dict[str, List[dict]]], int]:
    """{arm: {scan: [finding]}} for every labelled experiment found under directory."""
    arms: Dict[str, Dict[str, List[dict]]] = {}
    unmapped = 0
    for name, label in ARM_OF_SET.items():
        f = directory / name / "checks.jsonl"
        if not f.exists():
            continue
        for line in f.read_text().splitlines():
            r = json.loads(line)
            arm = label or r["arm"]
            if arm.startswith("trial"):
                continue
            tech = tm.technique(r["tool"], r["id"])
            if tech is None:
                unmapped += 1
                continue
            arms.setdefault(arm, {}).setdefault(r["scan"], []).append(
                {"tool": r["tool"], "id": r["id"], "technique": tech, "status": r["status"]}
            )
    return arms, unmapped


def spearman(xs: Sequence[float], ys: Sequence[float]) -> float:
    def ranks(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and v[order[j + 1]] == v[order[i]]:
                j += 1
            for k in range(i, j + 1):
                r[order[k]] = (i + j) / 2
            i = j + 1
        return r

    if len(xs) < 3:
        return 0.0
    rx, ry = ranks(xs), ranks(ys)
    mx, my = statistics.mean(rx), statistics.mean(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry, strict=True))
    den = math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    return num / den if den else 0.0


def evaluate_arms(P: Params, names: Sequence[str], arms: Dict[str, Dict[str, List[dict]]]) -> Dict:
    present = [a for a in ARM_ORDER if a in arms]
    out: Dict = {"arms": present, "scans": {a: len(arms[a]) for a in present}, "models": {}}
    for n in names:
        per_scan = {a: [score(n, fs, P) for fs in arms[a].values()] for a in present}
        med = {a: statistics.median(v) for a, v in per_scan.items()}
        pairs = [(w, b) for w, b in EXPECTED if w in med and b in med]
        correct = sum(med[b] > med[w] + 1e-9 for w, b in pairs)
        ties = sum(abs(med[b] - med[w]) <= 1e-9 for w, b in pairs)
        # stability: share of variance explained by the arm (one-way ANOVA eta squared)
        allv = [x for v in per_scan.values() for x in v]
        grand = statistics.mean(allv)
        ss_tot = sum((x - grand) ** 2 for x in allv)
        ss_between = sum(len(v) * (statistics.mean(v) - grand) ** 2 for v in per_scan.values())
        within_sd = statistics.mean(statistics.pstdev(v) for v in per_scan.values())
        # cross-tool agreement: the model applied to Perdedor's checks alone and to al-khaser's alone
        p_only, a_only = [], []
        for a in present:
            for fs in arms[a].values():
                sp = score(n, [f for f in fs if f["tool"] == "perdedor"], P)
                sa = score(n, [f for f in fs if f["tool"] == "alkhaser"], P)
                if sp is not None and sa is not None:
                    p_only.append(sp)
                    a_only.append(sa)
        out["models"][n] = {
            "median": {a: round(v, 2) for a, v in med.items()},
            "pairs_correct": correct,
            "pairs_tied": ties,
            "pairs": len(pairs),
            "eta2": ss_between / ss_tot if ss_tot else 0.0,
            "within_sd": within_sd,
            "range": max(med.values()) - min(med.values()),
            "tool_agreement": spearman(p_only, a_only),
            "at_ceiling": sum(v >= 99.0 for v in med.values()),
        }
    return out


def perturbed(P: Params, rng: random.Random, factor: float = 2.0) -> Params:
    """Same catalog with every p and q multiplied by an independent log-uniform factor in
    [1/factor, factor] (q capped at 0.99): how wrong may our prevalence/discrimination guesses be
    before the model's conclusions change?"""
    techs = {}
    for k, t in P.techniques.items():
        fp = math.exp(rng.uniform(-math.log(factor), math.log(factor)))
        fq = math.exp(rng.uniform(-math.log(factor), math.log(factor)))
        techs[k] = Technique(
            t.key, t.klass, t.category, min(0.9, t.p * fp), min(0.99, t.q * fq), t.tier, t.platforms
        )
    return Params(techs, P.severity_weights, P.families)


def robustness(
    P: Params, names: Sequence[str], arms: Dict[str, Dict[str, List[dict]]], rounds: int, rng: random.Random
) -> Dict[str, dict]:
    """A11: share of expected arm pairs still ranked correctly when p and q are off by up to 2x."""
    saved = M.DRAWS
    M.DRAWS = 60
    present = [a for a in ARM_ORDER if a in arms]
    pairs = [(w, b) for w, b in EXPECTED if w in arms and b in arms]
    out = {n: [] for n in names}
    try:
        for _ in range(rounds):
            Q = perturbed(P, rng)
            for n in names:
                med = {a: statistics.median(score(n, fs, Q) for fs in arms[a].values()) for a in present}
                out[n].append(sum(med[b] > med[w] + 1e-9 for w, b in pairs) / len(pairs))
    finally:
        M.DRAWS = saved
    return {n: {"mean_correct": statistics.mean(v), "worst_correct": min(v)} for n, v in out.items()}


# ---------------------------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------------------------

PRODUCTION = "PEM-1 production (perdedor_common.exposure)"


def add_production_model() -> bool:
    """Register the shipped implementation next to the candidates, so the lab checks the code that
    actually runs and not only its prototype."""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "common" / "python"))
        from perdedor_common.catalog import load_catalog
        from perdedor_common.exposure import assess
    except ImportError:
        return False
    cat = load_catalog()

    def pem(findings, P, platform="windows"):
        a = assess(findings, platform, cat, draws=1)
        return M.Result(a.get("score"), a)

    M.MODELS[PRODUCTION] = pem
    M.PLATFORM_AWARE.add(PRODUCTION)
    MEANING[PRODUCTION] = "as M5 coverage-imputed, with the Jensen correction and pillars"
    DECOMPOSABLE[PRODUCTION] = "yes: class survivals and points lost per class/category"
    return True


DECOMPOSABLE = {
    "M0 severity penalty": "partly (sum of penalties, but the denominator couples classes)",
    "M1 weighted pass rate": "yes (weighted mean of class pass rates)",
    "M2 points (VMAware-style)": "yes (sum of points)",
    "M3 noisy-OR exposure": "yes (product of class survivals; log-loss adds up by class)",
    "M4 family survival": "by family, not by class",
    "M5 hybrid (point)": "by family; class view from M3 log-loss",
    "M5 hybrid (coverage-imputed)": "by family; class view from M3 log-loss",
    "M6 weakest class": "only the weakest class shows",
}
MEANING = {
    "M0 severity penalty": "no probabilistic meaning; depends on how many checks the suite has",
    "M1 weighted pass rate": "share of check weight that passed",
    "M2 points (VMAware-style)": "distance from a fixed 'certain VM' threshold",
    "M3 noisy-OR exposure": "chance that an evasive sample drawn at random sees no tell",
    "M4 family survival": "weighted share of known evasive families that would run normally",
    "M5 hybrid (point)": "as M4 (or M3), with a credible interval",
    "M5 hybrid (coverage-imputed)": "as M5, with untested techniques imputed from tested ones",
    "M6 weakest class": "pass rate of the worst class",
}


def fmt(x, nd=2):
    if x is None:
        return "–"
    if isinstance(x, bool):
        return "yes" if x else "**no**"
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return str(x)


def markdown(results: Dict) -> str:
    names = list(results["axioms"]["A1_monotonic"].keys())
    L = [
        "# Scoring lab results",
        "",
        f"Synthetic trials per axiom: {results['trials']}. "
        f"Threat model: {'sourced families' if results['sourced_threats'] else 'pseudo-families drawn from technique tiers (provisional)'}.",
        "",
    ]
    L += [
        "## Synthetic axioms",
        "",
        "| Model | A1 never up | A1 strictly down | A2 mean gain from padding | A3 one strong < five weak | A3 one strong < 90 | A8 mean rise with 40 % fewer techniques | A10 score at 10 % / 33 % hits |",
        "|---|---|---|---|---|---|---|---|",
    ]
    ax = results["axioms"]
    for n in names:
        a1, a2, a3, a8, a10 = (
            ax["A1_monotonic"][n],
            ax["A2_no_dilution"][n],
            ax["A3_severity"][n],
            ax["A8_coverage"][n],
            ax["A10_range"][n],
        )
        L.append(
            f"| {n} | {a1['never_up']:.0%} | {a1['strictly_down']:.0%} | {a2['mean_gain']:+.2f} | "
            f"{fmt(a3['dominance'])} ({a3['one_strong']:.1f} vs {a3['five_weak']:.1f}) | {fmt(a3['below_warn'])} | "
            f"{a8['mean_rise']:+.2f} | {a10['hit_10']:.1f} / {a10['hit_33']:.1f} |"
        )
    if "arms" in results:
        A = results["arms"]
        L += [
            "",
            "## Labelled hardening arms",
            "",
            "Each arm is one snapshot/configuration measured 5 times with Perdedor and al-khaser together "
            "(al-khaser and Perdedor checks mapped onto techniques). Expected pairs are fixes whose effect was "
            "measured; a model should rank the fixed arm higher.",
            "",
            "| Model | "
            + " | ".join(A["arms"])
            + " | pairs right | ties | arm explains variance (eta²) | Perdedor vs al-khaser agreement (Spearman) | A11 pairs right with p, q off by up to 2x (mean / worst) |",
            "|---|" + "---|" * (len(A["arms"]) + 5),
        ]
        for n in names:
            m = A["models"][n]
            L.append(
                f"| {n} | "
                + " | ".join(fmt(m["median"][a], 1) for a in A["arms"])
                + f" | {m['pairs_correct']}/{m['pairs']} | {m['pairs_tied']} | {m['eta2']:.2f} | {m['tool_agreement']:+.2f} | "
                f"{A['robustness'][n]['mean_correct']:.0%} / {A['robustness'][n]['worst_correct']:.0%} |"
            )
    L += [
        "",
        "## Qualitative properties",
        "",
        "| Model | What the number means | Decomposes by class |",
        "|---|---|---|",
    ]
    for n in names:
        L.append(f"| {n} | {MEANING[n]} | {DECOMPOSABLE[n]} |")
    return "\n".join(L) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--trials", type=int, default=120)
    ap.add_argument("--arms", type=Path, help="directory with labelled experiment folders (private)")
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "results")
    ap.add_argument("--threats", type=Path)
    ap.add_argument("--rounds", type=int, default=12, help="parameter perturbation rounds (A11)")
    ap.add_argument("--models", nargs="*", default=list(M.MODELS))
    a = ap.parse_args(argv)

    P = Params.load(threats=a.threats)
    names = list(a.models)
    if add_production_model() and PRODUCTION not in names:
        names.append(PRODUCTION)
    rng = random.Random(2026)
    results: Dict = {
        "trials": a.trials,
        "sourced_threats": len([f for f in P.families if "windows" in f.get("platforms", [])]) >= 10,
    }
    results["axioms"] = {
        "A1_monotonic": axiom_monotonic(P, names, a.trials, rng),
        "A2_no_dilution": axiom_no_dilution(P, names, a.trials // 2, rng),
        "A3_severity": axiom_severity(P, names),
        "A8_coverage": axiom_coverage(P, names, a.trials // 2, rng),
        "A10_range": axiom_range(P, names, rng),
    }
    if a.arms:
        arms, unmapped = load_arms(a.arms, ToolMap())
        results["arms"] = evaluate_arms(P, names, arms)
        results["arms"]["unmapped_rows"] = unmapped
        results["arms"]["robustness"] = robustness(P, names, arms, a.rounds, random.Random(5))
        last = next(x for x in reversed(ARM_ORDER) if x in arms and x != "H3b+clock")
        scan = next(iter(arms[last].values()))
        results["arms"]["class_pass_rates_" + last] = {
            k: round(v, 1) for k, v in sorted(class_pass_rates(scan, P).items())
        }
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "results.json").write_text(json.dumps(results, indent=1, default=str))
    (a.out / "results.md").write_text(markdown(results))
    print(markdown(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
