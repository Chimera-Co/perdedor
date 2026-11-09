"""Axioms the exposure model was chosen for (research/scoring-lab) are kept as regression tests."""

from __future__ import annotations

import random

import pytest
from perdedor_common.catalog import load_catalog
from perdedor_common.exposure import assess, plan

CAT = load_catalog()
WIN = sorted(t["key"] for t in CAT.techniques_for("windows"))


def env(seed: int, rate: float = 0.25, share: float = 0.85) -> list[dict]:
    rng = random.Random(seed)
    out = []
    for k in WIN:
        if rng.random() > share:
            continue
        st = "detected" if rng.random() < rate else "clean"
        out.append({"id": f"x.{k}", "technique": k, "status": st, "evidence": "e"})
    return out


def score(findings) -> float:
    return assess(findings, "windows", CAT, draws=50)["score"]


def test_all_clean_full_coverage_scores_100():
    findings = [{"id": f"x.{k}", "technique": k, "status": "clean"} for k in WIN]
    assert score(findings) == pytest.approx(100.0)


def test_nothing_applicable_gives_no_score():
    a = assess([{"id": "x", "technique": WIN[0], "status": "error"}], "windows", CAT)
    assert a["score"] is None and "nothing was measured" in a["reason"]


@pytest.mark.parametrize("seed", range(12))
def test_monotonic_one_more_detection_lowers_score(seed):
    f = env(seed)
    clean = [x for x in f if x["status"] == "clean"]
    victim = random.Random(seed).choice(clean)["technique"]
    worse = [dict(x, status="detected") if x["technique"] == victim else x for x in f]
    assert score(worse) < score(f)


@pytest.mark.parametrize("seed", range(6))
def test_padding_with_redundant_clean_checks_changes_nothing(seed):
    f = env(seed)
    tested = sorted({x["technique"] for x in f})
    pad = [{"id": f"pad.{i}", "technique": tested[i % len(tested)], "status": "clean"} for i in range(30)]
    assert score(f + pad) == pytest.approx(score(f))


def test_one_strong_detection_outweighs_five_weak_ones():
    base = [{"id": f"x.{k}", "technique": k, "status": "clean"} for k in WIN]
    weak = sorted(WIN, key=lambda k: CAT.prevalence(k) * CAT.techniques[k]["discrimination"])[:5]
    one = [dict(x, status="detected") if x["technique"] == "cpu.hypervisor_bit" else x for x in base]
    five = [dict(x, status="detected") if x["technique"] in weak else x for x in base]
    assert score(one) < score(five)
    assert score(one) < 90  # a CPUID hypervisor bit alone must fail the pass line


def test_fewer_checks_do_not_buy_a_better_score_on_average():
    """Dropping 40 % of the tested techniques raises the measured-only score a lot (untested looks
    clean); the headline, which estimates untested techniques, must stay close to the full run."""
    rises, observed_rises = [], []
    for seed in range(40):
        f = env(seed, share=0.95)
        techs = sorted({x["technique"] for x in f})
        keep = set(random.Random(seed).sample(techs, int(0.6 * len(techs))))
        small = [x for x in f if x["technique"] in keep]
        a, b = assess(small, "windows", CAT, draws=1), assess(f, "windows", CAT, draws=1)
        rises.append(a["score"] - b["score"])
        observed_rises.append(a["observed"] - b["observed"])
    mean, observed_mean = sum(rises) / len(rises), sum(observed_rises) / len(observed_rises)
    assert observed_mean > 8
    assert mean < 4 and mean < 0.3 * observed_mean


def test_class_and_category_views_are_consistent():
    a = assess(env(3), "windows", CAT, draws=50)
    lost = sum(v["points_lost"] for v in a["classes"].values())
    assert lost == pytest.approx(100 - a["score"], abs=0.2)
    for cat, v in a["categories"].items():
        assert all(a["classes"][c]["category"] == cat for c in v["classes"])
    assert a["interval"][0] <= a["interval"][1]
    assert 0 < a["coverage"] <= 1


def test_pillars_reward_corroboration_and_repeat_runs():
    one = [{"id": "a", "technique": "cpu.hypervisor_bit", "status": "detected", "evidence": "bit31"}]
    two = one + [
        {
            "id": "b",
            "technique": "cpu.hypervisor_bit",
            "status": "detected",
            "evidence": "bit31",
            "tool": "t2",
        }
    ]
    p1 = assess(one, "windows", CAT, draws=20)["pillars"]
    p2 = assess(two, "windows", CAT, draws=20, runs=[two, two])["pillars"]
    assert p1["credibility"]["value"] < p2["credibility"]["value"]
    assert p1["dependability"]["value"] is None and p2["dependability"]["value"] == 1.0
    assert p2["confirmability"]["value"] == 1.0


def test_plan_orders_by_gain_per_effort_and_ends_higher():
    f = env(5, rate=0.4)
    p = plan(f, "windows", CAT)
    assert p["steps"] and p["end"] > p["start"]
    afters = [s["score_after"] for s in p["steps"]]
    assert afters == sorted(afters)
    assert all(s["gain"] >= 0 for s in p["steps"])


def test_headline_text_gives_exposure_or_points_to_perdedor_score():
    from perdedor_common.exposure import headline, headline_text

    summary = {"raw_score": "0/0", "detected": 0, "errored": 0, "skipped": 0}
    unscorable = {"platform": "nonexistent", "findings": [], "summary": summary}
    assert headline(unscorable) is None
    assert headline_text(unscorable).endswith("Exposure score: perdedor score <report.json>")
