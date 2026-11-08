"""`perdedor score` and `perdedor plan`: exposure score and hardening roadmap for saved reports.

perdedor score windows-report.json                  # headline, classes, categories, pillars
perdedor score run1.json --runs run2.json run3.json  # repeated runs feed the dependability pillar
perdedor plan windows-report.json                   # fixes ordered by score gain per unit of effort
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

CATEGORY_TITLES = {
    "environment_artifact": "Environment artifacts",
    "timing": "Timing",
    "behavioural_interaction": "Behaviour and interaction",
    "design_specific": "Design-specific",
}


def _load(path: str) -> dict:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: could not read {path}: {exc}") from exc
    if isinstance(doc, list):
        return {"platform": None, "findings": doc}
    if "findings" not in doc:
        raise SystemExit(f"error: {path} has no findings list")
    return doc


def _platform(doc: dict, override: str | None) -> str:
    p = override or doc.get("platform")
    if not p:
        raise SystemExit("error: the report does not name its platform; pass --platform")
    return p


def _catalog(path: str | None):
    from perdedor_common.catalog import load_catalog

    return load_catalog(path) if path else load_catalog()


def _bar(score: float, width: int = 20) -> str:
    n = max(0, min(width, round(score / 100 * width)))
    return "#" * n + "." * (width - n)


def render_assessment(a: dict) -> str:
    if a.get("score") is None:
        return f"No score: {a.get('reason')}"
    L = [
        f"Perdedor exposure score ({a['platform']}): {a['score']:.1f}/100  [{a['verdict'].upper()}]",
        f"  {a['meaning']}",
        f"  90 % interval {a['interval'][0]:.1f}-{a['interval'][1]:.1f}; measured techniques only: "
        f"{a['observed']:.1f}; coverage {a['coverage']:.0%} "
        f"({a['techniques']['tested']}/{a['techniques']['platform']} techniques tested, "
        f"{a['techniques']['detected']} detected)",
        f"  threat model: {a['threat_model']['source']}"
        + (f" ({a['threat_model']['families']} families)" if a["threat_model"]["families"] else ""),
        "",
        "Categories                    score  points lost  tested/all  detected",
    ]
    for cat, v in sorted(a["categories"].items(), key=lambda kv: -kv[1]["points_lost"]):
        L.append(
            f"  {CATEGORY_TITLES.get(cat, cat):<26} {v['score']:6.1f}  {v['points_lost']:11.1f}  "
            f"{v['tested']:>4}/{v['techniques']:<5}  {v['detected']:>8}"
        )
    L += ["", "Classes                                    score  lost  tested/all det"]
    for _, v in sorted(a["classes"].items(), key=lambda kv: -kv[1]["points_lost"]):
        L.append(
            f"  {v['title'][:38]:<38} {v['score']:6.1f} {v['points_lost']:5.1f}  "
            f"{v['tested']:>3}/{v['techniques']:<3} {v['detected']:>3}  {_bar(v['score'])}"
        )
    if a["detected"]:
        L += ["", "Detected techniques (largest exposure first)"]
        for d in a["detected"]:
            L.append(f"  {d['hazard']:.3f}  {d['technique']:<36} {d['title'][:60]}")
            L.append(f"         checks: {', '.join(d['checks'][:6])}")
    if a.get("families"):
        L += ["", "Most exposed families (share of each family's runs expected to proceed)"]
        for f in a["families"][:10]:
            L.append(f"  {f['survival']:5.1f} %  {f['name']:<24} triggered: {', '.join(f['triggered'][:5])}")
    if a.get("untested_top"):
        L += ["", "Untested techniques that matter most (measure these next)"]
        for u in a["untested_top"][:8]:
            L.append(f"  est. {u['expected_rate']:.0%} detected  {u['technique']:<36} {u['title'][:50]}")
    L += ["", "Trustworthiness of this result (Lincoln & Guba pillars)"]
    for name in ("credibility", "transferability", "dependability", "confirmability"):
        p = a["pillars"][name]
        v = "  n/a" if p["value"] is None else f"{p['value']:.2f}"
        L.append(f"  {name:<16} {p['grade']:>3}  {v}  {p['basis']}")
    L.append(f"  overall          {a['pillars']['overall']:>3}")
    return "\n".join(L)


def render_plan(p: dict) -> str:
    if p.get("start") is None:
        return "Nothing to plan: no applicable findings."
    L = [
        f"Hardening roadmap ({p['platform']}): {p['start']:.1f} -> {p['end']:.1f} if every step is applied",
        "",
        " #  gain  after  effort  layer            technique",
    ]
    for s in p["steps"]:
        L.append(
            f"{s['step']:>2} {s['gain']:5.1f} {s['score_after']:6.1f}  {s['effort']:>6}  "
            f"{(s['layer'] or '?'):<16} {s['technique']} - {s['title']}"
        )
        if s.get("how"):
            L.append(f"      how: {s['how']}")
    if p["measure_next"]:
        L += ["", "Then measure (no check ran; estimated from similar techniques):"]
        for m in p["measure_next"]:
            have = ", ".join(m["implemented_checks"]) or "no implemented check yet"
            L.append(f"   {m['technique']:<36} est. {m['expected_rate']:.0%}  ({have})")
    return "\n".join(L)


def _cmd_score(args: argparse.Namespace) -> int:
    from perdedor_common.exposure import assess

    doc = _load(args.report)
    runs = [doc["findings"]] + [_load(r)["findings"] for r in args.runs] if args.runs else None
    a = assess(doc["findings"], _platform(doc, args.platform), _catalog(args.catalog), runs=runs)
    if args.json:
        Path(args.json).write_text(json.dumps(a, indent=2), encoding="utf-8")
        print(f"Wrote assessment to {args.json}", file=sys.stderr)
    print(render_assessment(a))
    return 0 if a.get("score") is not None else 1


def _cmd_plan(args: argparse.Namespace) -> int:
    from perdedor_common.exposure import plan

    doc = _load(args.report)
    p = plan(doc["findings"], _platform(doc, args.platform), _catalog(args.catalog), max_steps=args.max_steps)
    if args.json:
        Path(args.json).write_text(json.dumps(p, indent=2), encoding="utf-8")
        print(f"Wrote plan to {args.json}", file=sys.stderr)
    print(render_plan(p))
    return 0


def register(subparsers) -> None:
    score = subparsers.add_parser("score", help="exposure score with per-class/category detail and pillars")
    score.add_argument("report", help="a Perdedor JSON report (or a JSON list of findings)")
    score.add_argument("--runs", nargs="*", default=[], help="repeated runs of the same environment")
    score.add_argument("--platform", help="override the platform named in the report")
    score.add_argument("--catalog", help="catalog directory (default: the repository catalog)")
    score.add_argument("--json", help="also write the full assessment as JSON")
    score.set_defaults(func=_cmd_score)

    pl = subparsers.add_parser(
        "plan", help="hardening roadmap: fixes ordered by score gain per unit of effort"
    )
    pl.add_argument("report", help="a Perdedor JSON report (or a JSON list of findings)")
    pl.add_argument("--platform", help="override the platform named in the report")
    pl.add_argument("--catalog", help="catalog directory (default: the repository catalog)")
    pl.add_argument("--max-steps", type=int, default=25)
    pl.add_argument("--json", help="also write the plan as JSON")
    pl.set_defaults(func=_cmd_plan)
