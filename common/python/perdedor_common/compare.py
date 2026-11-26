"""Compare two PERDEDOR reports: finding regressions, fixes, and score deltas.

Shows:
- Checks that newly fire (regressions: clean/skipped -> detected)
- Checks that stopped firing (fixes: detected -> clean/skipped)
- Checks with changed measurements or timing
- Score deltas (raw exposure delta, with a named place for net: "net: no baseline")
- Category and class breakdowns
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .catalog import Catalog, load_catalog
from .exposure import assess
from .report_reader import read_report

CATEGORY_TITLES = {
    "environment_artifact": "Environment artifacts",
    "timing": "Timing",
    "behavioural_interaction": "Behaviour and interaction",
    "design_specific": "Design-specific",
}


def compare_reports(
    report_a_input: Any,
    report_b_input: Any,
    catalog: Catalog | None = None,
    baseline: Any = None,
    baseline_store: str | Path | None = None,
) -> dict:
    """Compare baseline report A with current report B.

    When ``baseline`` is provided, evaluates net exposure deltas relative to the bare-metal baseline.
    """
    catalog = catalog or load_catalog()
    doc_a = read_report(report_a_input, validate=False)
    doc_b = read_report(report_b_input, validate=False)

    baseline_doc = None
    if baseline is not None:
        from .baseline import resolve_baseline

        baseline_doc = resolve_baseline(baseline, store_dir=baseline_store)

    findings_a = {f["id"]: f for f in doc_a.get("findings", [])}
    findings_b = {f["id"]: f for f in doc_b.get("findings", [])}

    all_ids = sorted(set(findings_a.keys()) | set(findings_b.keys()))

    newly_firing = []
    stopped_firing = []
    changed_measurement = []

    for cid in all_ids:
        fa = findings_a.get(cid)
        fb = findings_b.get(cid)

        st_a = fa["status"] if fa else "absent"
        st_b = fb["status"] if fb else "absent"

        tech = (fb or fa or {}).get("technique") or (catalog.check(cid) or {}).get("technique", cid)
        title = (fb or fa or {}).get("name") or (catalog.check(cid) or {}).get("name", cid)
        severity = (fb or fa or {}).get("severity", "info")
        check_class = (fb or fa or {}).get("class") or (catalog.technique(tech) or {}).get("class", "unknown")
        category = (fb or fa or {}).get("category") or catalog.class_category(check_class)

        item = {
            "id": cid,
            "technique": tech,
            "title": title,
            "class": check_class,
            "category": category,
            "severity": severity,
            "status_a": st_a,
            "status_b": st_b,
        }

        if st_b == "detected" and st_a != "detected":
            item["evidence"] = fb.get("evidence")
            item["confidence"] = fb.get("confidence")
            newly_firing.append(item)
        elif st_a == "detected" and st_b != "detected":
            item["evidence_before"] = fa.get("evidence")
            stopped_firing.append(item)
        elif fa and fb and st_a == st_b:
            # Check for measurement changes
            meas_a = fa.get("measurement")
            meas_b = fb.get("measurement")
            conf_a = fa.get("confidence")
            conf_b = fb.get("confidence")
            if meas_a != meas_b or (
                conf_a is not None and conf_b is not None and abs(conf_a - conf_b) >= 0.05
            ):
                item["measurement_a"] = meas_a
                item["measurement_b"] = meas_b
                item["confidence_a"] = conf_a
                item["confidence_b"] = conf_b
                changed_measurement.append(item)

    # Exposure assessments
    plat_a = doc_a.get("platform", "unknown")
    plat_b = doc_b.get("platform", "unknown")

    score_a = None
    score_b = None
    assess_a = {}
    assess_b = {}

    try:
        assess_a = assess(doc_a.get("findings", []), plat_a, catalog, baseline=baseline_doc)
        score_a = assess_a.get("score")
    except Exception:
        pass
    if score_a is None and "summary" in doc_a:
        score_a = doc_a["summary"].get("weighted_score")

    try:
        assess_b = assess(doc_b.get("findings", []), plat_b, catalog, baseline=baseline_doc)
        score_b = assess_b.get("score")
    except Exception:
        pass
    if score_b is None and "summary" in doc_b:
        score_b = doc_b["summary"].get("weighted_score")

    raw_score_delta = round(score_b - score_a, 2) if (score_a is not None and score_b is not None) else None

    # Net deltas
    has_net = (
        baseline_doc is not None
        and isinstance(assess_a.get("net"), dict)
        and isinstance(assess_b.get("net"), dict)
    )
    net_score_a = assess_a["net"].get("score") if has_net else None
    net_score_b = assess_b["net"].get("score") if has_net else None
    if has_net and net_score_a is not None and net_score_b is not None:
        net_overall_delta = round(net_score_b - net_score_a, 2)
        net_overall_delta_str = f"{net_overall_delta:+6.1f}".strip()
    else:
        net_overall_delta = None
        net_overall_delta_str = "net: no baseline"

    # Categories breakdown
    categories_delta = {}
    cats_a = assess_a.get("categories", {})
    cats_b = assess_b.get("categories", {})
    all_cats = sorted(set(cats_a.keys()) | set(cats_b.keys()))

    for cat in all_cats:
        c_a = cats_a.get(cat, {})
        c_b = cats_b.get(cat, {})
        sa = c_a.get("score")
        sb = c_b.get("score")
        delta = round(sb - sa, 2) if (sa is not None and sb is not None) else None

        if has_net:
            net_ca = assess_a["net"].get("categories", {}).get(cat, {})
            net_cb = assess_b["net"].get("categories", {}).get(cat, {})
            nsa = net_ca.get("score")
            nsb = net_cb.get("score")
            if nsa is not None and nsb is not None:
                net_cat_delta = f"{round(nsb - nsa, 2):+6.1f}".strip()
            else:
                net_cat_delta = "n/a"
        else:
            net_cat_delta = "net: no baseline"

        categories_delta[cat] = {
            "title": CATEGORY_TITLES.get(cat, cat),
            "score_a": sa,
            "score_b": sb,
            "raw_delta": delta,
            "net_delta": net_cat_delta,
            "detected_a": c_a.get("detected", 0),
            "detected_b": c_b.get("detected", 0),
        }

    # Classes breakdown
    classes_delta = {}
    cls_a = assess_a.get("classes", {})
    cls_b = assess_b.get("classes", {})
    all_cls = sorted(set(cls_a.keys()) | set(cls_b.keys()))

    for k in all_cls:
        ca = cls_a.get(k, {})
        cb = cls_b.get(k, {})
        sa = ca.get("score")
        sb = cb.get("score")
        delta = round(sb - sa, 2) if (sa is not None and sb is not None) else None
        title = cb.get("title") or ca.get("title") or k

        if has_net:
            net_ca = assess_a["net"].get("classes", {}).get(k, {})
            net_cb = assess_b["net"].get("classes", {}).get(k, {})
            nsa = net_ca.get("score")
            nsb = net_cb.get("score")
            if nsa is not None and nsb is not None:
                net_cls_delta = f"{round(nsb - nsa, 2):+6.1f}".strip()
            else:
                net_cls_delta = "n/a"
        else:
            net_cls_delta = "net: no baseline"

        classes_delta[k] = {
            "title": title,
            "score_a": sa,
            "score_b": sb,
            "raw_delta": delta,
            "net_delta": net_cls_delta,
            "detected_a": ca.get("detected", 0),
            "detected_b": cb.get("detected", 0),
        }

    return {
        "report_a": {
            "scan_id": doc_a.get("scan_id"),
            "platform": plat_a,
            "profile": doc_a.get("selection", {}).get("profile"),
            "generated_at": doc_a.get("generated_at"),
            "score": score_a,
        },
        "report_b": {
            "scan_id": doc_b.get("scan_id"),
            "platform": plat_b,
            "profile": doc_b.get("selection", {}).get("profile"),
            "generated_at": doc_b.get("generated_at"),
            "score": score_b,
        },
        "overall": {
            "score_a": score_a,
            "score_b": score_b,
            "raw_delta": raw_score_delta,
            "net_delta": net_overall_delta_str,
            "net_score_a": net_score_a,
            "net_score_b": net_score_b,
            "baseline": (
                {
                    "profile": baseline_doc.get("profile", "custom"),
                    "scan_id": baseline_doc.get("scan_id", "-"),
                    "os": baseline_doc.get("os", "-"),
                    "date": baseline_doc.get("date", "-"),
                }
                if baseline_doc
                else None
            ),
        },
        "categories": categories_delta,
        "classes": classes_delta,
        "newly_firing": newly_firing,
        "stopped_firing": stopped_firing,
        "changed_measurement": changed_measurement,
    }


def render_compare_text(diff: dict) -> str:
    ra = diff["report_a"]
    rb = diff["report_b"]
    ov = diff["overall"]

    sa_str = f"{ov['score_a']:.1f}" if ov["score_a"] is not None else "n/a"
    sb_str = f"{ov['score_b']:.1f}" if ov["score_b"] is not None else "n/a"
    delta_str = f"{ov['raw_delta']:+.1f}" if ov["raw_delta"] is not None else "n/a"

    L = [
        "PERDEDOR Report Comparison",
        f"  A (baseline): {ra.get('scan_id') or 'unknown'} ({ra['platform']}, {ra.get('profile') or 'profile ?'})",
        f"  B (target):   {rb.get('scan_id') or 'unknown'} ({rb['platform']}, {rb.get('profile') or 'profile ?'})",
    ]
    if ov.get("baseline"):
        b = ov["baseline"]
        L.append(
            f"  Bare-metal baseline: {b['profile']} (scan: {b['scan_id']}, os: {b['os']}, date: {b['date']})"
        )
        nsa_str = f"{ov['net_score_a']:.1f}" if ov.get("net_score_a") is not None else "n/a"
        nsb_str = f"{ov['net_score_b']:.1f}" if ov.get("net_score_b") is not None else "n/a"
        L += [
            "",
            f"Overall Score: raw {sa_str} -> {sb_str} (delta: {delta_str}); "
            f"net {nsa_str} -> {nsb_str} (delta: {ov['net_delta']})",
            "",
        ]
    else:
        L += [
            "",
            f"Overall Score: {sa_str} -> {sb_str} (delta: raw {delta_str}, {ov['net_delta']})",
            "",
        ]

    L += [
        "Categories                        A      B   raw delta   net delta",
        "-------------------------------------------------------------------------",
    ]
    for _cat, cd in diff["categories"].items():
        sa = f"{cd['score_a']:5.1f}" if cd["score_a"] is not None else "  n/a"
        sb = f"{cd['score_b']:5.1f}" if cd["score_b"] is not None else "  n/a"
        d = f"{cd['raw_delta']:+6.1f}" if cd["raw_delta"] is not None else "   n/a"
        title = cd["title"][:28]
        L.append(f"  {title:<30} {sa}  {sb}  {d}   {cd['net_delta']}")

    L += [
        "",
        "Classes                           A      B   raw delta   net delta",
        "-------------------------------------------------------------------------",
    ]
    for _k, cd in sorted(diff["classes"].items(), key=lambda kv: kv[1]["title"]):
        sa = f"{cd['score_a']:5.1f}" if cd["score_a"] is not None else "  n/a"
        sb = f"{cd['score_b']:5.1f}" if cd["score_b"] is not None else "  n/a"
        d = f"{cd['raw_delta']:+6.1f}" if cd["raw_delta"] is not None else "   n/a"
        title = cd["title"][:30]
        L.append(f"  {title:<32} {sa}  {sb}  {d}   {cd['net_delta']}")

    newly = diff["newly_firing"]
    stopped = diff["stopped_firing"]
    changed = diff["changed_measurement"]

    L += ["", f"Checks newly firing (regressions: {len(newly)})"]
    if newly:
        for c in newly:
            L.append(f"  [+] {c['id']:<40} [{c['severity'].upper()}] {c['title']}")
            if c.get("evidence"):
                L.append(f"        evidence: {c['evidence']}")
    else:
        L.append("  (none)")

    L += ["", f"Checks stopped firing (fixed: {len(stopped)})"]
    if stopped:
        for c in stopped:
            L.append(f"  [-] {c['id']:<40} {c['title']}")
    else:
        L.append("  (none)")

    if changed:
        L += ["", f"Checks with changed measurement ({len(changed)})"]
        for c in changed:
            L.append(f"  [~] {c['id']:<40} {c['title']}")
            if c.get("measurement_a") or c.get("measurement_b"):
                L.append(f"        A: {c.get('measurement_a')}")
                L.append(f"        B: {c.get('measurement_b')}")

    return "\n".join(L)


def render_compare_markdown(diff: dict) -> str:
    ra = diff["report_a"]
    rb = diff["report_b"]
    ov = diff["overall"]
    sa_str = f"{ov['score_a']:.1f}" if ov["score_a"] is not None else "n/a"
    sb_str = f"{ov['score_b']:.1f}" if ov["score_b"] is not None else "n/a"
    delta_str = f"{ov['raw_delta']:+.1f}" if ov["raw_delta"] is not None else "n/a"

    L = [
        "## PERDEDOR Comparison",
        f"- **Baseline (A)**: `{ra.get('scan_id')}` ({ra['platform']}, profile `{ra.get('profile')}`)",
        f"- **Target (B)**: `{rb.get('scan_id')}` ({rb['platform']}, profile `{rb.get('profile')}`)",
    ]
    if ov.get("baseline"):
        b = ov["baseline"]
        L.append(
            f"- **Bare-Metal Baseline**: `{b['profile']}` (scan: `{b['scan_id']}`, os: {b['os']}, date: {b['date']})"
        )
        nsa_str = f"{ov['net_score_a']:.1f}" if ov.get("net_score_a") is not None else "n/a"
        nsb_str = f"{ov['net_score_b']:.1f}" if ov.get("net_score_b") is not None else "n/a"
        L.append(
            f"- **Exposure Score**: raw **{sa_str}** &rarr; **{sb_str}** (delta: **{delta_str}**); "
            f"net **{nsa_str}** &rarr; **{nsb_str}** (delta: **{ov['net_delta']}**)"
        )
    else:
        L.append(
            f"- **Exposure Score**: **{sa_str}** &rarr; **{sb_str}** (raw: **{delta_str}**, *{ov['net_delta']}*)"
        )

    L += [
        "",
        "### Categories",
        "| Category | A | B | Raw Delta | Net Delta |",
        "|---|---|---|---|---|",
    ]
    for _cat, cd in diff["categories"].items():
        sa = f"{cd['score_a']:.1f}" if cd["score_a"] is not None else "n/a"
        sb = f"{cd['score_b']:.1f}" if cd["score_b"] is not None else "n/a"
        d = f"{cd['raw_delta']:+.1f}" if cd["raw_delta"] is not None else "n/a"
        L.append(f"| {cd['title']} | {sa} | {sb} | {d} | {cd['net_delta']} |")

    L += ["", "### Classes", "| Class | A | B | Raw Delta | Net Delta |", "|---|---|---|---|---|"]
    for _k, cd in sorted(diff["classes"].items(), key=lambda kv: kv[1]["title"]):
        sa = f"{cd['score_a']:.1f}" if cd["score_a"] is not None else "n/a"
        sb = f"{cd['score_b']:.1f}" if cd["score_b"] is not None else "n/a"
        d = f"{cd['raw_delta']:+.1f}" if cd["raw_delta"] is not None else "n/a"
        L.append(f"| {cd['title']} | {sa} | {sb} | {d} | {cd['net_delta']} |")

    newly = diff["newly_firing"]
    stopped = diff["stopped_firing"]
    L += ["", f"### Newly Firing Checks ({len(newly)})"]
    if newly:
        for c in newly:
            L.append(f"- `[+]` **`{c['id']}`** ({c['severity']}): {c['title']}")
    else:
        L.append("_None_")
    return "\n".join(L)

    L += ["", f"### Stopped Firing Checks ({len(stopped)})"]
    if stopped:
        for c in stopped:
            L.append(f"- `[-]` **`{c['id']}`**: {c['title']}")
    else:
        L.append("_None_")

    return "\n".join(L)
