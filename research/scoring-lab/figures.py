"""Render the scoring-lab figure used in docs/SCORING.md from a lab results.json.

    python3 research/scoring-lab/figures.py RESULTS.json docs/img/scoring-arms.svg

Static SVG with light and dark colours (prefers-color-scheme), direct labels at the line ends and a
legend, so identity never rests on colour alone. The numbers are also tabulated in SCORING.md.
"""

from __future__ import annotations

import json
import sys
from html import escape
from pathlib import Path

SERIES = [  # (results key, label, light, dark)
    ("M0 severity penalty", "M0 v1 formula", "#2a78d6", "#3987e5"),
    ("M1 weighted pass rate", "M1 weighted pass rate", "#eb6834", "#d95926"),
    ("M3 noisy-OR exposure", "M3 measured only", "#1baf7a", "#199e70"),
    ("PEM-1 production (perdedor_common.exposure)", "PEM-1 (chosen)", "#eda100", "#c98500"),
]
LABEL_ARM = {"H3b+clock": "H3b+clk"}


def render(results: dict) -> str:
    arms = results["arms"]["arms"]
    models = results["arms"]["models"]
    W, H = 800, 420
    L, R, T, B = 56, 200, 56, 56
    pw, ph = W - L - R, H - T - B

    def x(i):
        return L + pw * i / (len(arms) - 1)

    def y(v):
        return T + ph * (1 - v / 100)

    css_vars_light = "".join(f"--s{i}:{s[2]};" for i, s in enumerate(SERIES))
    css_vars_dark = "".join(f"--s{i}:{s[3]};" for i, s in enumerate(SERIES))
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" '
        'aria-labelledby="t d" font-family="system-ui,-apple-system,Segoe UI,sans-serif">',
        '<title id="t">Score of each hardening arm under four scoring models</title>',
        '<desc id="d">Arms H1 to H3b are successive hardening steps of one Xen sandbox, each measured five times '
        "with Perdedor and al-khaser. The v1 formula and the weighted pass rate stay between 95 and 99 for every "
        "arm; the exposure models spread the arms from under 10 to about 60.</desc>",
        "<style>",
        f":root{{--bg:#fcfcfb;--ink:#1f1f1e;--ink2:#5c5b55;--grid:#e4e3df;{css_vars_light}}}",
        f"@media (prefers-color-scheme:dark){{:root{{--bg:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--grid:#3a3936;{css_vars_dark}}}}}",
        ".bg{fill:var(--bg)} .t{fill:var(--ink);font-size:15px;font-weight:600} .a{fill:var(--ink2);font-size:12px}"
        " .g{stroke:var(--grid);stroke-width:1} .l{fill:var(--ink);font-size:12px}",
        "</style>",
        f'<rect class="bg" width="{W}" height="{H}" rx="8"/>',
        f'<text class="t" x="{L}" y="26">Same experiments, four scoring models</text>',
        f'<text class="a" x="{L}" y="44">Median of 5 scans per arm; higher = better hidden. Arms left to right = fixes applied.</text>',
    ]
    for v in (0, 25, 50, 75, 100):
        out.append(f'<line class="g" x1="{L}" x2="{L + pw}" y1="{y(v):.1f}" y2="{y(v):.1f}"/>')
        out.append(f'<text class="a" x="{L - 8}" y="{y(v) + 4:.1f}" text-anchor="end">{v}</text>')
    for i, a in enumerate(arms):
        out.append(
            f'<text class="a" x="{x(i):.1f}" y="{T + ph + 20}" text-anchor="middle">{escape(LABEL_ARM.get(a, a))}</text>'
        )
    ends = []
    for si, (key, label, *_c) in enumerate(SERIES):
        if key not in models:
            continue
        med = models[key]["median"]
        pts = [(x(i), y(med[a])) for i, a in enumerate(arms)]
        d = " ".join(f"{'M' if j == 0 else 'L'}{px:.1f},{py:.1f}" for j, (px, py) in enumerate(pts))
        out.append(
            f'<path d="{d}" fill="none" stroke="var(--s{si})" stroke-width="2" stroke-linejoin="round"/>'
        )
        for (px, py), a in zip(pts, arms, strict=True):
            out.append(
                f'<circle cx="{px:.1f}" cy="{py:.1f}" r="4" fill="var(--s{si})" stroke="var(--bg)" stroke-width="2">'
                f"<title>{escape(label)} — {escape(a)}: {med[a]:.1f}</title></circle>"
            )
        ends.append([pts[-1][1], label, si, med[arms[-1]]])
    # direct labels at the right edge, nudged apart so they never overlap
    ends.sort()
    for i in range(1, len(ends)):
        ends[i][0] = max(ends[i][0], ends[i - 1][0] + 16)
    for ey, label, si, v in ends:
        out.append(
            f'<rect x="{L + pw + 12}" y="{ey - 5:.1f}" width="10" height="10" rx="2" fill="var(--s{si})"/>'
        )
        out.append(f'<text class="l" x="{L + pw + 28}" y="{ey + 4:.1f}">{escape(label)} ({v:.0f})</text>')
    out.append("</svg>")
    return "\n".join(out)


if __name__ == "__main__":
    Path(sys.argv[2]).write_text(render(json.loads(Path(sys.argv[1]).read_text())), encoding="utf-8")
