# Scoring lab

Reproduces the model comparison in [docs/SCORING.md](../../docs/SCORING.md).

```bash
python3 research/scoring-lab/lab.py                                # synthetic axioms -> results/
python3 research/scoring-lab/lab.py --arms DIR --out OUT           # plus labelled hardening experiments
python3 research/scoring-lab/figures.py OUT/results.json docs/img/scoring-arms.svg
```

| File | Purpose |
|---|---|
| `models.py` | The candidate models M0–M6 (prototype implementations) |
| `lab.py` | Axioms A1–A11, synthetic environments, labelled-arm evaluation, Markdown/JSON output; also runs the shipped `perdedor_common.exposure` as "PEM-2" |
| `../../common/python/perdedor_common/equivalents.py` | Maps al-khaser, Pafish, VMAware and Perdedor check ids onto catalog techniques |
| `figures.py` | Renders the arms figure (light and dark) |
| `results/` | Synthetic results; labelled-experiment data describes a specific sandbox and is kept outside this repository |

`--arms DIR` expects one folder per experiment with a `checks.jsonl` of rows
`{"arm": "H1S", "run": 1, "scan": "<id>", "tool": "alkhaser", "id": "alkhaser.timing.x", "status": "detected"}`.
Pure Python 3.9+, no dependencies.
