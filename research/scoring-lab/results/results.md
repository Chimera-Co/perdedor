# Scoring lab results

Synthetic trials per axiom: 60. Threat model: pseudo-families drawn from technique tiers (provisional).

## Synthetic axioms

| Model | A1 never up | A1 strictly down | A2 mean gain from padding | A3 one strong < five weak | A3 one strong < 90 | A8 mean rise with 40 % fewer techniques | A10 score at 10 % / 33 % hits |
|---|---|---|---|---|---|---|---|
| M0 severity penalty | 100% | 100% | +0.95 | **no** (99.4 vs 99.1) | **no** | -0.39 | 96.8 / 89.2 |
| M1 weighted pass rate | 100% | 100% | +2.46 | **no** (98.3 vs 97.6) | **no** | -0.64 | 91.2 / 71.4 |
| M2 points (VMAware-style) | 100% | 2% | +0.00 | **no** (36.7 vs 0.0) | yes | +0.00 | 0.0 / 0.0 |
| M3 noisy-OR exposure | 100% | 100% | +0.00 | yes (71.5 vs 97.0) | yes | +15.20 | 37.7 / 5.0 |
| M4 family survival | 100% | 97% | +0.00 | yes (74.1 vs 97.0) | yes | +15.34 | 39.4 / 5.1 |
| M5 hybrid (point) | 100% | 100% | +0.00 | yes (71.5 vs 97.0) | yes | +15.20 | 37.7 / 5.0 |
| M5 hybrid (coverage-imputed) | 100% | 100% | +0.00 | yes (72.0 vs 98.2) | yes | +0.33 | 36.6 / 3.5 |
| M6 weakest class | 100% | 2% | +0.00 | yes (70.6 vs 98.3) | yes | -4.84 | 52.5 / 26.8 |
| PEM-1 production (perdedor_common.exposure) | 100% | 100% | +0.00 | yes (71.5 vs 97.0) | yes | -0.24 | 36.8 / 3.9 |

## Qualitative properties

| Model | What the number means | Decomposes by class |
|---|---|---|
| M0 severity penalty | no probabilistic meaning; depends on how many checks the suite has | partly (sum of penalties, but the denominator couples classes) |
| M1 weighted pass rate | share of check weight that passed | yes (weighted mean of class pass rates) |
| M2 points (VMAware-style) | distance from a fixed 'certain VM' threshold | yes (sum of points) |
| M3 noisy-OR exposure | chance that an evasive sample drawn at random sees no tell | yes (product of class survivals; log-loss adds up by class) |
| M4 family survival | weighted share of known evasive families that would run normally | by family, not by class |
| M5 hybrid (point) | as M4 (or M3), with a credible interval | by family; class view from M3 log-loss |
| M5 hybrid (coverage-imputed) | as M5, with untested techniques imputed from tested ones | by family; class view from M3 log-loss |
| M6 weakest class | pass rate of the worst class | only the weakest class shows |
| PEM-1 production (perdedor_common.exposure) | as M5 coverage-imputed, with the Jensen correction and pillars | yes: class survivals and points lost per class/category |
