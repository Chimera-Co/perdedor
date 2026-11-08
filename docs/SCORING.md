# Scoring: the Perdedor exposure model

Perdedor reports one headline number per run, the **exposure score**:

> **Share of known evasive malware expected to see no sign of analysis in this environment and run
> normally.** 0–100, higher is better. Techniques that were not measured are estimated from those that were.

Next to it Perdedor reports:
- a 90 % interval;
- the score from measured techniques only;
- coverage;
- a score and a "points lost" figure for each of the 19 classes and the 4 categories;
- the techniques that fired, ranked by how much they cost;
- the malware families most exposed (once a sourced threat model is loaded);
- four trustworthiness grades;
- a hardening roadmap ordered by gain per unit of effort.

The model was chosen, not assumed. Seven candidate formulas were tested against eleven stated
requirements, on synthetic environments and on nine labelled hardening experiments of a real Xen
sandbox. This page records the candidates, the tests, the evidence and the decision.
`research/scoring-lab/` reproduces all of it.

- [Why the old score had to go](#why-the-old-score-had-to-go)
- [The model](#the-model)
- [Reading a result](#reading-a-result)
- [How the model was chosen](#how-the-model-was-chosen)
- [Trustworthiness pillars](#trustworthiness-pillars)
- [Hardening roadmap](#hardening-roadmap)
- [Parameters and where they come from](#parameters-and-where-they-come-from)
- [Limits](#limits)

## Why the old score had to go

Perdedor 1.x scored `100 × (1 − Σ severity weight of detections / number of applicable checks)`.
On the Xen sandbox used for CHIMERA it reported **99.48 and then 100.0**, while al-khaser still found
20 detections in every run of the same snapshot. The number had three faults:

- **Dilution.** Every clean check adds to the denominator. A suite that adds twenty trivial checks
  raises every score, so the result depends on how many checks the suite has, not on the environment.
- **No sense of what matters.** A CPUID hypervisor bit, which most evasive malware checks,
  counted about the same as an obscure registry key. One decisive giveaway barely moved the score.
- **Saturation.** Across nine hardening steps the old formula moved by 1.3 points, from 97.0 to 98.3.
  The new one moves by 37 points over the same steps (figure below). Operators could not see their
  progress, and could not see what was still left.

## The model

For each technique *i* in the catalog, two values come from `catalog/`:
- **prevalence** *pᵢ*: the share of evasive samples that use the technique, from its tier, or from
  the threat model when one is loaded;
- **discrimination** *qᵢ*: how reliably our check firing means the malware's own version of the
  check fires too.

A run gives, for each technique, a hit *hᵢ* ∈ [0, 1]: 0 when every check was clean, otherwise the
highest confidence of a check that detected. A technique with no applicable check is **untested**.

**Untested techniques are estimated, not assumed clean.**
- Each untested technique gets the expected detection rate *rᵢ* of its class: the observed rate in
  the class, shrunk towards the run's overall rate with the weight of two techniques.
- A second-order correction then removes the optimism caused by sharing one estimated rate across
  a class.
- Without this step a quick profile would score better than a full one. With it, dropping 40 % of
  the techniques changes the score by −0.2 points on average, against +15 for the measured-only score.

**Without a sourced threat model**, the score is the survival of a sample that uses each technique
independently with chance *pᵢ*:

$$S = 100 \cdot \prod_i \left(1 - p_i\, q_i\, \tilde h_i\right), \qquad \tilde h_i = h_i \text{ if tested, else } r_i$$

**With a sourced threat model** (`catalog/threats.json`, at least ten families for the platform),
the score is the weighted share of families none of whose techniques fire. This form captures the
fact that techniques travel together:

$$S = 100 \cdot \frac{\sum_f w_f \prod_{i \in T_f} \left(1 - q_i\, \tilde h_i\right)}{\sum_f w_f}$$

**Interval.**
- 400 Monte-Carlo draws vary *p* and *q* (a Beta distribution around each catalog value,
  concentration 12) and the outcomes of untested techniques (Bernoulli with rate *rᵢ*).
- The 5th and 95th percentiles form the reported interval.
- The interval is wide when coverage is low or the catalog is uncertain. That width is the point.

**Classes and categories.**
- A class's score is its own survival, `100 · Π_{i∈class} (1 − pᵢ qᵢ h̃ᵢ)`.
- The headline's lost points are shared among classes by their share of the log-loss, so
  "points lost" sums exactly to `100 − score`.
- A category's score is the product of its class scores. Its points lost is the sum over its classes.

**Verdict bands** match the console: pass ≥ 90, warn ≥ 70, fail below.

Implementation: `common/python/perdedor_common/exposure.py` (`assess`, `plan`). Regression tests
for every axiom: `tests/test_exposure.py`.

## Reading a result

```
$ perdedor score windows-report.json
Perdedor exposure score (windows): 41.8/100  [FAIL]
  Share of known evasive malware expected to see no sign of analysis here and run normally ...
  90 % interval 20.6-63.2; measured techniques only: 59.4; coverage 75% (53/104 techniques tested, 9 detected)

Categories                    score  points lost  tested/all  detected
  Environment artifacts         53.2         42.1    26/45            7
  Design-specific               89.0          7.8    16/37            1
  Timing                        89.4          7.5     4/7             1
  Behaviour and interaction     98.8          0.8     7/15            0

Classes                                    score  lost  tested/all det
  Firmware (SMBIOS / ACPI / BIOS)           75.6  18.6    4/6     2  ###############.....
  Registry, files and named objects         87.9   8.6    4/5     1  ##################..
  Devices and peripherals                   88.2   8.4    8/14    4  ##################..
  ...
```

| Field | Meaning |
|---|---|
| `score` | The headline (estimates untested techniques) |
| `observed` | The same model with untested techniques treated as clean: an upper bound for this run |
| `interval` | 90 % credible interval of the headline |
| `coverage` | Share of the platform's technique weight (Σ *p q*) that a check measured |
| `classes.*.score` | Survival within the class; 100 = nothing in this class gives the environment away |
| `classes.*.points_lost` | How many of the headline's lost points this class accounts for |
| `detected[]` | Techniques that fired, highest hazard *p q h* first, with the checks and tools that saw them |
| `untested_top[]` | Techniques that were not measured but probably fire (largest expected cost first) |
| `families[]` | (with a threat model) families with the lowest chance of running, and what triggers them |
| `pillars` | How far the number can be trusted (below) |

## How the model was chosen

### Candidates

| | Model | Formula |
|---|---|---|
| M0 | v1 severity penalty | `100 (1 − Σ_det w_sev / N_applicable)` |
| M1 | Weighted pass rate | `100 (1 − Σ_det w / Σ_applicable w)` |
| M2 | Points (VMAware style) | `100 max(0, 1 − Σ_det points / 150)` |
| M3 | Noisy-OR exposure | `100 Π (1 − p q h)` over measured techniques |
| M4 | Family survival | weighted share of families none of whose techniques fire |
| M5 | Hybrid | M4 or M3, with an interval; also a variant with coverage imputed |
| M6 | Weakest class | lowest prevalence-weighted class pass rate |

### Axioms

| # | Requirement | Why |
|---|---|---|
| A1 | One more detection never raises the score, and lowers it | Basic monotonicity |
| A2 | Redundant clean checks change nothing | The score must not depend on suite size (no dilution) |
| A3 | One CPUID hypervisor-bit hit costs more than five hits on rare, weak techniques, and alone fails the pass line | Severity dominance |
| A4 | Hardening arms are ranked in the order the experiments measured | Validity on real data |
| A5 | Repeated scans of one arm agree; the arm explains the variance | Reliability |
| A6 | Perdedor-only and al-khaser-only scores agree on the same scans | Tool-independence (convergent validity) |
| A7 | The headline decomposes into class and category parts | Explainability |
| A8 | Running fewer checks does not raise the score | Coverage honesty |
| A9 | The number has a plain meaning | Interpretability |
| A10 | The score uses its range (clean = 100; more detections = clearly lower) | Resolution |
| A11 | Conclusions survive catalog values that are off by up to 2× | Robustness to our own guesses |

### Synthetic results

Random Windows environments drawn from the catalog (60 trials per axiom; `research/scoring-lab/results/`):

| Model | A1 strictly down | A2 gain from 20 padding checks | A3 one strong vs five weak | A3 strong alone < 90 | A8 rise with 40 % fewer techniques | A10 at 10 % / 33 % hits |
|---|---|---|---|---|---|---|
| M0 v1 | 100 % | **+0.95** | **no** (99.4 vs 99.1) | **no** | −0.4 | 96.8 / 89.2 |
| M1 | 100 % | **+2.46** | **no** (98.3 vs 97.6) | **no** | −0.6 | 91.2 / 71.4 |
| M2 | **2 %** | 0 | **no** (36.7 vs 0.0) | yes | 0 | **0 / 0** |
| M3 | 100 % | 0 | yes (71.5 vs 97.0) | yes | **+15.2** | 37.7 / 5.0 |
| M4 | 97 % | 0 | yes (74.1 vs 97.0) | yes | **+15.3** | 39.4 / 5.1 |
| M5 coverage-imputed | 100 % | 0 | yes (72.0 vs 98.2) | yes | +0.3 | 36.6 / 3.5 |
| M6 | **2 %** | 0 | yes | yes | −4.8 | 52.5 / 26.8 |
| **PEM-1 (shipped)** | **100 %** | **0** | **yes (71.5 vs 97.0)** | **yes** | **−0.2** | **36.8 / 3.9** |

### Labelled hardening experiments

The experiments are nine snapshots and configurations of one Xen + DRAKVUF Windows 10 sandbox,
produced by successive fixes, and each was scanned five times by Perdedor and al-khaser together.
Every al-khaser and Perdedor check was mapped onto a technique (`research/scoring-lab/toolmap.py`;
all 340 al-khaser, 58 Pafish and 15 VMAware ids map). The arms are:
- **H1** hardened image;
- **S** CPUID leaves hidden by the instrumentation;
- **H** simulated input;
- **H2** host firmware identifiers, in three snapshot variants (a, b, c);
- **H3** everyday applications installed, in two variants (a, b);
- **+clock** guest clock synchronised.

Ten pairs are known to be ordered, because each was a measured fix:
- H1 < H1S < H1SH < H2c;
- H2a, H2b < H2c;
- H2c < H3b;
- H3a < H3b;
- H3b+clock < H3b;
- H1 < H3b.

![Score of each hardening arm under four models](img/scoring-arms.svg)

| Model | H1 | H1S | H1SH | H2a | H2b | H2c | H3a | H3b | H3b+clock | Pairs right | Range | A6 agreement | A11 pairs right, p and q off by 2× |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| M0 v1 | 97.0 | 97.4 | 97.6 | 98.1 | 98.1 | 98.3 | 98.2 | 98.4 | 98.2 | 10/10 | **1.3** | 0.79 | 100 % |
| M1 | 94.9 | 95.5 | 95.9 | 96.7 | 96.8 | 97.1 | 96.9 | 97.2 | 96.9 | 10/10 | **2.3** | 0.79 | 100 % |
| M2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **0/10** | 0 | – | 0 % |
| M3 | 8.5 | 16.9 | 21.0 | 50.5 | 49.8 | 56.2 | 53.4 | 59.4 | 53.4 | 10/10 | 50.9 | 0.80 | 100 % |
| M4 | 10.6 | 17.2 | 21.7 | 52.7 | 50.0 | 57.1 | 55.1 | 59.9 | 55.1 | 10/10 | 49.2 | 0.73 | 100 % |
| M5 imputed | 4.1 | 9.5 | 12.7 | 34.3 | 32.9 | 39.6 | 38.0 | 43.2 | 38.0 | 10/10 | 39.0 | 0.73 | 100 % |
| M6 | 23.2 | 23.2 | 23.2 | 57.5 | 5.0 | 66.4 | 66.4 | 66.4 | 66.4 | **4/10** | 61.4 | 0.50 | **53 %** |
| **PEM-1** | **4.3** | **9.5** | **12.8** | **33.3** | **31.9** | **38.2** | **36.8** | **41.8** | **36.8** | **10/10** | **37.4** | **0.84** | **100 %** |

*Agreement*: Spearman correlation between the score computed from Perdedor's checks alone and
from al-khaser's checks alone, over the same 45 scans. In every model the arm explains ≥ 99 % of the
variance between scans (η²); scans of one arm differ by 0.1 points or less.

### Decision

**PEM-1** is the coverage-imputed hybrid (M5), with a second-order correction and the trust pillars.
It is the only candidate that meets every requirement:

- **M0 and M1 are rejected** for dilution (A2) and for ignoring severity (A3). Their arm order is
  right, but their nine hardening steps span 1–2 points: correct, and useless to an operator.
- **M2 is rejected** because it saturates. One environment already exceeds VMAware's 150-point
  threshold, after which nothing can be distinguished.
- **M6 is rejected** because it is blind to every class except one. It ties and misorders arms
  (A4, A11). It stays available as a view, as the lowest class score.
- **M3 and M4 rank arms well** but reward running fewer checks (A8: +15 points). A quick profile
  would look safer than a full one.
- **M5 imputed and PEM-1 meet A1–A11.** PEM-1 adds the Jensen correction (a deterministic,
  monotonic point estimate instead of a Monte-Carlo median) and has the best tool agreement (0.84).

When `catalog/threats.json` holds sourced families, PEM-1 switches its headline from the noisy-OR
form to the family form (M4's structure). That form represents techniques that malware uses
together, which the independence assumption of M3 cannot.

## Trustworthiness pillars

A number is only as good as the evidence behind it. Perdedor grades each result on the four
criteria Lincoln and Guba proposed for the trustworthiness of qualitative inquiry, adapted here to
measurement. The grades sit **next to** the score and never change it.

| Pillar | Question | Measured as | Grade |
|---|---|---|---|
| Credibility | Do independent observations agree? | Share of tested weight resting on ≥ 2 agreeing checks; contradictions count against | A ≥ 0.9, B ≥ 0.75, C ≥ 0.5, D below |
| Transferability | Does the threat population apply here? | With a threat model: share of each family's techniques that were tested, weighted. Without one: coverage, halved | same |
| Dependability | Would a rerun say the same? | With `trials` > 1: share of techniques with the same verdict in every run | n/a for a single run |
| Confirmability | Can each verdict be traced to evidence? | Share of applicable findings that recorded evidence or a measurement | same |

The overall grade is the lowest of the four, because a chain is as strong as its weakest link.

## Hardening roadmap

`perdedor plan report.json` (and the console's roadmap panel) turns the assessment into an
ordered list of fixes:

1. Start from the current score. Untested techniques stay at their estimate.
2. For each detected technique, compute the score gain of fixing it, divided by its **effort**
   (1 = minutes in the guest … 5 = architectural). Effort and the fix layer come from the check
   catalog (`fix.effort`, `fix.layer`, `fix.how`).
3. Apply the fix with the best gain per unit of effort, recompute, and repeat. Because the model is
   multiplicative, a fix's value grows as the others are done.
4. After the fixes, list the untested techniques with the largest expected cost, so the next scan
   measures them.

On the H3b scan above, four fixes take the score from 42 to 66:
- named-object artifacts;
- SMBIOS table layout;
- ACPI table layout;
- CPUID VM-exit timing.

Fixing every detection reaches 70. The rest is held back by untested techniques, which is the cue to
run a deeper profile.

## Parameters and where they come from

| Parameter | Source | Notes |
|---|---|---|
| *p* (prevalence) | technique tier in `catalog/techniques.json` (very common 0.30 … research 0.003), or a numeric `prevalence` set from published research | Tiers are deliberately coarse; A11 shows the conclusions hold when every value is off by up to 2× |
| *q* (discrimination) | `techniques.json` `discrimination` | How decisive the technique is on real machines |
| *h* (hit) | the finding's `confidence`, default 1.0 for a detection | Agents set lower confidence for timing and statistical checks |
| Families *T_f*, *w_f* | `catalog/threats.json` | Sourced entries only: every technique of a family cites a public analysis |
| Shrinkage, interval width | `SHRINK = 2`, `KAPPA = 12` in `exposure.py` | Lab-checked; changing them requires rerunning the lab |

## Limits

- **The prevalences are estimates.** The tiers summarise public reporting, not a census of malware.
  The interval and A11 bound how much this matters for rankings, but an absolute score of 40 does not
  mean exactly 40 % of all malware.
- **Independence in the noisy-OR form.** Techniques that tend to be used together, such as the CPUID
  bit and the vendor leaf, are double-counted until a sourced threat model replaces the form.
- **A check is not the malware.** *q* stands for the gap between our check and a sample's check of
  the same technique. Real samples may use stricter or looser thresholds.
- **The score is about this environment, at scan time.** It says nothing about whether the
  sandbox's instrumentation, network or analysis quality is good. It only says how visible the
  sandbox is.
