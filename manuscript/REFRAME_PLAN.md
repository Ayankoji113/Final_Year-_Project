# Paper reframe — from system paper to measurement paper

**Decision taken:** reframe `microapi_guard.tex` around the cross-generator finding.
**Target:** IEEE conference, this cycle, two-column, 6 pages.
**Build:** Overleaf. No LaTeX toolchain here, so the source is written carefully and
validated statically; expect to fix float placement on the first real build.

---

## Why reframe

The current abstract already ends with: *"flagging a transfer risk that recall-only
reporting hides."* That sentence was a caveat. It is now a measurement, and it is the most
novel thing this project has produced.

A four-layer stacking ensemble for API anomaly detection is a crowded space. A *measured*
demonstration that the field's standard evaluation protocol overstates performance by a
factor of sixty is not. The system becomes the instrument; the finding becomes the paper.

Nothing in the existing work is discarded. The gateway, the session-grouped splits, the
withheld families, the FPR budget and the McNemar comparison all survive — they are what
makes the measurement credible, because the in-distribution result was obtained under
*stricter* discipline than the literature usually applies, and it still failed to transfer.

---

## Title candidates

1. **Your Detector Learned the Generator: Cross-Generator Evaluation of Inline API Anomaly Detection**
2. Single-Generator Evaluation Overstates Learned API Anomaly Detection
3. Shape Is Not Semantics: Why API Anomaly Detectors Fail Outside Their Training Generator

Preference: (1) for a conference — it states the finding and is memorable. (2) is the safe
alternative if the venue dislikes colon-headline framing.

---

## The claim chain

Each link is measured, not argued.

**C1 — The gap exists.**
The same model, gateway, and threshold: F1 0.957 (95% CI [0.940, 0.976]) and FPR 0.0069 on
session-grouped held-out data from its own generator; **44.49% false positives** on
legitimate traffic from an independently written client. A 64× gap in false-positive rate.

**C2 — The mechanism is shape memorisation, not overfitting in the usual sense.**
The detector learns each endpoint's *call convention*. Measured on the shipped model:

| Request | Query params | Score (threshold 0.25) |
| --- | ---: | ---: |
| `GET /api/products` | 0 | **0.9948** |
| `GET /api/products?page=2&limit=20` | 2 | 0.0003 |
| `GET /api/comments` | 0 | **0.9979** |
| `GET /api/comments?page=1&limit=20` | 2 | 0.0002 |

Omitting an optional parameter scores higher than most real attacks. The feature set
deliberately excludes endpoint identity; the shortcut reappeared through `q_param_count`,
`q_total_len` and `q_special_ratio`.

**C3 — Intervention confirms causation.**
Changing only the *generator's* shape coverage, with no change to the model, features,
architecture or hyperparameters:

| | FPR | Precision | F1 | ROC-AUC | AE saturation |
| --- | ---: | ---: | ---: | ---: | ---: |
| Narrow generator | 44.49% | 0.287 | 0.4461 | 0.7320 | 32.9% |
| Widened generator | **13.58%** | **0.537** | **0.6667** | **0.8358** | **11.8%** |

**C4 — Precision and recall were not independent.**
The narrow model's apparent 100% recall was a blanket endpoint flag — the same phenomenon
producing its 44% FPR. Removing the blanket removed both. Reported per family, six of seven
families survive at 100% under the widened model; the detections that vanished were never
discriminative. **This is the result most likely to be mis-read as a regression, and it needs
its own paragraph.**

**C5 — An expressivity limit, separate from the data problem.**
Three families are undetectable by shape features at any threshold. Candidate features
computed on the same corpus separate each perfectly:

| Family | Best candidate | AUC | 99th pct on 508 benign |
| --- | --- | ---: | ---: |
| mass assignment | `body_unknown_field_ratio` | 1.000 | 0.0000 |
| NoSQL injection | `body_nonscalar_ratio` | 1.000 | 0.0000 |
| enumeration | `max_numeric_magnitude` | 1.000 | 6.22 |

The sharpest single datum in the paper: a NoSQL injection against `/api/users/login` scores
**0.436** while a genuine login scores **0.936**. The attack looks *more normal than real
traffic*. No threshold can separate them because they are ordered the wrong way.

**C6 — A protocol other people can reuse.**
The independent-validation-client method: a second traffic client written from the API
contract, sharing no code, no word list and no payload builder with the training generator.
Disjoint identity pools, different pagination conventions, different body-field subsets.
Verified by assertion, not by intention.

---

## Secondary finding worth a subsection

**Silent feature death.** `n_flags` was logged as constant zero on every event for the
lifetime of the project, because `detector.inspect()` copies the event dict before setting
it while the logger reads the original. The model scored with the true value and trained on
zeros. One feature of 34 was dead and no metric revealed it — in-distribution accuracy was
unaffected because the feature was constant on *both* sides of the split.

This is a concrete, citable instance of a general hazard: train/serve skew that
in-distribution evaluation is structurally incapable of detecting. It also motivates the
zero-variance guard as a first-class control rather than a warning.

---

## Section structure (6 pages)

| § | Content | Pages |
| --- | --- | --- |
| I | Introduction — the gap, stated numerically in the first paragraph | 0.75 |
| II | Related work — trimmed; keep the evaluation-protocol critique, cut system comparisons | 0.75 |
| III | System under measurement — the four layers, compressed from the current §III–IV | 1.0 |
| IV | **Evaluation protocol** — session grouping, FPR budget, withheld families, *and* the independent client | 1.0 |
| V | **Results** — C1–C5, five tables, one figure | 1.75 |
| VI | Threats to validity — honest and specific | 0.4 |
| VII | Conclusion | 0.35 |

Cuts needed from the current 1,154-line source: the deployment-topology detail, several
TikZ figures, most of the per-layer hyperparameter narrative, and the 116× short-circuit
latency argument (keep one sentence — it is a nice result but no longer the point).

---

## Figures

1. **The gap.** Grouped bars: in-distribution vs cross-generator, FPR and F1. One figure,
   makes the paper's case at a glance.
2. **Per-endpoint false positives**, narrow vs widened. Shows the failure is per-endpoint and
   that an aggregate hides it.
3. **Score inversion.** Benign vs attack score distributions on `/api/users/login`, showing
   the attack sitting *below* legitimate traffic.

pgfplots, inline, consistent with the existing manuscript's self-contained approach.

---

## Evidence status

| Needed | Status |
| --- | --- |
| In-distribution CIs, narrow model | have — `models/validation.json`, 10 seeds |
| Cross-generator FPR, narrow model | have — 44.49%, n=508 benign |
| Cross-generator FPR, widened model | have — 13.58%, same traffic |
| Per-endpoint breakdown, both | have |
| Per-family recall, four model generations | have |
| Candidate-feature AUC matrix | have |
| Threshold sweeps | have |
| Latency p50/p95/p99 | have |
| **In-distribution CIs, widened model** | **running** — `validate.py --seeds 10` |
| **CI on the cross-generator gap itself** | **missing** — needs repeated independent-client runs with different seeds |
| McNemar, widened model | missing — `compare.py` |

The gap CI is the one that matters most. A single 44.49% is an anecdote; the claim needs a
spread across independent client seeds. Plan: five runs at different seeds, report
mean ± CI.

---

## Threats to validity — to be written honestly

- **Both traffic sources are synthetic.** The independent client is a *substitute* for
  production traffic, not production traffic. The gap it measures is a lower bound on what a
  real client population would produce, and should be described that way.
- **One backend.** The API contract is a single mock microservice. The claim generalises to
  the protocol, not yet to arbitrary APIs.
- **n = 91** attacks survive Layer 1 in the independent corpus. Adequate for family-level
  direction, thin for per-family CIs.
- **Re-scoring sets the rate input to zero.** Replayed rows have no live Redis counters,
  making re-scored numbers slightly conservative on rate-driven attacks.
- The candidate-feature result is measured on one corpus and has not survived a retrain.

---

## Order of work

1. Finish the missing evidence (validation CIs, gap CI, McNemar).
2. Rewrite abstract and introduction around C1.
3. Restructure III–V; cut to fit.
4. Draw the three figures.
5. Update `refs.bib` — the reframe needs evaluation-methodology and dataset-bias citations
   the current 19 do not cover.
6. Re-run `check_originality.py`.
7. Hand over `.tex` + `.bib` for Overleaf.
