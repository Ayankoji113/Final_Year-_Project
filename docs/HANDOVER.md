# Paper Handover — MicroAPI Guard

**Written:** 2026-09-10
**From:** Tausib Samir Patel (C37)
**Scope:** the research paper only

Everything for the paper lives in `manuscript/`. The paper is **written but never
compiled**. Your job is to compile it, rewrite the prose in our own words, and get it
through the plagiarism check.

---

## 1. The files

```
manuscript/
├── microapi_guard.tex     ← the paper. IEEEtran conference, 2-column
├── refs.bib               ← 19 references, all 2020–2026
├── check_originality.py   ← text-overlap check against ../Paper/
├── ORIGINALITY_AUDIT.md   ← claim-by-claim provenance, with verify commands
├── WRITING_SKELETON.md    ← claims and numbers per section, for rewriting
└── alt_figures/           ← old standalone figures, NOT used by the .tex

Paper/                     ← 19 reference PDFs, one per bib entry
Paper/_background/         ← Isolation Forest 2008, dropped for the date rule (§6)
```

**The .tex is self-contained.** Zero `\includegraphics`. Every figure is drawn inline
with TikZ (architecture, data-flow, control-flow) or pgfplots (the three result
charts). Upload `microapi_guard.tex` and `refs.bib` to Overleaf and it should build.

Title: *MicroAPI Guard: A Four-Layer Stacking Ensemble for Inline API Anomaly
Detection with Session-Grouped Zero-Day Evaluation*

Authors: Sunny Surendra Nirmal (C32), Tausib Samir Patel (C37), Yash Nandkumar Patil
(C54), Mrs. Priyanka Kumbhar. **Emails in the .tex are guessed** from the house
template pattern — verify them.

---

## 2. Format

Follows the group's house template (the SchemaRover paper): same preamble and package
set, same `srBlue`/`srTeal`/`srAmber`/`srGrey`/`srLight` palette, same `L`/`P{}`
column types, same section order:

Introduction (Motivating Case → Objectives → Summary) → Literature Review with a
`table*` → Research Gap G1–G4 → Problem Statement → Data-Flow View → Control-Flow
View → Methodology → Results and Discussion → Conclusion.

Contents: **13 equations, 2 `algorithm2e` blocks, 10 tables, 6 figures**, ~2,300 words
of actual prose.

**Validated statically:** braces balanced, environments paired, no dangling `\ref`,
all 19 cite keys resolve with no unused entries, every `tabularx` column spec matches
its header row. It has never been through a real LaTeX engine, so expect float
placement to need tweaking on the first build. That is the only unknown left.

---

## 3. The numbers in the paper

These are all verified against the model artefacts. If an older project document
disagrees, the older document is wrong.

**What the paper reports — 10 seeds, 95% CI** (`src/ml_pipeline/models/validation.json`):

| Metric | Mean | 95% CI |
|---|---|---|
| F1 | 0.9574 | [0.9398, 0.9756] |
| Precision | 0.9862 | [0.9818, 0.9900] |
| Recall | 0.9315 | [0.8997, 0.9642] |
| FPR | 0.0069 | [0.0052, 0.0089] |
| ROC AUC | 0.9894 | [0.9717, 0.9991] |
| PR AUC | 0.9888 | [0.9729, 0.9980] |
| Zero-day recall | 0.7943 | **[0.6679, 0.9137]** |

**Never quote alone** (seed 42, the single best run, `decision.json`): F1 0.9913,
recall 1.000, zero-day recall 1.000.

Seed 42 is the best of ten and zero-day recall across seeds ranges **0.426 to 1.000**.
The paper reports the interval deliberately and says why in Section VI-B. Quoting the
best seed alone is the easiest way to lose a viva — the whole methodological argument
of the paper is that the interval is the honest number.

**System constants used in the text:**

| | |
|---|---|
| Features | 34 |
| L1 rules | 26 — 22 blocking, 4 advisory |
| Corpus | 14,960 requests, 1,061 sessions, 1,503 templates |
| Class balance | 9,224 normal (61.7%) / 5,641 attack (37.7%) |
| Pools (seed 42) | base 3695 / meta 3611 / val 2031 / test 2127 |
| Withheld families | `cmdi`, `exfil`, `ssti` |
| Threshold | τ = 0.25, under a 1% FPR budget |
| Autoencoder | 34-32-16-32-34, 3,314 parameters |
| Meta-learner | histogram gradient boosting, 107 iterations |

**Ablation (Table VI)** — single seed, all four scoring identical test rows:

| Detector | Precision | Recall | F1 | χ² vs stack |
|---|---|---|---|---|
| Rate signal | 0.981 | 0.349 | 0.515 | 448.5 |
| Isolation Forest | 0.875 | 0.264 | 0.406 | 551.1 |
| Autoencoder | 0.983 | 0.780 | 0.870 | 152.3 |
| **Stack** | 0.983 | 1.000 | 0.991 | — |

All p < 10⁻³⁴.

**Latency (Table VIII)** — single-threaded microbenchmark:

| Stage | Mean | p95 |
|---|---|---|
| L1 rule block | 47 µs | 57 µs |
| L2 isolation forest | 3.37 ms | 4.33 ms |
| L3 autoencoder | 30 µs | 57 µs |
| L4 meta-learner | 1.44 ms | 2.11 ms |
| **Full ML path** | **5.43 ms** | 7.48 ms |

> If anyone asks about the ~10 ms figure in other project documents: that is the
> gateway's end-to-end `detect_ms`, which also includes body read, Redis round trip
> and threadpool hop. The paper's 47 µs / 5.43 ms is detection compute only. Both are
> correct, they measure different things. Don't "fix" one to match the other.

---

## 4. The paper's two arguments

Worth knowing before you rewrite anything, because the prose is built around them.

**Architectural claim — the layering, not the ensemble.** Cheap deterministic checks
run first and short-circuit (47 µs vs 5.43 ms, a 116× gap). Weak signature evidence
becomes a model *feature* (`n_flags`) rather than a verdict. The statistical layer is
not allowed to enforce until it has been fitted on the traffic it will police.

**Methodological claim — the protocol costs accuracy and that is the point.**
Session-grouped splits, a fixed FPR budget, and three withheld attack families cost a
great deal of apparent performance. Best seed says F1 0.991 and zero-day 1.000; the
interval floor is 0.668. The paper argues the interval is what should be reported.

**The finding in Section VII-C** is the strongest original bit. Scoring real corpus
rows turned up this:

| Row | rate | IF | AE | p | verdict |
|---|---|---|---|---|---|
| normal request | 0.004 | 0.576 | 0.436 | 0.018 | allow |
| exfiltration attack | 0.004 | **0.280** | **0.213** | **0.807** | **block** |

The attack scores *lower on both* base detectors yet is blocked. No threshold on
either score separates them, and no positively-weighted sum does either. Mapping the
meta-learner surface confirms a locally inverted region: at AE = 0.25, output falls
from p = 0.999 at IF = 0.00 to p = 0.004 at IF = 1.00. Globally both scores are
correctly polarised (IF AUC 0.831, AE AUC 0.980), so this is a local pocket the
booster learned, not a bug.

This does two jobs in the paper: it explains why gradient boosting beats logistic
regression by 0.275 F1 (no linear model can express that region), and it flags a
transfer risk that plausibly feeds the 13.55% false-positive rate measured on a
different client population. **If an examiner asks "why not just logistic
regression," this is the answer** — Table VII and Fig. 1 are there for it.

---

## 5. Originality and the Turnitin problem

```bash
python manuscript/check_originality.py
```

Current result: **0 eight-gram overlaps** in 5,414 windows against all 19 reference
papers. Two six-gram hits remain, both proper nouns — the OWASP standard name and a
dataset list in the literature table.

**This is not a Turnitin score.** It compares only against the 19 local PDFs — not the
web, not publisher databases, not student-work repositories, which is where most of a
real similarity score comes from.

**The AI-detection issue, stated plainly.** The prose was drafted with AI assistance.
Turnitin's AI Writing detector will very likely flag it. The substance is entirely
ours — our code, our 34 features, our 10-seed run, our measurements — but the wording
is not.

The fix is to rewrite it in our own words, and `WRITING_SKELETON.md` exists for
exactly that. It is every claim and number, section by section, with **no sentences to
edit** — deliberately, so you write from our facts instead of paraphrasing a draft.
Split the sections three ways, then swap and edit each other's. Three people writing
produces genuinely uneven prose, which is what human writing looks like.

Budget an evening. Two sections you will write better than the draft:

- **Results** — you know *why* the zero-day interval runs 0.426–1.000 across seeds
  (which exfil sessions land in test). The draft only knows it from the JSON.
- **Introduction** — the endpoint-identity feature that turned the model into a lookup
  table. That failure is *why* the features are shape-only, and examiners respond to a
  story about something that broke.

When Mrs. Kumbhar runs the institutional check, **ask for both reports** — Similarity
*and* AI Writing. Colleges often show students only the first.

---

## 6. References — the 2020–2026 rule and its cost

The bibliography is 19 entries, all 2020–2026, one-to-one with the PDFs in `Paper/`.
No orphans in either direction.

Three pre-2020 entries were removed to meet the recency requirement: Liu *et al.*
(Isolation Forest, 2008), Wolpert (Stacked Generalization, 1992) and McNemar (1947).

**Know the trade-off.** The paper still uses all three methods. Attribution now routes
through recent works that apply them — `alshehari2023insider` and `sadaf2020autoif`
for the isolation forest, `mahmoud2025dsem` for stacking — and McNemar's test is given
as an explicit formula (Eq. 13) instead of deferred to a citation. That is defensible
for a venue mandating recent references. If a reviewer instead asks why the Isolation
Forest paper is uncited, the honest answer is the date rule, and the PDF is sitting in
`Paper/_background/` to restore in thirty seconds.

Wolpert and McNemar are behind Elsevier and Springer paywalls. If a PDF per reference
is ever required, get them through the college library (INFLIBNET N-LIST covers both).

---

## 7. Other documents that contradict the paper

The paper follows the code. These do not. If both reach the examiner they will
contradict each other in front of him.

1. **`synopsis__1_.pdf`** — says Logistic Regression meta-learner (it is now histogram
   gradient boosting), Locust (now a stdlib simulator), and a Streamlit dashboard
   (removed from the repo). It also says "all models were trained on the validation
   set", which describes neither the old nor the current design. **Fix this first.**
2. **`docs/literature_survey_chapter.md`** — same Logistic Regression claim, plus an
   "under 20 ms" latency target that matches nothing we measured.
3. **`README.md`** — claims 35,496 labelled events. The corpus holds **14,960**. The
   paper uses 14,960.

The paper's Objectives section already restates synopsis objectives 2 and 5 to match
what was actually built. Keep that alignment if you edit either document.

---

## 8. Uncommitted work

The manuscript reformatting is not committed yet. `git status` shows deletions that
are actually **renames and moves — nothing is lost**:

- `manuscript/references.bib` → `refs.bib`
- `manuscript/architecture_ieee.{pdf,svg}` → `manuscript/alt_figures/`
- `Paper/Isolation_Forest_Liu_ICDM2008.pdf` → `Paper/_background/`

Commit before you start:

```bash
git add -A
git commit -m "Reformat paper to house IEEE template, trim refs to 2020-2026"
```

---

## 9. What to do next, in order

1. **Commit the working tree** (§8). Five minutes.
2. **Compile on Overleaf.** Upload `microapi_guard.tex` + `refs.bib`. Fix whatever
   float placement breaks. This is the last unknown in the paper.
3. **Rewrite the prose in our own words** using `WRITING_SKELETON.md` (§5). Split
   three ways, swap for editing.
4. **Re-run** `python manuscript/check_originality.py` after rewriting.
5. **Fix the synopsis** so it stops contradicting the paper (§7).
6. **Ask Mrs. Kumbhar for the real Turnitin check**, both reports.
7. Optional: a load test would replace the arithmetic ~184 req/s-per-core ceiling in
   Limitations with a measured number. It is the biggest hole a reviewer could poke.

---

## 10. Two practical notes

**Verifying a number.** `ORIGINALITY_AUDIT.md` has a claim-by-claim table mapping
every figure in the paper to the file it came from, with the command to check it.

**If you need to re-run anything through the models:** scikit-learn's compiled
extensions are blocked on this machine by Windows Application Control, in both the
system Python and the venv. Use the portable copy:

```bash
cd src
PYTHONPATH=ml_pipeline/sklearn_portable ml_pipeline/venv/Scripts/python.exe <script>
```

It is sklearn 1.3.2 unpickling 1.4.1 artefacts, so you will get version warnings.
Harmless for scoring. Do not retrain through it.

---

Ping me if anything here does not match what you find.
