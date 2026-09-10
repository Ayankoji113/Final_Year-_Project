# Originality Audit — `microapi_guard.tex`

Last updated 2026-09-05, after the revision that added equations, algorithms
and the results figure. Re-run the check after any edit to the manuscript.

## What was actually checked

**Method.** All 19 cited PDFs in `../Paper/` were extracted to plain text with
`pdftotext -layout`. The manuscript was stripped of LaTeX markup, tables, and
`\cite{}` commands, normalised to lowercase alphanumerics, and every 6- and
8-word sliding window was tested against the reference set.

**Result.**

| Window | Overlapping windows | Total windows | Rate |
|---|---|---|---|
| 8-gram | **0** | 2,315 | 0.000% |
| 6-gram | **1** | 2,317 | 0.043% |

Prose fell from 3,444 to 2,322 words in the revision; the removed theory was
replaced by 13 numbered equations, 2 algorithm blocks, 7 tables and a
three-panel results figure.

The single 6-gram hit is `"the owasp api security top 10"` — the proper name
of a standard, cited as `\cite{owasp2023api}`. It cannot be reworded without
misnaming the standard. No action needed.

One phrase was reworded during the audit: `"scalability, explainability and
real-time applicability"` matched the Barata survey and has been rewritten,
even though it was already an attributed paraphrase.

To re-run:
```bash
python manuscript/check_originality.py     # exit 1 if any 8-gram matches
```

## What this does NOT tell you

**This is not a Turnitin/iThenticate result and must not be presented as one.**
No tool in this environment produces a real similarity score. Specifically,
this check compares against **only the 19 papers in `Paper/`** — not against
the web, not against published-paper databases, not against student-work
repositories, which is where the bulk of a Turnitin score comes from.

Run the manuscript through your institution's actual plagiarism system before
submission. This audit is evidence that the prose was written from scratch, not
a substitute for that check.

## Claim-by-claim provenance

Every number in the paper traces to a file in this repository. Verify with the
commands listed.

| Claim in paper | Source | Verify |
|---|---|---|
| 34 features, names and grouping | `src/common/features.py` | `python -c "from common import features; print(len(features.FEATURE_NAMES))"` |
| 26 rules, 22 block / 4 flag | `src/common/rules.py` | `python -c "from common import rules; print(len(rules.RULES))"` |
| Corpus: 14,960 requests, 1,061 sessions, 1,503 templates | `src/data/events_training.jsonl` | recount script in session log |
| Family breakdown (Table II) | same | same |
| Pool sizes 3695/3611/2031/2127 (seed 42) | `models/decision.json` → `pool_sizes` | `cat` the file |
| Withheld families cmdi/exfil/ssti | `models/decision.json` → `novel_families` | `cat` the file |
| Threshold 0.25, 1% FPR budget | `models/decision.json`, `common/config.py` | `cat` |
| 10-seed CIs (Tables IV, V) | `models/validation.json` → `summary` | `cat` |
| Ablation + McNemar (Table VI) | `models/comparison.json` | `cat` |
| HGB 0.884 vs LR 0.744 | `models/tuning.json` → `results` | grouping script in session log |
| Latency + complexity (Table III) | benchmark, this session | `scratchpad/bench2.py` |
| 13.6% FPR on different population | `src/common/config.py` comment, `docker-compose.yml` | `grep -n "13.55" src/` |
| Architecture Fig. 1 | `diagrams/architecture_ieee.svg` | — |

## Discrepancies found while writing — resolve before submitting

These are places where existing project documents disagree with the code. The
paper follows the **code**; the other documents are stale.

1. **`synopsis__1_.pdf` is out of date.** It describes a logistic-regression
   meta-learner (now histogram gradient boosting), Locust (now a stdlib
   simulator), and a Streamlit dashboard (removed from the repo this session).
   It also says "all models were trained on the validation set", which
   describes neither the old nor the current design. If the synopsis is being
   submitted alongside the paper, it needs updating or the two will contradict
   each other in front of the examiner.

2. **`docs/literature_survey_chapter.md` is out of date** in the same way —
   it claims a Logistic Regression meta-learner and a "under 20ms" latency
   target.

3. **`README.md` claims 35,496 labelled events.** The actual training corpus
   (`events_training.jsonl`) holds **14,960**. The paper uses 14,960. Find out
   where 35,496 came from before anyone asks.

4. **`compare.py` is not fully synchronised with `train.py`.** It rebuilds the
   models independently so that every detector scores identical test rows
   (McNemar requires paired predictions), but it does not read the
   hyperparameter environment variables and constructs the autoencoder with
   defaults. Table VI is therefore indicative of the *ranking*, not an exact
   reproduction of the deployed model. This is disclosed in the paper's
   Limitations section — do not remove that sentence.

## Self-review against common reviewer objections

- **"Zero-day recall CI is very wide [0.668, 0.914]."** Acknowledged in the
  Results section and again in the Conclusion. Individual seeds range 0.426 to
  1.000. Reporting the interval is deliberate.
- **"Synthetic traffic."** Stated as the first limitation, with the 13.6%
  cross-population false-positive rate given as concrete evidence against
  over-claiming.
- **"Table VI shows recall = 1.000."** Explicitly flagged in-text as a
  single-partition property, with the 10-seed figure named as the defensible
  one.
- **"No throughput measurement."** Stated as a limitation, with the ~185 req/s
  per core figure presented as arithmetic, not measurement.
- **"Novelty is limited — IF + AE + stacking are all known."** Addressed head
  on in Related Work: the paper claims the *combination* and the
  *protocol*, not the components.

## Citation integrity

- **19 entries in `references.bib`, all published 2020–2026, and every one has
  a PDF in `Paper/`.** One-to-one, no orphans in either direction.
- Three pre-2020 entries were removed to meet the recency requirement:
  Liu *et al.* (Isolation Forest, 2008), Wolpert (Stacked Generalization,
  1992) and McNemar (1947). Each was a method-origin citation only.

  **Know the trade-off before defending this.** The paper still uses all three
  methods, so their attribution now rests on recent works that apply them —
  `alshehari2023insider` and `sadaf2020autoif` for the isolation forest,
  `mahmoud2025dsem` for stacking — and on the fact that McNemar's test is
  stated as an explicit formula, Eq. (13), rather than deferred to a citation.
  This is defensible for a venue that mandates recent references. If a
  reviewer instead asks why the Isolation Forest paper is uncited, the honest
  answer is the recency constraint, and the fix is to restore that one entry.
  Its PDF is kept at `Paper/_background/` for exactly that reason.
- `OWASP_API_Security_Top10_2023.pdf` was rendered from the official OWASP
  2023 edition page, which OWASP publishes as HTML rather than PDF.
- No uncited entries and no citation to a work not in the bibliography.
- No direct quotations anywhere in the manuscript — all source material is
  paraphrased and attributed.
