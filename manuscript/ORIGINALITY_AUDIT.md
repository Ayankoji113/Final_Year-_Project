# Originality Audit — `microapi_guard.tex`

Generated 2026-09-01. Re-run the check after any edit to the manuscript.

## What was actually checked

**Method.** All 18 PDFs in `../Paper/` were extracted to plain text with
`pdftotext -layout` (2.6 MB of reference text, 227,424 unique 8-grams). The
manuscript was stripped of LaTeX markup, tables, and `\cite{}` commands,
normalised to lowercase alphanumerics, and every 6- and 8-word sliding window
was tested against the reference set.

**Result.**

| Window | Overlapping windows | Total windows | Rate |
|---|---|---|---|
| 8-gram | **0** | 3,437 | 0.000% |
| 6-gram | **1** | 3,439 | 0.029% |

The single 6-gram hit is `"the owasp api security top 10"` — the proper name
of a standard, cited as `\cite{owasp2023api}`. It cannot be reworded without
misnaming the standard. No action needed.

One phrase was reworded during the audit: `"scalability, explainability and
real-time applicability"` matched the Barata survey and has been rewritten,
even though it was already an attributed paraphrase.

Script: `scratchpad/shingle.py`. To re-run:
```bash
python <scratchpad>/shingle.py
```

## What this does NOT tell you

**This is not a Turnitin/iThenticate result and must not be presented as one.**
No tool in this environment produces a real similarity score. Specifically,
this check compares against **only the 18 papers in `Paper/`** — not against
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
| Pool sizes 4062/3117/2096/2106 | `models/decision.json` → `pool_sizes` | `cat` the file |
| Withheld families cmdi/exfil/ssti | `models/decision.json` → `novel_families` | `cat` the file |
| Threshold 0.275, 1% FPR budget | `models/decision.json`, `common/config.py` | `cat` |
| 10-seed CIs (Table III) | `models/validation.json` → `summary` | `cat` |
| Ablation + McNemar (Table IV) | `models/comparison.json` | `cat` |
| HGB 0.884 vs LR 0.744 | `models/tuning.json` → `results` | grouping script in session log |
| Latency table (Table V) | benchmark, this session | `scratchpad/bench2.py` |
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
   defaults. Table IV is therefore indicative of the *ranking*, not an exact
   reproduction of the deployed model. This is disclosed in the paper's
   Limitations section — do not remove that sentence.

## Self-review against common reviewer objections

- **"Zero-day recall CI is very wide [0.668, 0.914]."** Acknowledged in the
  Results section and again in the Conclusion. Individual seeds range 0.426 to
  1.000. Reporting the interval is deliberate.
- **"Synthetic traffic."** Stated as the first limitation, with the 13.6%
  cross-population false-positive rate given as concrete evidence against
  over-claiming.
- **"Table IV shows recall = 1.000."** Explicitly flagged in-text as a
  single-partition property, with the 10-seed figure named as the defensible
  one.
- **"No throughput measurement."** Stated as a limitation, with the ~185 req/s
  per core figure presented as arithmetic, not measurement.
- **"Novelty is limited — IF + AE + stacking are all known."** Addressed head
  on in Related Work §D: the paper claims the *combination* and the
  *protocol*, not the components.

## Citation integrity

- 22 entries in `references.bib`. **20 have a PDF in `Paper/`.** The two
  without are foundational method citations behind publisher paywalls:
  - `wolpert1992stacked` — Wolpert, *Stacked Generalization*, Neural Networks
    5(2), 1992. Elsevier, DOI `10.1016/S0893-6080(05)80023-1`.
  - `mcnemar1947note` — McNemar, Psychometrika 12(2), 1947. Springer,
    DOI `10.1007/BF02295996`.

  Both are cited only as the origin of a method (stacking; the paired
  significance test). Neither is quoted, and nothing in the paper depends on
  reading them. Get them through the college library (INFLIBNET N-LIST covers
  Springer and Elsevier for most Indian institutions) if a PDF per reference
  is required.
- `Isolation_Forest_Liu_ICDM2008.pdf` came from co-author Zhi-Hua Zhou's own
  university page; `OWASP_API_Security_Top10_2023.pdf` was rendered from the
  official OWASP 2023 edition page, which OWASP publishes as HTML rather than
  PDF.
- No uncited entries and no citation to a work not in the bibliography.
- No direct quotations anywhere in the manuscript — all source material is
  paraphrased and attributed.
