# Writing Skeleton — write the paper in your own words

This is the paper reduced to **claims and numbers only**. No sentences to
edit — deliberately. Read a block, look away, and write what it says the way
you'd explain it to a classmate who knows Python but not your project.

Every number is verified against a file in this repo. The `->` line tells you
where it came from, so you can check anything you're unsure of before you
commit it to prose.

Target: ~3,400 words of prose across 8 sections. Split the sections between
the three of you, then swap and edit each other's — mixed authorship reads
as human because it *is*.

---

## Title / Abstract  (~200 words, write LAST)

Write this after everything else. It is the introduction, method, results and
limitation in five sentences.

Must contain:
- What it is: an API gateway that blocks hostile requests inline
- Four layers: signature rules + rate limiting -> Isolation Forest ->
  autoencoder -> gradient-boosted meta-learner
- The cheap-path claim: L1 short-circuits, 47 us vs 5.4 ms
- Headline result: F1 **0.957** [0.940, 0.976], FPR **0.0069**
- Zero-day: **0.794** [0.668, 0.914] on 3 withheld families
- The honesty point: you report the interval, not your best seed

---

## I. Introduction  (~450 words)

**The problem**
- Microservices = many HTTP endpoints = large attack surface
- One unmonitored endpoint is enough (T-Mobile, Optus, Peloton — cite
  `levi2026mrg`)

**Why existing options don't fit** — this is the paper's whole reason to exist
- Signature WAFs: fast, deterministic, explain themselves, but blind to
  anything without a rule
- Recent ML detectors: accurate, but need GNNs / LLMs / trace pipelines / GPUs
- Second group has another problem: they read telemetry *after* the fact, so
  they can't block anything

**Your five contributions** — say these plainly, don't dress them up
1. Layered design where cost tracks certainty (47 us cheap path, 5.4 ms full)
2. Base detectors trained only on normal traffic -> meta-features are
   out-of-sample for free, no k-fold stacking needed
3. Evaluation protocol built against leakage (session splits, FPR budget,
   test read once, withheld families)
4. Portability by calibration, not retraining
5. Interval reporting instead of best-seed reporting

> Your own angle, if you want one: you tried the obvious thing first (feeding
> endpoint identity as a feature) and it turned into a lookup table. That
> failure is *why* the features are shape-only. Examiners like this.

---

## II. Related Work  (~600 words)

Four short subsections. One or two sentences per paper — do not summarise
them, *position* them.

**A. Microservice anomaly detection (they measure health, not hostility)**
- `barata2026survey` — survey, 117 studies 2012–2025
- `jin2020rpca` — RPCA over invocation chains
- `liu2024lmgd` — LMGD, logs+metrics on a dependency graph
- `zhang2026admm` — ADmM, handles missing metrics
- `liu2020traceanomaly` — deep Bayesian nets over traces
- `kohyarnejadfard2022nlp` — NLP on traces
- `raeiszadeh2025artfl` — federated
- `pedroso2025llm` — LLM + Bayesian nets
- `moens2026kg` — knowledge graphs
- `faseeha2025observability` — observability tooling has its own overhead
- **Your one-line verdict:** better than yours at what they do, but all
  off the request path — none can block

**B. Detection at the gateway (the actual neighbours)**
- `sowmya2023api` — ML on HTTP features, closest antecedent to your features
- `huang2026gateway` — Envoy + Flink, 98.5% recall on DDoS/traversal, but
  data plane and analytics plane are separate = near-real-time, not inline
- `levi2026mrg` — learns API structure, autoencoder on payloads
- `markande2026saas` — behavioural analytics behind a MITM proxy

**C. Your components are all known — say so**
- `liu2008iforest` — Isolation Forest
- `alshehari2023insider` — IF under class imbalance
- `sadaf2020autoif` — **AE + IF together, 95.4% on NSL-KDD.** Your direct basis
- `wolpert1992stacked` — stacked generalisation
- `mahmoud2025dsem` — DSEM-NIDS, deep stacking for NIDS
- `alam2025adaptive` — withholds attack classes to measure zero-day. **You
  copied this methodology — say that explicitly, it's a strength**

**D. Positioning**
- You claim no novel detector. You claim: the combination + the protocol
- Table I already exists in the .tex — keep it

---

## III. System Architecture  (~700 words)  — Fig. 1 goes here

**Deployment shape**
- Reverse proxy, only published port; backend + Redis internal-only
- -> `src/docker-compose.yml`

**Preprocessing**
- client ID, path template (`/orders/8813` -> `/orders/{id}`)
- body cap 1 MiB, inspect first 64 KiB (bounds attacker-forced work)
- -> `src/common/config.py`, `src/common/normalize.py`

**Layer 1**
- **26 rules, 22 blocking, 4 advisory** — sqli, xss, traversal, cmdi, scan,
  ssti, deser, ssrf
- Redis: 60 s window, 5 s burst, HyperLogLog for endpoint spread, 11 commands
  in one pipeline
- **Two points that matter:**
  - blocking hit returns immediately, models never run -> the 47 us
  - the 4 advisory rules do NOT decide; their count becomes `n_flags`, so weak
    signature evidence *informs* the model instead of overriding it
- -> `src/common/rules.py`, `src/gateway/ratelimit.py`

**Features — 34, shape not identity**
- Groups: body 7, content 2, path 11, query 5, behaviour 1, method 7, flags 1
- The rule: raw path never reaches a model; template only keys baselines
- Feature contract checked at load — mismatch = gateway won't start
- -> `src/common/features.py`, `src/gateway/detector.py:load()`

**Layers 2–4**
- L2: Isolation Forest, 300 trees
- L3: autoencoder 34→32→16→32→34, **plain NumPy** (drops a ~2 GB torch
  dependency; 30 us inference)
- Both min-max normalised to [0,1]; third input = window count / limit
- L4: HistGradientBoosting over the three scores. **Only layer that decides**
- Base detectors fit on `base` (normal only), meta fit on disjoint `meta`
  -> out-of-sample by construction
- -> `src/ml_pipeline/train.py`, `src/common/autoencoder.py`

**Graded enforcement**
- `monitor` / `enforce-l1` (default) / `enforce`
- Justify with the measurement: **13.6% FPR** on a different client
  population even after calibration
- -> `src/common/config.py` comments

**Calibration**
- Re-derives baseline + threshold. Updates **no weights**
- Why: catastrophic forgetting, and online updates are a poisoning surface
- Refuses when: window too small, >2% trips a block rule, median already
  scores anomalous
- -> `src/ml_pipeline/calibrate.py`

---

## IV. Evaluation Protocol  (~500 words)

State it **before** results. Each constraint lowers your numbers; that's the point.

**Corpus**
- **14,960** labelled requests, **1,061** sessions, **1,503** templates
- 9,224 normal (61.7%) / 5,641 attack (37.7%)
- Families: flood 1981, exfil 1669, bruteforce 1419, scan 314, sqli 80,
  xss 61, traversal 48, cmdi 37, payload 19, ssti 13
- Labels exist only via a lab-only header flag = a poisoning channel, off in
  production
- -> `src/data/events_training.jsonl`
- **NOTE: README.md says 35,496. That is wrong. Use 14,960.**

**Session-grouped splits**
- Hash the client, never the row. Row-level splits let near-identical requests
  from one session straddle the boundary
- Pools: 4062 / 3117 / 2096 / 2106
- -> `decision.json` -> `pool_sizes`

**Withheld families**
- cmdi, exfil, ssti appear **only in test**
- This is what makes zero-day recall a measurement, not a restatement
- Methodology from `alam2025adaptive`

**Threshold + test discipline**
- tau chosen on `val` under a 1% FPR budget; **every baseline gets the same
  budget** or the comparison rewards whoever was loosest
- test read once, at the end

**L1 accounting**
- L1-blocked rows excluded from model stages, re-attached for end-to-end
- Otherwise the ensemble gets credit for the rule engine's work

---

## V. Results  (~600 words)

**Table III — 10 seeds, mean [95% CI]**  -> `validation.json` -> `summary`

| | mean | CI |
|---|---|---|
| F1 | 0.957 | [0.940, 0.976] |
| Precision | 0.986 | [0.982, 0.990] |
| Recall | 0.931 | [0.900, 0.964] |
| FPR | 0.0069 | [0.0052, 0.0089] |
| ROC AUC | 0.989 | [0.972, 0.999] |
| PR AUC | 0.989 | [0.973, 0.998] |
| Zero-day | 0.794 | [0.668, 0.914] |

**The paragraph that matters most in the paper:**
- Precision high and stable; recall lower and more variable
- Zero-day interval is the widest; per-seed range **0.426 to 1.000**
- Single-seed reporting would have let you claim 1.000 — real, reproducible,
  and misleading. Say that in your own words. It's the most defensible
  sentence you'll write.

**Table IV — ablation, single seed**  -> `comparison.json`

| detector | F1 | recall |
|---|---|---|
| rate only | 0.515 | 0.349 |
| Isolation Forest | 0.406 | 0.264 |
| autoencoder | 0.870 | 0.780 |
| **stack** | **0.991** | **1.000** |

- Interesting bit: **IF alone is weak (26% recall) but still adds to the
  stack** — it and the rate signal carry information the AE lacks
- McNemar vs rate n01=488/n10=13; vs IF 565/4; vs AE 163/3; all p < 1e-34
- **Two caveats you must keep:** single seed; and recall 1.000 is a property
  of this partition, not a claim

**Meta-learner choice**  -> `tuning.json`
- HGB 0.884 (val F1 0.943) vs LR 0.744 (val F1 0.668)
- Searched on seeds 11–15, reported on 1–10; rotated pseudo-novel families so
  the real withheld families never informed a hyperparameter

**Table V — latency**
- L1 block 47 us | IF 3.37 ms | AE 30 us | meta 1.44 ms | **full 5.43 ms**
- Note the inversions: the AE is the best detector *and* the cheapest; the IF
  is the weakest *and* 62% of the cost
- HGB costs 1.44 ms vs 46 us for LR — a 30x penalty you accepted knowingly

---

## VI. Limitations  (~350 words) — do not soften these

- **Synthetic corpus.** The 13.6% cross-population FPR is your own evidence
  that generalisation is unproven
- **No throughput measurement.** 185 req/s per core is arithmetic from 5.4 ms,
  not a load test. Say "we have not measured this"
- **One deployment.** Portability is a design property, not a result
- **compare.py is not fully in sync with train.py** — rebuilds models
  independently to get paired predictions, doesn't inherit all hyperparameters.
  Ranking robust, magnitudes indicative
- **No adaptive adversary.** Character-ratio and encoding-delta features are
  plausibly evadable

---

## VII. Conclusion  (~250 words)

- Restate the result once, with intervals
- **The claim you'd actually defend:** not the ensemble — the layering.
  Cheap check first; weak evidence informs rather than overrides; the
  statistical layer doesn't enforce until fitted on the traffic it polices
- **The methodological claim:** the protocol cost you a lot of apparent
  accuracy (1.000 best seed vs 0.668 interval floor) and the interval is the
  number worth reporting
- Future work: public/production corpora, load testing, sampling for
  high throughput, adaptive adversary

---

## Before you submit

- [ ] Fix `synopsis__1_.pdf` — still says logistic regression, Locust,
      Streamlit dashboard. Will contradict the paper in front of the examiner
- [ ] Fix `README.md` 35,496 -> 14,960
- [ ] Update `docs/literature_survey_chapter.md` (same LR / "under 20ms" issue)
- [ ] Run `python check_originality.py` after rewriting
- [ ] Ask Mrs. Kumbhar to run the real Turnitin check
