# MicroAPI Guard — Open House Study Guide

**For:** the open-house panel (4 faculty, 2 seniors, 3 industry people)
**Built from:** every source file in `src/`, the model artefacts, `README.md`, `HANDOVER.md`,
`docs/*`, `manuscript/`, the Review II deck and the reference list. Every number here can be
traced to a file in this repository. Section 19 lists where each one comes from.

---

## How to use this guide

| When | Read |
| --- | --- |
| **First pass (3–4 h)** | §1 pitch, §2 architecture, §3 story, §4 numbers card, §18 cheat sheet |
| **Second pass (a full day)** | §5–§10, one layer at a time, with the source file open next to it |
| **Day before** | §13 stale claims, §14 known gaps, §15 question bank, §16 demo |
| **Morning of** | §18 only |

Three habits that matter more than any single answer:

1. **Say which number you are quoting and what it was measured on.** This project has three
   generations of results. A faculty member holding the Review II deck and an industry person
   reading the README will quote different numbers at you. §3 and §4 explain why both exist.
2. **Give the limitation before they find it.** Your strongest material is the part where the
   project measured its own failure, worked out why, and fixed most of it. Presented well, this is
   what a panel remembers.
3. **"I don't know, but here is how I would find out"** is a good answer. A made-up answer is a bad
   one, and someone on a 10-person panel will usually notice.

---

## Table of contents

1. [The pitch: 30 seconds, 2 minutes, 5 minutes](#1-the-pitch)
2. [The system in one picture, and one request through it](#2-the-system-in-one-picture)
3. [The story: how the project evolved](#3-the-story)
4. [The numbers card: what to quote and what not to](#4-the-numbers-card)
5. [Layer 0: normalization](#5-layer-0--normalization)
6. [Layer 1: signature rules and rate limiting](#6-layer-1--signature-rules-and-rate-limiting)
7. [The 34 features, and the ones that were deleted](#7-the-34-features)
8. [Layers 2, 3 and 4: Isolation Forest, autoencoder, meta-learner](#8-layers-2-3-4--the-ml-stack)
9. [Training and evaluation methodology](#9-training-and-evaluation-methodology)
10. [The main finding: independent traffic](#10-the-main-finding--independent-traffic)
11. [Safe ML enforcement: canary, thresholds, brake](#11-safe-ml-enforcement)
12. [Deployment, security posture, console](#12-deployment-security-posture-console)
13. [Stale claims in older documents](#13-stale-claims-in-older-documents)
14. [Known gaps, including ones not in the docs](#14-known-gaps)
15. [Cross-question bank (143 questions)](#15-cross-question-bank)
16. [Live demo script and what can go wrong](#16-live-demo-script)
17. [Theory refreshers](#17-theory-refreshers)
18. [One-page cheat sheet](#18-one-page-cheat-sheet)
19. [Where every number comes from](#19-where-every-number-comes-from)

---

## 1. The pitch

### 30 seconds

> APIs are now the main way into most applications, and the usual defences sit at two
> extremes. Signature firewalls are fast but miss anything without a rule. ML research detectors
> catch more but need heavy infrastructure, and they read logs after the request has already
> landed. MicroAPI Guard is a reverse proxy that sits in front of any HTTP backend and inspects every
> request inline through four layers: deterministic rules and rate limits first, then two
> unsupervised models trained only on normal traffic, then a meta-learner that combines them.
> The rules layer blocks today with zero measured false positives. The ML layer is measured
> honestly against traffic from a second, independent client, and the gateway includes the
> machinery to switch ML blocking on safely, one endpoint at a time.

### 2 minutes (add these to the 30-second version)

- **Cost follows certainty.** A `UNION SELECT` gets blocked in about **47 µs** without running any model.
  Only requests that are neither obviously malicious nor obviously excessive go through the ML path
  (**~5.4 ms** of compute).
- **No endpoint identity in the features.** The 34 features describe the *shape* of a request
  (lengths, entropy, character ratios, parameter counts, method, breadth of endpoints touched),
  so the same model can sit in front of a different backend.
- **Honest evaluation.** Splits are by client session, the threshold is picked under a 1%
  false-positive budget, and three attack families are kept out of training so zero-day recall
  is a real measurement.
- **The finding.** On its own generator's test data the earlier model scored F1 0.957. On
  traffic from an independently written client it wrongly flagged **61%** of legitimate requests.
  We traced the cause (the model had learned how the generator calls each endpoint), changed only the
  training data, and cut that to **17%** with ROC-AUC 0.87. That is the result we stand behind.

### 5 minutes (add these)

- Walk through one request (§2).
- Show that one trick, encoding, is defeated by normalization (`%252e%252e%252f` still blocked).
- Explain why the ML layer *records* verdicts (`X-Guard-Would-Block`) instead of blocking by default.
- Show the console: Overview → Threat Investigation (per-detector scores) → System Health (brake).
- Close on what is still open: global FPR is 17% against a 1% goal, three attack types cannot be seen
  by shape features, and all traffic is synthetic.

### What is new about it (have this ready, it gets asked every time)

1. **A cascade where weak evidence turns into a feature.** BLOCK-severity rules short-circuit. FLAG-severity
   rules do not block; the count of them (`n_flags`) is fed to the model instead.
2. **Measuring against a second generator.** The project shows, with numbers, that evaluating on one
   traffic generator overstated performance: FPR 0.69% in-distribution vs 44–82% on independent traffic for
   the same model. It found the cause and confirmed it by intervention.
3. **Detection is kept separate from enforcement.** ML verdicts can be rolled out per endpoint, per
   client percentage, with an automatic brake. This is ordinary practice in production engineering
   but rare in student ML security projects.
4. **An expressivity analysis.** It shows that three attack families (mass assignment, NoSQL injection,
   enumeration) *cannot* be detected with shape features, and names the single feature that separates each.

---

## 2. The system in one picture

```
 client ──► MicroAPI Guard (FastAPI, port 5000 — the ONLY published port) ──► backend (internal)
                │
                ├─ read body, streamed, hard cap 1 MiB  ─────────────────────────► 413 if larger
                ├─ client id = socket peer (X-Forwarded-For only if trusted hops > 0)
                ├─ Redis: 60 s window, 5 s burst, HyperLogLog of distinct endpoints (one pipelined trip)
                │
                ├─ L0  normalize: percent-decode ×4, HTML-unescape, NFKC, strip control chars, lowercase
                ├─ L1a 26 signature rules (22 BLOCK, 4 FLAG) ── BLOCK hit ──────► 403 layer=L1-rules
                ├─ L1b rate limit: >40 per 5 s or >240 per 60 s ─────────────────► 403 layer=L1-rate
                │
                ├─ 34 shape features (common/features.py)  → StandardScaler
                ├─ L2  Isolation Forest, 300 trees           → score, min-max normalised to [0,1]
                ├─ L3  NumPy autoencoder 34-32-16-32-34      → reconstruction error, normalised
                ├─ L4  HistGradientBoosting on [rate, IF, AE] → probability p
                │        p ≥ threshold (0.43 for the live model) → ML verdict
                │
                ├─ MLGate: mode → Redis healthy? → brake → threshold → endpoint allowlist → canary
                │        default mode enforce-l1: ML verdict is LOGGED, request still forwarded,
                │        response carries X-Guard-Would-Block: L4-meta
                │
                └─ async batched log: numeric feature vector + SHA-256 client prefix (never raw body)
```

### One request, step by step (`src/gateway/main.py` → `proxy()`)

1. **Read the body with a cap.** `read_body_capped()` streams chunks and stops at 1 MiB (413).
   `await request.body()` has no limit, so one large POST could pin memory.
2. **Identify the client.** The socket address by default. `X-Forwarded-For` is read only if
   `GUARD_TRUSTED_PROXY_HOPS > 0`, and then the entry that trusted hop appended is used.
   Otherwise anyone could add one header and get a fresh rate-limit identity.
3. **Path template.** `/api/users/1837` → `/api/users/{id}` (numbers, UUIDs, hex ≥16 chars collapse).
   Used for baselines and grouping, **never as a model feature**.
4. **Rate state.** `RateLimiter.check()` does one Redis pipeline: ZADD + ZREMRANGEBYSCORE + ZCARD on a
   60 s sorted set and a 5 s sorted set, PFADD/PFCOUNT on a HyperLogLog of templates.
5. **Detect.** `detector.inspect()` runs in a threadpool (`run_in_threadpool`) so CPU-bound model
   inference does not block the async event loop.
6. **Decide.** An L1 verdict blocks under `enforce` and `enforce-l1`. An ML verdict goes through `MLGate`,
   which under the default `enforce-l1` returns gate `mode`, meaning record but don't block.
7. **Forward or 403.** Hop-by-hop headers are stripped, `X-Forwarded-For`, `X-Forwarded-Proto` and
   `X-Guard-Request-Id` are added, and the request goes out over one pooled `httpx.AsyncClient`.
   Backend down → 502, backend timeout (15 s) → 504.
8. **Log asynchronously.** An `asyncio.Queue` of up to 10,000 records is drained by a background task in
   batches of 50 into `data/events.jsonl`. If the queue fills, logging is dropped and traffic continues
   ("shed telemetry before traffic").

### The block response

```json
{"error": "Request blocked by MicroAPI Guard",
 "layer": "L1-rules",
 "reason": "sqli.union: UNION SELECT is never emitted by a legitimate API client",
 "categories": ["sqli"]}
```

Every block says which layer decided and why. That is the explainability answer for L1.

### Layer names you will see in logs and the console

| `layer` | Meaning |
| --- | --- |
| `L1-rules` | a BLOCK-severity signature matched |
| `L1-rate` | burst or window limit exceeded |
| `L4-meta` | ML probability ≥ threshold |
| `L-error` | feature extraction or inference threw; **fail closed** → treated as a block |
| `L1-only` | models not loaded; only L1 ran (`degraded: true`) |
| `""` | allowed by the ML stack |

---

## 3. The story

The panel will probably have seen numbers from more than one stage of this project. Know the
order and what changed at each step.

### Stage 0: legacy pipeline (`src/legacy/`, do not extend)

- 7 features including a **one-hot encoded HTTP path**, PyTorch listed in requirements but never imported.
  The build picked whichever of seven score sources did best on validation, so its meta-learner computed a
  number nothing used. That is why the rebuild makes L4 the only thing allowed to decide.
- Old generator: 16 normal + 19 attack hard-coded tuples. **11,474 rows contained only 31 distinct feature
  vectors** (99.7% duplicates). A random row split put identical rows on both sides of the split, which is how it
  reported F1 0.988 while having learned nothing that transfers.
- The model learned `path == /wp-admin → attack`, which amounts to a lookup table for one backend's URLs.

### Stage 1: rebuild (Review II deck)

- 34 shape features with no endpoint identity, normalization, 26 rules, session-grouped pools, withheld
  zero-day families, a 1% FPR budget, NumPy autoencoder, **Logistic Regression** meta-learner.
- 10-seed result: **F1 0.854 [0.812, 0.891]**, zero-day recall **0.598 [0.445, 0.749]**.

### Stage 2: tuned (README, paper draft)

- `tune.py` grid (noise × bottleneck × meta model, 24 configs × 5 seeds 11–15). LR gave val F1 0.600
  (sd 0.196). HGB gave 0.940 (sd 0.043). **Meta-learner switched to HistGradientBoosting.**
- 10-seed result: **F1 0.957 [0.940, 0.976]**, FPR 0.0069, zero-day **0.794 [0.668, 0.914]**.
- Ablation + McNemar: stack beats every single detector, p < 10⁻³⁴.
- Fixes along the way: header features deleted (36.7% FP on multi-client load), rate magnitude moved out of
  the ML features (38% FP on fast clients), baseline-relative features recomputed at training time
  (the first enforcement run blocked all legitimate traffic), zero-variance guard added.

### Stage 3: the audit (ZORO 1.0, `docs/ZORO_1.0.md`)

- Question: should `GUARD_MODE` move to full `enforce`? Answer: **no**.
- Ground-truth traffic through the live gateway: ML would block **31–88%** of legitimate requests depending
  on endpoint mix, with separability around AUC 0.5. L1: **0 false positives**.
- The model's verdict was effectively fixed by *which endpoint* was called: `/api/products` always ≈0.99,
  `/api/products/{id}` always ≈0.001.
- Three gateway defects found by triggering failure paths: dead Redis reported "healthy"; a corrupt model
  stopped boot even in `enforce-l1`; **`n_flags` was logged as 0 on every event ever written**.

### Stage 4: independent client and root cause (`docs/BASELINE.md`, `CHANGES_SINCE_PULL.md`)

- `validate_client.py`: a second client written from the API contract, **sharing no code, word list or
  payload builder** with the generator. A test asserts that independence.
- Locked baseline (old model): **ML FPR 67.13% (341/508)**, ROC-AUC 0.739, L1 FPR 0/508.
- Root cause, shown by intervention: the generator always called `/api/products` as `?page=N&limit=M`, so

  | Request | Score (threshold 0.25) |
  | --- | ---: |
  | `GET /api/products` (bare) | **0.9948** |
  | `GET /api/products?page=2&limit=20` | 0.0003 |

  Leaving out an optional parameter scored as worse than most real attacks. The endpoint shortcut had
  come back through `q_param_count`, `q_total_len`, `q_special_ratio`.
- Fix: widen the generator (`_query()`, `_body()` helpers, deliberate bare-call branch, accented text,
  dotted paths, PATCH/HEAD/OPTIONS, benign FLAG-tripping searches). **Changing only the data:** FPR 44.5% → 13.6%,
  F1 0.446 → 0.667, ROC-AUC 0.732 → 0.836.
- Out-of-sample normalisation bounds (the old `ae_hi` sat at the **52nd percentile** of real traffic, so
  half of legitimate requests were flattened to 1.0, the same score an attack gets) and per-endpoint bounds.

### Stage 5: model selection on four independent draws (`models/MODEL_SELECTION.md`)

- Selection rule fixed **before** seeing numbers: judge on independent traffic, rank by ROC-AUC, break ties
  on recall at 1% FPR, winner must beat the old model on FPR.
- **`models_b4` shipped**: FPR 17.02% (range 13.0–21.8%), ROC-AUC 0.8716, recall on L1-missed attacks 92.8%,
  F1 0.584, 7 of 13 endpoints under 1%.
- The old model on the same four draws: FPR 61.27% (44.5–82.5%), ROC-AUC 0.5595, and **0.389 on one draw,
  which is below chance.**

### Stage 6: safe enforcement machinery and console

- `enforcement.py`: separate detection/enforcement thresholds, per-endpoint allowlist, deterministic canary,
  automatic brake, admin token.
- 8-page React console.
- **Current state: L1 enforces. ML records. ML blocking under 1% FPR globally is not yet met.**

---

## 4. The numbers card

### Quote these

| What | Number | Measured on |
| --- | --- | --- |
| L1 false positives | **0 / 508 (0.00%)** | independent client |
| L1 false positives | 0 / 1,200 | earlier legitimate-request suite |
| L1 attack patterns | 31 / 31 blocked | known-pattern suite |
| ML false positive rate, live model `models_b4` | **17.0%** (13.0–21.8% over 4 draws) | independent client |
| ML ROC-AUC, live model | **0.87** | independent client |
| Attacks L1 missed that ML caught | **92.8%** | independent client |
| Endpoints meeting the 1% FPR target | **7 of 13** | independent client |
| Previous model on the same traffic | FPR 61.3%, AUC 0.56 | independent client |
| Fixing data only (no model change) | FPR 44.5% → 13.6% | independent client, one draw |
| In-distribution, 10 seeds (previous model) | F1 **0.957 [0.940, 0.976]**, FPR 0.0069, zero-day 0.794 [0.668, 0.914] | own generator's held-out sessions |
| Detection compute | L1 block **47 µs**; full ML path **5.43 ms** (IF 3.37 ms, HGB 1.44 ms, AE 30 µs) | single-thread microbenchmark |
| Gateway `detect_ms` | median **~11 ms**, p95 15–23 ms, p99 34–53 ms | live gateway, 1 worker, Docker Desktop |

### Do not quote these on their own

| Number | Why |
| --- | --- |
| F1 **0.991**, recall 1.000, zero-day 1.000 | seed 42, the **best** of 10 seeds. Zero-day recall ranges 0.426–1.000 across seeds |
| "F1 0.957" without saying in-distribution | the same model wrongly flags 61% of legitimate requests on independent traffic |
| "100% recall" of the old model | it was flagging entire endpoints, which produced both the 100% recall and the 44–82% FPR |
| "sub-20 ms latency" | true at the median only |
| `decision.json` test F1 0.631 for b4 | true and in-distribution; it is *lower* than the old model's because the widened generator makes the in-distribution task harder (see Q in §15) |

### Live model facts (`src/ml_pipeline/models/decision.json`)

| | |
| --- | --- |
| Model set | `models_b4`, trained 2026-09-12, seed 42 |
| Features | 34 |
| Autoencoder | 34 → 32 → 16 → 32 → 34, ReLU, linear output, **3,314 parameters**, noise 0.0 |
| Isolation Forest | 300 trees, `max_samples = min(4096, n)`, contamination `auto` |
| Meta-learner | HistGradientBoosting, depth 3, ≤200 iterations, lr 0.1, min leaf 40, L2 1.0, early stopping |
| Threshold | **0.43** (old model: 0.25) |
| Pools | base 6,386 normal / meta 4,148 / val 2,819 / test 3,753 |
| Withheld families | cmdi, exfil, ssti |
| In-distribution test | precision 0.924, recall 0.479, F1 0.631, FPR 1.83%, ROC-AUC 0.84, zero-day 0.584 |
| Known defect | its corpus fails the zero-variance gate (6 constant features); retraining it needs `TRAIN_ALLOW_CONSTANT_FEATURES=1` |

### System constants

| | |
| --- | --- |
| Signature rules | 26 (22 BLOCK, 4 FLAG) across sqli, xss, traversal, cmdi, ssti, scan, deser, ssrf |
| Rate limits | 240 req / 60 s and 40 req / 5 s per client |
| Body cap / inspected bytes | 1 MiB / first 64 KiB |
| Attack families in generator | sqli, xss, traversal, cmdi, ssti, scan, bruteforce, flood, exfil, payload (10) |
| Normal profiles | human 58%, SPA dashboard 16%, integration 16%, poller 10% |
| Paper corpus | 14,960 requests, 1,061 sessions (9,224 normal) |
| Tests | 137 collected: **112 pass, 10 skip, 15 errors** on a laptop (scikit-learn version mismatch with pickles, not real failures) |
| Console | 8 pages, React + TypeScript + Vite + Tailwind + Recharts |
| Team | Sunny Nirmal, Tausib Patel, Yash Patil · Guide: Mrs. Priyanka Kumbhar · Dept. of IT, GHRCEM Pune |

> **Fill in before the open house:** who did what. Panels nearly always ask each member
> "which part did *you* build?" Agree on the split with your teammates.

---

## 5. Layer 0 — normalization

**File:** `src/common/normalize.py`

```python
s = url_decode_loop(s)                 # unquote_plus until stable, max 4 rounds
s = html.unescape(s)                   # &lt; → <
s = unicodedata.normalize("NFKC", s)   # fullwidth / compatibility chars → ASCII
s = _NULLS.sub("", s)                  # strip control chars (not \t \n \r)
s = _WS.sub(" ", s)                    # collapse whitespace
canonical = s.lower()
```

**Why the order matters.** Decode first, then fold. If you lowercase or fold first, `%2E%2E%2F` is still
literal text and the traversal rule never sees `../`.

**Why 4 rounds.** Double and triple encoding (`%252e` → `%2e` → `.`) are standard WAF evasions. Each round
stops early if nothing changed. The cap bounds CPU on hostile input.

**NFKC.** Compatibility normalization maps fullwidth `ＵＮＩＯＮ` to `UNION` and `／` to `/`. Verified: a
fullwidth `UNION SELECT` is blocked.

**`decode_delta`.** `(len(raw) − len(decoded)) / len(raw)`, how much a string shrinks when decoded.
Heavy nested encoding is suspicious but not proof, so it becomes a *feature* (`q_decode_delta`,
`path_decode_delta`) rather than a block.

**Trap worth knowing:** `path_decode_delta` is always 0 in practice because Starlette percent-decodes the path
before the gateway sees it. That is why it is the one entry in `STRUCTURALLY_CONSTANT` in `train.py`.

**`path_template()`.** `^\d+$` → `{id}`, UUID → `{uuid}`, hex ≥16 → `{hash}`. Used to key baselines.
Never a model input. That was the Stage-0 mistake.

---

## 6. Layer 1 — signature rules and rate limiting

### 6a. Signatures (`src/common/rules.py`)

**Three design rules (expect to be asked for them):**

1. **BLOCK only what a legitimate client would essentially never send.** Anything weaker is FLAG: it does not
   block, it increments `n_flags` for the model. This is why L1's false-positive count is zero.
2. **Match structure, not single characters.** The old version blocked on a bare `'` and on `--`, which blocks
   `O'Brien` and `use the -- flag`. Example of structure:
   `sqli.tautology` = quote/space/paren, `OR|AND`, `x = y`, then a comment, a paren or end of string.
3. **Match only the normalized form.** Every encoding variant collapses onto one signature.

**The 26 rules:**

| Category | BLOCK | FLAG |
| --- | --- | --- |
| SQLi | `union`, `tautology`, `stacked_ddl`, `stacked_dml`, `xp_cmdshell`, `timing`, `schema` | `comment_terminator` |
| XSS | `script_tag`, `event_handler`, `js_uri`, `dom_exfil`, `svg_iframe` | — |
| Traversal | `dotdot`, `semicolon` (`..;/`), `unix_secrets`, `win_secrets` | — |
| Command injection | `chained`, `substitution`, `reverse_shell` | — |
| SSTI | — | `expr` (`{{…}}`, `${…}`, `<%= %>`) |
| Scanning | `vcs_secrets` (`.env`, `.git`, `.aws`, `id_rsa`…) | `admin_panels` (`wp-admin`, `phpmyadmin`…), `config_files` |
| Deserialization | `java` (`rO0AB`, `aced0005`, `pickle.loads`…) | — |
| SSRF | `metadata` (`169.254.169.254`, GCP/Azure metadata hosts) | — |

Totals: 22 BLOCK + 4 FLAG = 26.

**Targets.** `PATH` rules see path + query, `BODY` rules see the body, `ANY` sees both joined by a newline.
**Headers are never inspected** (see §14).

**The test suite checks both directions** (`tests/test_rules.py`). 34 attacks must block, including
double-encoded traversal, `..;/`, `....//`, reverse shells and JSON bodies. 18 legitimate requests must
pass: `?q=admin`, `?q=100%`, `select a product`, `european union`, `O'Brien`, `-- flag`, UUIDs,
`report.2024.pdf`, `/api/v2/products`, nested JSON.

**Order inside the detector.** Rules first, then the rate-limit check. If a request is both an SQLi
and over the limit, it is reported as `L1-rules`.

### 6b. Rate limiting (`src/gateway/ratelimit.py`)

| Signal | Redis structure | Limit | Catches |
| --- | --- | --- | --- |
| window | sorted set, 60 s | 240 / client | sustained abuse |
| burst | sorted set, 5 s | 40 / client | spikes a long window hides |
| spread | HyperLogLog of templates | none (feature only) | scanning, enumeration |

- **Algorithm: sliding-window log.** Every request is a member scored by its timestamp. Old members are
  trimmed and the rest counted. Exact, with no boundary-burst problem (a fixed window lets 2× the limit through
  across a boundary). Memory is O(requests in window) per client, bounded at roughly 240.
- **Unique member per request** (`timestamp:id:perf_counter_ns`). A bare timestamp collides under concurrency,
  so the counter under-counts at exactly the moment load is highest.
- **Blocked requests still count.** ZADD runs before the check, so a client that keeps hammering stays blocked.
- **HyperLogLog**: a fixed ≤12 KB per key with ~0.81% standard error, however many paths a scanner touches.
  That is what keeps the breadth signal cheap under attack.
- **One pipelined round trip** for all 11 commands.
- **Continuous score for L4:** `rate = clip(max(window/240, burst/40), 0, 1)`. L1 is a base detector too.
- **Redis down →** `RateState(degraded=True)`. Requests keep flowing, signatures and models still run,
  **rate limiting is off**, `/__guard/health` reports `status: degraded`, and ML enforcement is
  suppressed (`GATE_DEGRADED`) because its rate input would read as zero.

---

## 7. The 34 features

**File:** `src/common/features.py`. One `extract()` is used by **both** the gateway and the trainer.

| Group | # | Features |
| --- | ---: | --- |
| Body shape | 9 | `body_log_size`, `body_entropy`, `body_special_ratio`, `body_digit_ratio`, `body_upper_ratio`, `body_nonascii_ratio`, `body_size_z`, `has_body`, `ct_json` |
| Path shape | 11 | `path_len`, `path_depth`, `path_max_seg`, `path_entropy`, `path_special_ratio`, `path_digit_ratio`, `path_numeric_seg_ratio`, `path_nonascii_ratio`, `path_decode_delta`, `path_dot_count`, `path_known` |
| Query shape | 5 | `q_param_count`, `q_max_val_len`, `q_total_len`, `q_special_ratio`, `q_decode_delta` |
| Behaviour | 1 | `win_distinct_paths` = log1p(distinct templates in window) |
| Method | 7 | `m_get`, `m_post`, `m_put`, `m_delete`, `m_patch`, `m_other`, `is_write` |
| L1 evidence | 1 | `n_flags` (FLAG-severity hits; BLOCK hits never reach the model) |

Details people ask about:

- **Entropy** = Shannon, bits per character, over the first 4,096 body chars. English prose ≈ 4, base64 ≈ 6,
  random bytes approach 8.
- **"Special" chars** = anything not in `[A-Za-z0-9 _\-./]`.
- **Baseline-relative features:** `body_size_z` (z-score of body size against *this endpoint's* normal,
  clipped to ±10) and `path_known` (has this template been seen in the baseline). They measure deviation
  from this backend's normal, which is how one model can serve another backend after calibration.
- **Order is part of the contract.** `decision.json` stores `feature_names`. `Detector.load()` **refuses** a
  model whose list differs, because a silent reordering gives a model that is confidently wrong on every request.

### What was deleted, and why. These are good answers.

| Removed | Why |
| --- | --- |
| **One-hot path** | The model became a URL lookup table. It could not transfer to another backend or catch attacks on "benign" paths |
| **Header features** (`header_count`, `ua_len`, `ua_entropy`, `has_ua`, `has_referer`, `has_auth`) | (1) Client-controlled: an attacker copies a browser UA for free. (2) The main source of FPs: the generator's own `X-Ground-Truth`/`X-Forwarded-For` headers contaminated `header_count`. **36.7% FP** on a multi-client load |
| **Rate magnitude** (`win_log_count`, `burst_log_count`, `rate_z`) | The AE learned the corpus's ~9 req/min and rejected anything faster. An operator who configured 240/min got an effective limit near 20. **38% FP on fast legitimate clients** while test FPR read 1.3%. Now L1 decides how fast is too fast and the models decide whether the request looks wrong |

`win_distinct_paths` stayed because breadth measures behaviour (scanning, exfiltration), not volume.

### The baseline (`Baseline` class, `calibration.json`)

Per endpoint: `body_mean`, `body_std`, `count` (needs ≥5 samples), plus optional per-endpoint score bounds
`if_lo/if_hi/ae_lo/ae_hi` (needs ≥40 samples, `MIN_SCORE_SAMPLES`). Global: `rate.mean`, `rate.std`, `n_samples`.

**Why per-endpoint score bounds:** normal reconstruction error differs by about 1000× between endpoints
(0.0001 on `/api/orders` vs 0.59 on `/api/users/login`). One global ceiling saturates some endpoints at 1.0
on every request, and a saturated score tells benign and hostile apart no better than a constant.
Normalising against the endpoint's own distribution is a deviation measure, not endpoint identity,
and `FEATURE_NAMES` is unchanged.

---

## 8. Layers 2, 3, 4 — the ML stack

All three are fitted in `src/ml_pipeline/train.py` and served by `src/gateway/detector.py`.

### Scaling

`StandardScaler` fitted on the `base` pool: z = (x − μ)/σ. If σ = 0 sklearn sets scale to 1, so a feature that
was constant in training stays unscaled. That is the root of the zero-variance trap (§9).

### L2 — Isolation Forest (Liu, Ting & Zhou, ICDM 2008)

- **Idea:** build random trees by picking a random feature and a random split value. Anomalies are few and
  different, so they get isolated in **fewer splits**, i.e. a shorter path from the root.
- **Score:** s(x, n) = 2^(−E[h(x)] / c(n)), with c(n) = 2H(n−1) − 2(n−1)/n the average path length of an
  unsuccessful BST search and H(i) ≈ ln(i) + 0.5772. s → 1 is anomalous, s ≈ 0.5 or below is normal.
- **Here:** `-iforest.decision_function(X)`. With `contamination="auto"` sklearn's offset is −0.5, so the raw
  score is roughly s − 0.5, in about [−0.5, 0.5]. It is then min-max normalised with `if_lo` = 1st and `if_hi` =
  99.5th percentile of **out-of-sample** normal traffic, clipped to [0, 1].
- **300 trees** (sklearn default is 100) and **`max_samples = min(4096, n)`** (default 256). Larger subsamples
  and more trees give a more stable score, at a cost: the pickle is **25 MB** and the forest takes **62% of
  detection latency** (3.37 ms), while being the **weakest** single detector (F1 0.406 alone).
- **Fitted on normal rows only**, so it needs no labels.

### L3 — Autoencoder (`src/common/autoencoder.py`)

- **Architecture:** 34 → 32 → 16 → 32 → 34, ReLU on the hidden layers, linear output.
  Parameters: 34·32+32 + 32·16+16 + 16·32+32 + 32·34+34 = **3,314**.
- **Training:** mini-batch backprop written by hand, **Adam** (β1 0.9, β2 0.999, lr 1e-3), batch 256,
  ≤300 epochs, **early stopping** with patience 15 on a 10% held-out slice, and **the best weights are
  restored** rather than the last. Initialization: Glorot-style √(2/(fan_in+fan_out)).
- **Anomaly score:** mean squared reconstruction error per row. Trained only on normal traffic, the network
  learns to rebuild normal and rebuilds anything else badly. **No attack labels**, which is where the
  zero-day property comes from.
- **Denoising option** (`noise`): Gaussian corruption of the input, loss against the clean target. It pushes the
  network to learn the manifold rather than exact coordinates, so a capitalised name is not a 10-sigma event.
  The tuning grid tried 0, 0.05, 0.1, 0.2. The search **picked 0.0** for the current feature set, after the
  near-constant features were fixed in the data.
- **Why NumPy, not PyTorch:** the old requirements pulled in ~2 GB of torch that was never imported. For 34
  inputs, NumPy loads faster, has no CUDA/DLL surface and keeps the image small. It runs in **~30 µs**.
- **Pickle hygiene:** `__getstate__` drops Adam's moment buffers, which would otherwise triple the file size.

### L4 — meta-learner

- Input: exactly three numbers `[rate, isolation_forest, autoencoder]`, all in [0, 1]. Output: P(attack).
- **HistGradientBoostingClassifier:** max_depth 3, max_iter 200, learning_rate 0.1, min_samples_leaf 40,
  l2_regularization 1.0, early_stopping with 15% validation. Kept shallow because there are 3 inputs and a few
  thousand rows.
- **Why not logistic regression?** Measured: val F1 LR 0.600 (sd 0.196) vs HGB 0.940 (sd 0.043), and on 10 seeds
  F1 0.854 → 0.957, zero-day 0.598 → 0.794. The mechanism: the decision boundary is **non-monotonic**. The paper's
  example: a normal request (IF 0.576, AE 0.436 → p 0.018, allow) and an exfiltration attack (IF 0.280, AE 0.213
  → p 0.807, block). The attack scores *lower on both* detectors and is still blocked, which no positively
  weighted sum can express. The rate and breadth context changes what a given IF/AE pair means.
- **"Only L4 decides"** for ML. The base detectors produce features for L4 and never vote on their own.
  The exception is L1 BLOCK, which short-circuits.
- **Cost:** HGB is ~1.44 ms vs ~46 µs for LR (about 30×). Accepted for accuracy, and worth revisiting under a hard
  latency budget. `TRAIN_META=lr` still works.

### Why stack at all? (`models/comparison.json`, earlier model, identical test rows, same 1% budget)

| Detector alone | Precision | Recall | F1 | McNemar vs stack |
| --- | ---: | ---: | ---: | --- |
| Rate only | 0.981 | 0.349 | 0.515 | stack better, p = 1.6e-99 |
| Isolation Forest only | 0.875 | 0.264 | 0.406 | stack better, p = 7.1e-122 |
| Autoencoder only | 0.983 | 0.780 | 0.870 | stack better, p = 5.5e-35 |
| **Stack** | 0.983 | 1.000 | **0.991** | — |

Discordant pairs vs AE: stack-only-correct 163, AE-only-correct 3.
**Caveat to say before anyone asks:** this is in-distribution, single split, and describes the previous model.
The table has not been regenerated for `models_b4`.

---

## 9. Training and evaluation methodology

### The 8 training stages (`train.py`)

```
[1/8] load events, keep labelled rows, mark which ones L1 would block
[2/8] take L1-blocked rows OUT of the ML path (re-attached for the end-to-end number)
[3/8] session-grouped pools; novel families withheld from meta/val
[4/8] build baseline from `base` only; recompute body_size_z / path_known on every row
[5/8] zero-variance gate → StandardScaler → Isolation Forest → autoencoder (on `base` normal rows)
      → out-of-sample normalisation bounds (normal rows of `meta`) + per-endpoint bounds
[6/8] meta-learner on [rate, IF, AE] over `meta`
[7/8] threshold on `val`: max F1 subject to FPR ≤ 1%
[8/8] read `test` once → metrics, baselines, per-family recall, zero-day recall, full pipeline
      → write scaler.pkl, isolation_forest.pkl, autoencoder.pkl, meta_lr.pkl, calibration.json, decision.json
```

### The pools

`pool_of(client) = sha256(client|SEED)[:8] mod 100`

| Pool | Share | Contents | Used for |
| --- | ---: | --- | --- |
| base | 45% | **normal rows only** | scaler, forest, autoencoder, baseline |
| meta | 25% | labelled, minus novel families | meta-learner; its normal rows set the normalisation bounds |
| val | 15% | labelled, minus novel families | threshold |
| test | 15% | everything, including novel families | read once |

- **Sessions, not rows.** A random row split lets near-identical requests from one session sit on both
  sides of the split, which inflates every metric. Stage 0 got F1 0.988 that way.
- **Hash-based** so the assignment is deterministic and cannot correlate with time or label.
- **No k-fold OOF stacking needed.** The base detectors are unsupervised and fitted only on `base`, so their
  scores on `meta` are out-of-sample by construction, which is what OOF stacking exists to simulate.
- **L1-blocked rows are excluded** from ML training and evaluation because in production they never reach a
  model. Training on them would measure a decision path that never runs.

### Guards learned the hard way

| Guard | The incident behind it |
| --- | --- |
| **Recompute baseline-relative features** (`apply_baseline`) | During capture there was no baseline, so `body_size_z`/`path_known` were logged as constant 0. The AE learned "always 0". On the first enforcement run **all legitimate traffic was blocked** |
| **Zero-variance gate** (hard abort on constant features; warning for sd < 0.01) | Bit twice (baseline features, then `path_dot_count`). A corpus with `body_upper_ratio` sd 0 made one capital letter an unbounded-sigma event, causing **44% FP**. It was a warning for months that everyone read past. "A warning nobody acts on is not a control" |
| **Out-of-sample normalisation bounds** | In-sample `ae_hi` landed at the 52nd percentile of real traffic, so half of legitimate requests were flattened to 1.0 |
| **Feature contract check** at load | A reordered feature list would give confident nonsense |
| **`MODELS_DIR` for drivers** | `validate.py` once overwrote `models/` with seed 10 |
| **Duplicate check** (unique vector ratio) | Stage 0 had 31 distinct vectors |

### Evaluation rules (do not weaken; the faculty will test these)

1. **Threshold under a false-positive budget, on `val`.** F1 is maximised subject to FPR ≤ 1%. A gateway that blocks
   5% of real users is unusable however good its recall is. **Every baseline gets the same budget**, or the comparison
   just rewards whichever model was allowed to be loosest.
2. **Test is read once.**
3. **Zero-day families** cmdi, exfil, ssti are withheld from meta and val. Recall on them measures attacks never seen
   in any fitting or tuning.
4. **10 seeds, bootstrap percentile CI** (10,000 resamples of the 10 seed means). With n = 10 the normal
   approximation (mean ± 1.96 sd) assumes more than the data supports.
5. **McNemar** for paired comparison on identical rows (`compare.py` rebuilds all four models on one split).
   χ² = (|b − c| − 1)² / (b + c) with continuity correction, exact binomial when b + c < 25. **Not** across seeds:
   different seeds mean different test rows, so the pairs don't match.
6. **Tuning kept apart from reporting.** `tune.py` searches seeds **11–15**, `validate.py` reports on **1–10**.
   Tuning also swaps the held-out families to a *different* triple (bruteforce, scan, flood), so the real zero-day
   families never influence a hyperparameter. Objective: 0.5 · val F1 + 0.5 · pseudo-zero-day recall.
   It warns if the winner beats second place by less than the standard error.
7. **Independent traffic decides model choice** (§10). In-distribution numbers are diagnostic only.

### 10-seed spread (`models/validation.json`, previous model)

| Seed | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| F1 | .927 | .993 | .919 | .962 | .992 | .919 | .980 | .947 | .994 | .944 |
| Zero-day | .426 | .997 | .512 | .879 | .990 | .591 | .928 | .865 | 1.00 | .755 |

Precision, FPR and ROC-AUC are stable across seeds. **Zero-day recall is not**, because with only three
held-out families, one family going badly moves the mean a lot.

---

## 10. The main finding — independent traffic

### Why it was needed

Every pool in `train.py` comes from **one generator**. A model can score F1 0.99 on held-out sessions and still
fail on anything that merely looks different, and no in-distribution metric can show it. No production traffic was
available, so the substitute was a second client.

### `validate_client.py`: the rule is independence

- **Must never import from `generate.py`.** No helper, word list or payload builder. Duplication is deliberate.
- Disjoint identity pool (Amara, Bjorn, Chidi… vs Alice, Bob, Carol…).
- Different conventions: `offset`/`count` pagination as well as `page`/`limit`, different optional-field subsets,
  different pacing.
- 4 profiles: mobile 34%, browser 33%, partner batch 18%, ops console 15%.
- Attacks in two groups. **SIGNED** (sqli, traversal, xss, cmdi, ssrf, scan, deser): L1 should catch these.
  **UNSIGNED** (nosql, massassign, idor, logic, enum): **no L1 rule exists**, so this is the only place ML
  can justify itself.
- Paced at **3 rps** because the limit is 240/min = 4 rps. A run at 6 rps had 352 of 632 requests rate-blocked;
  they never reached the model and silently disappeared from the measurement.
- Records its **send window** so `evaluate_live.py` pairs only this run's log rows. Pairing against leftovers once
  produced a false "L1 blocks 16.67% of legitimate traffic".

### The mechanism, shown by intervention

1. Feature ablation (dropping each feature in turn): **no single feature** was responsible.
2. Per-endpoint comparison: reconstruction error on live traffic was **1,230×** the training level on `/api/products`
   and 803× on login.
3. Direct test: bare `GET /api/products` → **0.9948**; `?page=2&limit=20` → **0.0003**.
4. Diagnosis: the generator emitted one canonical shape per endpoint (3,260 of 3,260 sessions called
   `/api/products` with page and limit). The query-shape features together fingerprinted "how this endpoint is
   normally called". Endpoint identity, deliberately removed, had **come back through other features**.
5. **Intervention:** widen only the generator. The model, features, architecture and hyperparameters stayed
   the same. FPR 44.5% → 13.6%. Because only the data changed, this is evidence of cause, not just correlation.

### Why recall "dropped", and why that is not a regression

| Model | FPR | Recall | F1 | ROC-AUC |
| --- | ---: | ---: | ---: | ---: |
| Old (narrow data) | 44.5% | 100% | 0.446 | 0.732 |
| B1 (query + body shapes widened) | 13.6% | 87.9% | 0.667 | 0.840 |
| B2 (full coverage) | 8.5% | 29.7% | 0.335 | 0.813 |

The old model's 100% recall came from flagging *whole endpoints*. The same blanket produced its 44% FPR. Removing
the blanket removed both. "A stopped clock is right twice a day."

### Model selection on four independent draws

| Model | FPR mean | FPR range | ROC-AUC | Recall (L1-missed) | F1 | Endpoints ≤1% |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Old shipped | 61.27% | 44.5–82.5% | 0.5595 | 100% | 0.320 | 5 / 13 |
| models_b3 | 8.46% | — | 0.8867 | 48.4% | 0.456 | 9.8 / 13 |
| **models_b4 (live)** | **17.02%** | 13.0–21.8% | **0.8716** | **92.8%** | **0.584** | 7 / 13 |
| models_final | 9.71% | 7.1–16.4% | 0.8331 | 48.0% | 0.437 | 9.5 / 13 |

**Why b4 over b3 when b3 has fewer FPs?** The rule was fixed beforehand: ROC-AUC first, then the tie-break. b3 and b4
are effectively tied on AUC (0.887 vs 0.872). Tie-break = recall at a 1% FPR budget: **b3 catches 0.5%, b4 catches
13.4%**. b4 also has the best F1 and about twice the recall. If you are asked "isn't that cherry-picking?": the
rule was written before the numbers were seen, and the losing models are committed so anyone can re-score them.

### The expressivity limit (`docs/feature_case.html`)

Some attacks have **no unusual shape**. Retraining cannot fix that, because the features do not encode what makes the request hostile:

| Family | What makes it hostile | Candidate feature | AUC alone | 99th pct on benign |
| --- | --- | --- | ---: | ---: |
| Mass assignment | extra field names (`is_staff`, `role`) | `body_unknown_field_ratio` | 1.000 | 0.0000 |
| NoSQL injection | an object where a string belongs (`{"$ne": null}`) | `body_nonscalar_ratio` | 1.000 | 0.0000 |
| Enumeration | a huge value (`limit=10^9`) | `max_numeric_magnitude` | 1.000 | 6.22 |

The sharpest single number: under B2 a NoSQL injection on `/api/users/login` scores **0.436** while a genuine login
scores **0.936**. The attack looks *more normal* than real traffic, so no threshold separates them.

Each blind family is separated by a *different* single feature. That pattern indicates a gap in what the features
can express, not a statistical one. Adding the features breaks the 34-feature contract and needs a full retrain,
which is why it is a pending decision and not yet in the code. The risk: `body_unknown_field_ratio` has to know which
fields an endpoint accepts, which is close to learning the backend's vocabulary. The defence: it is learned from the
calibration baseline, like `body_size_z`, and must still pass the backend-agnosticism tests.

### What this means for the paper (`manuscript/REFRAME_PLAN.md`)

The plan reframes the paper from "a system" to "a measurement": *single-generator evaluation overstates
learned API anomaly detection*. Working title: **"Your Detector Learned the Generator."** Still missing: a CI on
the transfer gap across several client seeds, and McNemar for the new model.

---

## 11. Safe ML enforcement

**Files:** `src/gateway/enforcement.py`, `src/common/config.py`

**Principle:** *detection is a property of the model; enforcement is a property of the deployment.* They used to be
one boolean, which gave all-or-nothing behaviour with no reverse gear.

### Modes (`GUARD_MODE`)

| Mode | L1 rules & rate | ML |
| --- | --- | --- |
| `monitor` | log only | log only |
| **`enforce-l1`** (default) | **block** | log only, header `X-Guard-Would-Block` |
| `enforce` | block | block |

"Enforce what is certain, observe what is learned." Under full `enforce` the gateway **refuses to start** if models
cannot load, because otherwise it would advertise protection it cannot give. Under `enforce-l1` it starts and
reports `degraded`, so a corrupt pickle does not take down the layer that is actually working.

### The gate, cheapest and most global check first

```
rollout 0%            → "mode"                 (every ML detection today)
Redis degraded        → "degraded"             (rate input would read 0 — detect, don't 403)
brake engaged         → "brake"
p < enforce threshold → "below-threshold"
endpoint not allowed  → "endpoint-not-enabled"
client not in canary  → "not-in-canary"
otherwise             → "enforce"  → 403
```

Every event logs `enforce_gate`, so "why wasn't this blocked?" is recorded, not inferred.

### Knobs

| Variable | Default | Purpose |
| --- | --- | --- |
| `GUARD_ML_DETECTION_THRESHOLD` | −1 → trained value | what counts as a detection |
| `GUARD_ML_ENFORCEMENT_THRESHOLD` | −1 → same as detection | how sure before a 403; clamped never below detection |
| `GUARD_ML_ENFORCE_PERCENT` | −1 → inherit from mode | **the one "never" knob**: % of clients |
| `GUARD_ML_ENFORCE_ENDPOINTS` | empty = all | per-endpoint allowlist, because FPR is per endpoint |
| `GUARD_ML_ENFORCE_SALT` | empty | salts canary buckets so clients cannot pick an address outside the cohort |
| `GUARD_ML_BRAKE_MAX_RATE` | 0.05 | 5× the FPR budget |
| `GUARD_ADMIN_TOKEN` | empty | required before rollout > 0 |

- **Canary bucket** = `sha256(salt|client)[:4] mod 10000` vs `percent × 100` basis points. Deterministic, so a client
  never flips between blocked and allowed. Monotonic, so a client inside the 5% cohort is still inside at 25%.
- **Why only one "never" knob:** if both the threshold and the percentage defaulted to "never", an operator would
  set one, see nothing happen, assume the canary is broken, and loosen both.
- **The brake:** 10 time buckets over 300 s, cached for 1 s so it cannot be used to burn CPU. It trips when the
  **would-block rate across everything that reached the model** is above 5% with ≥200 samples **and ≥5 distinct
  clients**, so one attacker cannot trip it alone. It latches until an explicit reset. Measuring would-block rather
  than enforced means the figure is meaningful at **0% rollout**, so you can watch it for a week before anyone gets a 403.
  In-process, not Redis: a Redis outage must not break it, it adds no round trip, and in-process state fails
  toward *not* enforcing.
- **reset() clears the window too.** A unit test caught that clearing only the latch made it re-engage immediately.
- **Structural guarantee:** the L1 decision in `main.py` never calls into `enforcement.py`. A bug there can only stop
  ML blocking. It cannot weaken a signature or over-block. `evaluate()` is wrapped, so an exception means "don't enforce".

```bash
# ML blocking only on /api/products, for 5% of clients, with a brake
GUARD_ADMIN_TOKEN=<secret> GUARD_ML_ENFORCE_ENDPOINTS=/api/products \
GUARD_ML_ENFORCE_PERCENT=5 docker compose up -d gateway
# kill switch, no restart
curl -X POST 'http://localhost:5000/__guard/reload?ml_brake=engage' -H "X-Guard-Admin-Token: <secret>"
```

---

## 12. Deployment, security posture, console

### Topology (`src/docker-compose.yml`)

- Three containers: `redis:7-alpine`, backend (FastAPI mock e-commerce API), gateway. **Only port 5000 is published**,
  so the backend and Redis are unreachable from the host and the gateway cannot be bypassed. (The very first version
  published 8000 and 6379, which made the gateway decorative.)
- Gateway: Python 3.11-slim, **non-root uid 10001**, `no-new-privileges`, 2 CPU / 1 GB limit, 1 uvicorn worker,
  healthcheck on `/__guard/health`.
- **Models mounted read-only**, because pickles are executable code.
- Redis: `maxmemory 256mb`, `allkeys-lru`, no AOF.
- **Lab override** (`docker-compose.lab.yml`, "NEVER deploy"): `monitor` mode, trust 1 proxy hop (so the generator can
  simulate many IPs via XFF), trust the label header, exposes Redis and the backend on localhost.

### Admin endpoints (namespaced so they cannot shadow a backend route)

| Endpoint | Purpose |
| --- | --- |
| `GET /__guard/health` | status healthy/degraded **with reasons**, mode, ml gate snapshot, models, calibration, Redis, threshold |
| `GET /__guard/stats` | counters by deciding layer, ML detected vs enforced, gate outcomes |
| `POST /__guard/reload` | hot-reload models + baseline; `?ml_brake=engage|reset`; token-protected if set |

Health returns **HTTP 200 even when degraded**: liveness is the status code, readiness is the payload, so a
liveness probe does not restart a gateway whose signature layer is still doing useful work.

### Security decisions and the attack each one stops

| Decision | Stops |
| --- | --- |
| Ignore `X-Forwarded-For` by default | spoof one header, reset every per-IP control |
| Fail **closed** on inference error | find the input that crashes the extractor and get waved through |
| 1 MiB streamed body cap | one huge POST pinning memory |
| Never log raw bodies, only features + hashed client | passwords leaking via the security log |
| Strip `x-ground-truth` before forwarding; label header off in prod | training-data poisoning |
| Strip hop-by-hop headers both ways | duplicated/conflicting connection headers |
| Shed logging when the queue is full | a log flood turning into a traffic outage |
| Admin token for reload/brake | anyone on the port clearing the safety brake |
| Calibration refuses contaminated windows | an attacker teaching the baseline their traffic is normal |
| Feature-contract check | silent train/serve mismatch |

### Calibration for a new backend (`calibrate.py`)

Run in `monitor` in front of the new backend, let **normal** traffic flow, then
`python ml_pipeline/calibrate.py --target-fpr 0.01` and `POST /__guard/reload`.

- Re-derives the baseline, the normalisation bounds (global + per endpoint) and the threshold
  (= the (1 − target FPR) percentile of scores, clamped to [0.05, 0.999]).
- **Does not retrain the forest or the network.** Fine-tuning on a short window causes **catastrophic forgetting**, and
  any online weight update is a **poisoning surface**. Threshold + baseline recalibration limits how much damage an
  attacker can do.
- **Abort gates:** fewer than 2,000 events; more than 2% of the window trips a BLOCK rule; median score ≥ 0.5 (the
  window is not normal: this caught a single client sending 900 req/min); threshold below 0.2; threshold jump > +0.3.
  Backups are written as `.bak` before overwriting.
- Honest status: portability is a **design property**. It has not been tested against an independently built backend.

### The console (`frontend/`)

- React 18 + TypeScript + Vite 6 + Tailwind 4 + Recharts + Lucide. **8 pages:** Overview, Live Traffic, Threats,
  Threat Investigation, ML Intelligence, Request Logs, System Health, Configuration.
- Reads `/__guard/*` through a Vite proxy (the gateway sends no CORS headers on purpose) and the event log and
  artefacts through a **read-only Vite plugin** (`/__dash/*`). No new gateway endpoint was added to feed a dashboard.
- **Polling, labelled as such** (health/stats every 5 s, log every 4 s, reading only the newly appended bytes).
- Rules it follows: a block is attributed to the layer the gateway recorded, never inferred from the HTTP status
  (a 403 might be the backend's own); "Would block" is a separate amber state; missing data is shown as missing;
  ML metrics are shown with their confidence intervals.
- Playwright smoke test over all 8 routes (`npm run smoke`).
- Limitation: the file reader exists only in the dev and preview servers. A plain static host gets a page with no data.

---

## 13. Stale claims in older documents

These documents are older than the code. If a panelist quotes one, correct it calmly:
"That was true at Review II; we changed it because…"

| Old claim | Where | Current truth | Why it changed |
| --- | --- | --- | --- |
| Logistic Regression meta-learner | PRD, SDD, Review II deck, problem doc, `detector.py` docstring | **HistGradientBoosting** (LR still selectable) | tuning: LR val F1 0.600±0.196 vs HGB 0.940±0.043; boundary is non-linear |
| PyTorch autoencoder | PRD, SDD | **NumPy** autoencoder | torch was ~2 GB and never imported |
| Locust traffic generation | PRD, SDD, problem doc | Python stdlib generator | no extra dependency; full control over variation |
| Streamlit dashboard | PRD, Review II deck, problem doc | **React console**, 8 pages | needed per-layer attribution, a separate "would block" state, investigation views |
| 7 features | SDD, presentation script | **34** | old set encoded path identity |
| Static rule = window > 50 | SDD | 26 signatures + 240/60 s + 40/5 s | real WAF-style layer |
| AE 34→32→**12**→32→34 | Review II deck, README tech stack | live model is **34→32→16→32→34** | tuning picked bottleneck 16 |
| 43 features | `autoencoder.py` docstring | 34 | features were deleted (headers, rate) |
| `rate_z` is a feature | `CLAUDE.md`, `train.py` comments | not in `FEATURE_NAMES`; recomputed but ignored | rate magnitude moved to L1 |
| Backend on port 8000 | presentation script | not published; only 5000 | gateway must not be bypassable |
| Backend down → 503 | PRD | **502**, timeout → **504** | |
| Default mode `enforce` | `src/README.md` | **`enforce-l1`** | ML not safe to enforce yet |
| 35,496 requests / 14,960 requests | Review II / paper | different corpus generations; the live model's four pools hold 17,106 rows (base normal-only, novel families removed from meta/val) | the corpus was regenerated as the generator was widened |
| 92 / 102 tests | Review II / explainer | **137 collected** | tests added for generator and enforcement |
| F1 0.854, zero-day 0.598 | Review II | LR-era numbers; HGB gave 0.957 / 0.794; **both in-distribution** | |
| "Same model serves any backend" | PRD, problem doc | designed for it, **not yet tested** on a second backend | |
| "Sub-20 ms" | PRD | median yes; p95 ≈ 15–23 ms, p99 ≈ 34–53 ms | |

---

## 14. Known gaps

Bring these up yourself when it fits. Saying "here is what I would fix next and how" counts in your favour.

### Documented in the project

1. **ML is not safe to enforce globally:** 17% FPR against a 1% target, 7 of 13 endpoints qualify.
2. **All traffic is synthetic**, from two generators against one mock backend. No CSIC 2010 or production validation.
3. **Three families are invisible** to shape features: mass assignment, NoSQL injection, enumeration.
4. **Zero-day recall is unstable across seeds** (0.426–1.000).
5. **Feature-space collapse:** only ~15–24% of logged events have distinct feature vectors.
6. **`models_b4`'s corpus fails the zero-variance gate** (6 constant features). The gate was not weakened to admit it, and the defect is recorded.
7. `validation.json`, `tuning.json`, `comparison.json` describe the **previous** model.
8. **Redis is a single point of failure** for rate limiting (fails open, reported as degraded).
9. **`sqli.timing` misses `WAITFOR DELAY '00:00:05'`** (no parenthesis). It is only FLAGged by the comment rule.
10. **Scanner and SSTI rules are FLAG only**, so with ML not enforcing, `/wp-admin` probes and `{{7*7}}` have no
    blocking layer.
11. **No load test.** All latencies are at low concurrency on one worker.
12. **Admin auth is optional** (empty token by default).
13. **The training corpus is not committed** (15–35 MB, regenerable), so published numbers can only be reproduced by
    regenerating it in lab mode.

### Found while preparing this guide (verified in the code)

These are not in the project docs. Each one is a likely question from an industry panelist.

| Gap | Evidence | Fix you can propose |
| --- | --- | --- |
| **JSON `\u` escapes bypass L1.** `{"t":"<script>…"}` is not decoded by normalization, but the backend's JSON parser decodes it | probed: plain `<script>` → block, `<script>` → no hit | decode JSON string escapes (parse the body when `ct_json`) before matching |
| **MySQL versioned comment** `/*!50000UNION*/ SELECT` passes | probed: no hit (`\b` fails between `0` and `u`) | strip `/*!NNNNN … */` wrappers during normalization |
| **Only the first 64 KiB of a 1 MiB body is inspected** (`BODY_INSPECT_BYTES`) | `main.py` slices the body before `inspect()` | pad 64 KiB, then put the payload after it. Fix: set the body cap equal to the inspection window per content-type, or scan in streaming chunks |
| **Headers and cookies are never rule-checked.** Log4Shell (`${jndi:…}` in `User-Agent`) or SQLi in a cookie is invisible to L1 | `rules.evaluate(canon_path, canon_body)` only | add a HEADER target for a few high-risk headers |
| **Calibration and comparison read the removed `win_log_count`** for the rate input, while `train.py` uses `window_count` | `calibrate.py`, `compare.py` | read `window_count` from the event like `train.py` |
| **`evaluate_live --models` rescoring uses global bounds and rate = 0**, while the live gateway uses per-endpoint bounds | `evaluate_live.py: rescore()` | model-selection numbers are re-scored, not live. The difference is documented for rate, not for bounds |
| **The independent client sends from one IP**, so `win_distinct_paths` builds up across all its sessions | `validate_client.send()` has no XFF | threat to validity of the independent measurement; send with distinct identities in lab mode |
| **Admin token compared with `==`**, not constant-time | `main.py: _admin_ok` | `hmac.compare_digest` |
| **Client hash is unsalted SHA-256 of an IP.** IPv4 is only 2³² values, so it can be reversed by brute force | `hash_client()` | pseudonymisation, not anonymisation; add a secret salt (HMAC) |
| **Response is buffered, not streamed** (`upstream.content`) | `main.py` | large downloads sit in gateway memory; stream the response |
| **One worker, in-process brake and stats.** With several replicas each has its own brake and counters | `enforcement.py`, `main.py` | aggregate through Redis or a metrics backend |
| **No WebSocket / gRPC / HTTP/2-specific handling** | route methods list | out of scope; state it |
| **`pick_threshold` never returns `None`.** If no threshold meets the budget it silently returns 0.5 with F1 0 | `train.py` | the fallback branch is dead; fail loudly instead |

---

## 15. Cross-question bank

Short answers you can say out loud. **[T]** faculty, **[S]** seniors, **[I]** industry, **[X]** curveball.

### A. Problem and motivation

1. **[T] What problem are you solving, in one line?** Blocking malicious API requests inline, in front of any backend, including attacks nobody has written a rule for, without blocking real users.
2. **[T] Why APIs specifically?** Microservices expose many HTTP endpoints, each one a way in. The OWASP API Top 10 (2023) exists because API-specific abuse (object-level authorization, mass assignment, resource consumption) is different from classic web attacks.
3. **[I] Real incidents?** T-Mobile, Optus and Peloton leaked customer records through exposed or poorly protected APIs. Use these as motivation only. We did not study them.
4. **[T] What's wrong with WAFs?** They only catch what they have a signature for, and badly written rules block real users (`O'Brien`). Ours keeps that layer but writes it conservatively, and adds learned layers for the rest.
5. **[T] What's wrong with existing ML research?** It is mostly offline (logs, traces, GNNs, LLMs). By the time it reads the log, the request has already reached the database. It can alert but not block, and it needs heavy infrastructure.
6. **[I] Who would use this?** A team without a commercial API-security product that wants an inline, explainable, open filter in front of a service. In its current state it is a strong L1 filter plus an ML observer.
7. **[X] Is this a WAF?** Partly. L1 is WAF-like. The full system is an API security gateway with anomaly detection and a controlled path to ML enforcement.

### B. Architecture

8. **[T] Why four layers, not one model?** Cost follows certainty. Certain things (signatures, limits) are cheap and explainable, and the expensive models only see ambiguous traffic. It is also defence in depth: L1 can enforce from day one while ML earns trust.
9. **[T] Why does a BLOCK rule short-circuit?** Asking a model about a confirmed `UNION SELECT` adds latency and a chance of being wrong about something already certain. 47 µs vs 5.4 ms.
10. **[T] Then why do FLAG rules not block?** They are evidence, not proof (`{{price}}` could be a legitimate template search). Their count becomes `n_flags`, a feature the model can weigh.
11. **[S] Why a reverse proxy rather than middleware in the app?** It works with any backend language with zero code changes. The cost is an extra network hop.
12. **[S] Why FastAPI?** Async I/O for proxying, Python so the gateway shares `common/` with the training code (same feature code on both sides), and good performance for an async Python server.
13. **[I] Why Python for a latency-critical proxy? Wouldn't Go or Rust or Envoy be better?** For raw proxy throughput, yes. Python was chosen so training and serving share one feature implementation. That symmetry prevented real bugs. A production version could keep Python for training and export features and models to a compiled sidecar (e.g. ONNX, treelite). We'd measure first.
14. **[S] Why Redis?** Rate state must be shared across gateway replicas and survive a process restart. Sorted sets give an exact sliding window and HyperLogLog gives cheap cardinality. One pipelined round trip.
15. **[S] Why `run_in_threadpool` for inference?** Model inference is synchronous CPU work. Run inline, it would block the event loop for every other in-flight request.
16. **[I] Doesn't the GIL make the threadpool useless?** For CPU-bound Python it limits parallelism, yes. NumPy and parts of sklearn release the GIL, but the real answer for throughput is multiple worker processes or replicas. The threadpool's job is to stop one request from freezing the event loop.
17. **[S] What happens to the response body?** It is relayed with hop-by-hop headers stripped and `X-Guard-Action` added. It is currently buffered, not streamed (§14).
18. **[S] What is `X-Guard-Would-Block`?** Under `enforce-l1`, an ML verdict is recorded and the request forwarded, and this header tells the operator which layer *would* have blocked it.

### C. Normalization and rules

19. **[T] What is NFKC?** Unicode Normalization Form KC: compatibility decomposition followed by canonical composition. It folds fullwidth and other compatibility characters to plain forms, so `ＵＮＩＯＮ` becomes `UNION`.
20. **[T] Why decode up to four times?** Double and triple percent-encoding is a classic evasion. Decoding stops when the string stops changing, and the cap bounds CPU.
21. **[S] Show me a rule and explain it.** Use `sqli.tautology` or `traversal.dotdot`: `(?:^|[/\\])\.{2,}[/\\]` matches a run of two or more dots between separators, which covers `../`, `..\` and `....//`.
22. **[I] How do you avoid false positives in rules?** BLOCK only for things a client would never send, structural patterns, normalized matching, and a regression list of awkward legitimate inputs that must pass. Measured: 0/508 FP on independent traffic.
23. **[I] Can I bypass your rules?** Yes, and I can show you how: JSON `<` escapes, the MySQL `/*!50000UNION*/` form, padding past the 64 KiB inspection window, payloads in headers. Each has a fix (§14). L1 has not been fuzzed with dedicated WAF-bypass tools.
24. **[I] Why not use the OWASP Core Rule Set?** CRS is the mature choice and a real deployment should consider it. Ours is small on purpose, so every rule is explainable and tested in both directions. CRS also uses anomaly scoring, with hand-set weights. Our L4 learns how to combine the signals.
25. **[S] How many rules, and why so few?** 26. Each BLOCK rule has to meet the "never legitimate" bar. Breadth comes from the ML layers, not from a long rule list that is hard to maintain.
26. **[T] Is regex matching safe from ReDoS?** The patterns are bounded (`{0,64}`, `{1,64}`) and avoid nested quantifiers. Bodies are capped at 64 KiB for inspection. We have not run a formal ReDoS analysis, and that is worth stating.

### D. Rate limiting

27. **[T] Explain the sliding-window log.** Each request is a sorted-set member scored by its timestamp. Members older than the window are trimmed and the rest counted. Exact count, no boundary burst.
28. **[T] Compare it with token bucket / fixed window.** A fixed window can let 2× the limit through across a boundary. A token bucket allows controlled bursts with O(1) memory. The sliding log is exact but uses O(n) memory per client. We also run a short 5 s window to catch bursts.
29. **[S] Why 240/min and 40/5 s?** They are operator policy defaults, configurable by env vars. The point of the design is that L1 owns this policy, so the models must not learn a contradictory one.
30. **[T] What is HyperLogLog?** A probabilistic cardinality estimator: hash each item and keep the maximum number of leading zeros per register. Redis uses ≤12 KB per key with ~0.81% standard error. We use it to count distinct endpoints a client touches.
31. **[I] Clients behind NAT share an IP. Won't you rate-limit a whole office?** Yes. Per-IP limiting has that limit. Better keys are an API key or authenticated user id. The gateway would need to know which header carries identity, which is a deployment-specific config.
32. **[I] A botnet with 10,000 IPs at 1 req/min each?** Per-client rate limiting cannot see it. The ML breadth signal is also per-client. A slow distributed attack is out of scope, and we say so. Cross-client correlation is future work.
33. **[S] What if Redis dies?** Requests continue, rate limiting fails open, health shows `degraded` with the reason, ML enforcement is suppressed. Failing the whole gateway would turn a cache outage into a full outage.
34. **[X] Why does a blocked request still count toward the limit?** ZADD happens before the check, so a client that keeps hammering stays blocked instead of getting through every time the window slides.

### E. Features

35. **[T] Why no endpoint/path feature?** A path feature turns the model into a lookup table for one backend's URLs. It cannot transfer and cannot catch attacks on "benign" paths. That is exactly how the Stage-0 model failed.
36. **[T] Then how did endpoint identity come back?** Through query-shape features, because the generator always called each endpoint the same way. Leaving out an optional parameter looked like an attack. The fix was in the data.
37. **[T] Why remove header features? More features is more information.** They are client-controlled (an attacker sets them for free) and they were the main source of false positives (36.7%). Features an attacker can trivially set add accuracy only against attackers who don't bother.
38. **[T] What is Shannon entropy and why use it?** H = −Σ p·log₂p over the characters. Encoded, encrypted or random payloads have high entropy, prose and JSON lower. It is a cheap obfuscation signal.
39. **[S] Why log1p for body size?** Body size is heavy-tailed, and the log compresses it so a 200 KB body doesn't dominate the scaler.
40. **[S] What's `body_size_z` and why clip at ±10?** Body size as a z-score against this endpoint's normal. Clipping stops one freak request from dominating. Also, a baseline with σ ≈ 0.5 bytes (an old login baseline) turned a 4-character-longer username into a 10-sigma event. That was a real bug.
41. **[S] Why is `path_decode_delta` always zero?** Starlette decodes the path before the gateway sees it. It is listed as structurally constant.
42. **[T] Why 34 features? Did you do feature selection?** The set came from design (shape, method, breadth, L1 evidence) plus deletions driven by measured harm. Ablation (drop one at a time) found no single feature responsible for the FP problem. We have not run a formal selection method like mutual information or SHAP ranking.
43. **[X] What was the `n_flags` bug?** `inspect()` copied the event dict before setting `n_flags`, and the logger read the original. Every logged vector carried 0, so the model trained on zeros and served the real value. In-distribution evaluation cannot catch this, because the feature was constant on both sides of the split. Fixed with one line.

### F. Isolation Forest

44. **[T] How does Isolation Forest work?** Random trees with random features and split values. Anomalies get isolated in fewer splits. Score 2^(−E[h]/c(n)).
45. **[T] What is c(n)?** The average path length of an unsuccessful binary-search-tree search over n points, 2H(n−1) − 2(n−1)/n. It normalises path length so scores are comparable.
46. **[T] Why sub-sampling?** Small subsamples reduce swamping and masking (normal points crowding anomalies). The original paper uses 256. We use up to 4,096 for a more stable score on a 34-D feature space, at the cost of a 25 MB model.
47. **[I] It's the slowest and the weakest detector. Why keep it?** Fair point. It takes 62% of latency and has F1 0.406 alone. The stack beats the AE alone on identical rows, but we have **not** run the ablation "stack without IF". That is the obvious next experiment, and if IF adds nothing it should go.
48. **[T] What does `contamination="auto"` do?** It sets the offset to −0.5 (as in the paper) instead of assuming a contamination fraction. We never use the forest's own predict(), only its score, which L4 thresholds.
49. **[T] Alternatives?** One-Class SVM (scales poorly, kernel choice), LOF (density, slow at inference), Elliptic Envelope (assumes Gaussian). IF is fast to infer and needs no distance metric.

### G. Autoencoder

50. **[T] Explain an autoencoder for anomaly detection.** Compress the input through a bottleneck and reconstruct it. Trained only on normal data it rebuilds normal well, and anything off the normal manifold reconstructs badly. The error is the score.
51. **[T] Why 34-32-16-32-34?** A small, undercomplete network for 34 inputs. Bottleneck size was tuned over {8, 12, 16} and 16 won. Bigger risks learning the identity function.
52. **[T] Why ReLU and a linear output?** ReLU is standard and avoids vanishing gradients. The output is linear because the inputs are standardized real values that can be negative.
53. **[T] Why MSE?** Standardized continuous inputs, so squared error is the natural reconstruction loss.
54. **[T] Explain Adam.** Per-parameter adaptive learning rates from bias-corrected first and second moment estimates of the gradient (β1 0.9, β2 0.999).
55. **[T] Explain early stopping.** Track validation reconstruction error each epoch, stop after 15 epochs without improvement, **restore the best weights**. It prevents overfitting to the training normals.
56. **[T] What is a denoising autoencoder and did you use it?** Add noise to the input, reconstruct the clean target, so the network learns the manifold rather than exact values. Implemented and tuned. The search picked noise 0 once the near-constant features were fixed in the data.
57. **[T] Why not a VAE / LSTM / Transformer?** Each request is one independent fixed-length vector with no sequence modelling in this design. A dense AE costs 30 µs and was the strongest single detector. A sequence model over a client's request history is a reasonable future direction for slow attacks.
58. **[S] Why write backprop by hand?** To avoid a 2 GB torch dependency in a gateway image for a 3,314-parameter network. It is about 60 lines and checked against convergence.
59. **[T] AE vs PCA?** A linear AE with MSE learns the PCA subspace. ReLU makes ours non-linear, so it can fit a curved normal manifold.

### H. Meta-learner and stacking

60. **[T] What is stacking?** Base models' outputs become the inputs of a second-level model that learns how to combine them. Bagging averages models trained on resamples, boosting trains them sequentially on residuals, and stacking learns the combiner.
61. **[T] How do you avoid leakage in stacking?** Normally with k-fold out-of-fold predictions. Here the base detectors are unsupervised and fitted only on `base`, so their scores on `meta` are out-of-sample by construction.
62. **[T] How does gradient boosting work?** It adds shallow trees one at a time, each fitted to the negative gradient (residuals) of the loss, scaled by a learning rate. "Histogram" means features are binned (≤255 bins) so splits are fast.
63. **[T] Why is HGB better than LR here?** The boundary is non-monotonic. An exfiltration attack can score lower on both IF and AE than a normal request, and still needs to be blocked because of context. LR is linear and cannot express that. Measured gain: F1 +0.10 over 10 seeds, zero-day +0.20.
64. **[I] Isn't a non-monotonic boundary a risk?** Yes, and the paper says so: a learned local pocket can behave unpredictably on traffic that looks different. That is part of why ML isn't enforced globally yet.
65. **[T] Why only 3 inputs to L4, not all 34 features?** L4 is a combiner, not a second detector. Keeping it on three scores keeps it small, explainable and less likely to relearn endpoint shortcuts from raw features.
66. **[S] What is the threshold and how is it chosen?** The live model uses 0.43. It is the F1-maximizing point on `val` among thresholds with val FPR ≤ 1%, searched from 0.02 to 0.985 in steps of 0.005.
67. **[X] Your in-distribution test FPR for b4 is 1.83%. That's over the 1% budget.** The budget holds on `val`, where the threshold is chosen. Test is a different sample, so its FPR can land above it. That is normal variance between val and test, and another reason to report intervals.

### I. Evaluation and statistics

68. **[T] Why split by session, not by row?** Requests in one session are near-duplicates. A row split puts them on both sides and inflates metrics. Our Stage-0 pipeline showed exactly that.
69. **[T] What is data leakage? Give three you avoided.** Information from evaluation data reaching training. Avoided: row-level splits, base detectors seeing meta/test data, threshold tuned on test, and normalisation bounds from in-sample rows.
70. **[T] Why the FPR budget instead of maximizing F1?** F1 weights a false positive and a false negative equally. For a gateway, a false positive is a 403 to a paying user, so the right objective is maximum recall under an FPR ceiling.
71. **[T] Why is accuracy misleading here?** Class imbalance. With 99% normal traffic, "allow everything" scores 99% accuracy.
72. **[T] ROC-AUC vs PR-AUC?** ROC-AUC is the probability that a random attack scores above a random normal request. It is threshold-independent and insensitive to class ratio. PR-AUC (average precision) focuses on the positive class and is more informative when positives are rare. We report both.
73. **[T] Why was ROC-AUC the selection metric?** Threshold-independent. The threshold was known to be a separate, unsolved problem, so ranking models by how well they *order* traffic separates the two questions.
74. **[T] Explain McNemar's test.** For two classifiers on the same rows, count b = A right and B wrong, c = A wrong and B right. Under H0, b = c. χ² = (|b−c|−1)²/(b+c), 1 degree of freedom. Exact binomial when b+c < 25.
75. **[T] Why not a t-test?** Across seeds the test sets differ, so the samples are not paired the way McNemar needs. For across-seed comparison use CIs or a Wilcoxon signed-rank test on per-seed scores.
76. **[T] Explain your bootstrap CI.** Resample the 10 per-seed values with replacement 10,000 times, take the mean of each resample, and report the 2.5th–97.5th percentiles. With n = 10 the normal approximation assumes too much.
77. **[T] Why 10 seeds?** The seed changes the session partition, the forest's sampling and the AE initialization. One seed's four-decimal F1 claims a precision the experiment doesn't have.
78. **[T] What is a p-value? Does p < 1e-34 mean the stack is much better?** It is the probability of data at least this extreme if H0 were true. A tiny p means the difference is very unlikely to be chance. It does **not** measure effect size. With 2,000+ test rows even modest differences become highly significant. Look at the discordant counts (163 vs 3).
79. **[T] How is "zero-day recall" a fair term?** It is recall on three families withheld from every fitting and tuning step, which measures *unseen families*. It is not a true zero-day: the families come from the same generator, and the tuning search used a different pseudo-novel triple so the real ones never influenced a choice.
80. **[T] Why is zero-day recall so variable?** Only three families. Which sessions land in test changes per seed, and one family doing badly moves the mean a lot.
81. **[X] Seed 42 gives perfect results. Why not report that?** It is the best of 10. Reporting it alone would be cherry-picking. The interval is the result.
82. **[T] Hyperparameter tuning: how did you avoid overfitting the test?** Search on seeds 11–15 and report on 1–10. Search against a different pseudo-novel triple. Objective on `val`. Test never read during the search.

### J. The independent-traffic finding

83. **[I] So your 0.99 F1 was fake?** It was a correct measurement of the wrong question: how well the model fits its own generator. On independent traffic that model was close to chance. We found that ourselves, found the cause, and fixed most of it. This is now the main contribution.
84. **[T] How do you know the cause is the generator and not the model?** By intervention. We changed only the generator (same model, features, hyperparameters) and FPR fell from 44.5% to 13.6%. Feature ablation had ruled out any single feature.
85. **[T] How independent is "independent" if you wrote both clients?** Independent in code (asserted by a test: no imports, disjoint word lists), not in authorship. Both are synthetic against one backend. It is a substitute for production traffic, and the measured gap should be read as a **lower bound** on what real users would produce.
86. **[I] Why not just use real production traffic?** We have none with ground truth. Labelling real traffic needs attack labels you cannot be sure of, and storing raw production requests raises privacy issues. The next step is a public benchmark (CSIC 2010) and a captured deployment.
87. **[T] Why didn't CSIC 2010 get used?** It is 2010 web-form traffic, not JSON REST, has no client/session behaviour, and needs the feature extractor mapped to its schema. It is planned future work.
88. **[X] Recall went from 100% to 92.8%. Isn't the new model worse?** The old model's 100% came from flagging whole endpoints, and that same blanket gave 61% FPR. The new model ranks attacks much better (AUC 0.56 → 0.87).
89. **[I] Why ship b4 with 17% FPR instead of b3 with 8.5%?** In the default `enforce-l1` mode the ML layer doesn't block, so what matters is detection quality. The rule fixed in advance ranked by AUC (tie) and then recall at 1% FPR: b4 13.4% vs b3 0.5%. For enforcement, only endpoints measured under 1% are allowed.
90. **[T] Isn't choosing among 4 candidates on the same draws overfitting the selection?** A little, which is why the rule was fixed in advance, four draws were used instead of one, and the comparison is published with every candidate committed. A fresh set of draws would be the clean confirmation.
91. **[X] Why can't the model catch a NoSQL injection?** `{"$ne": null}` has normal length, entropy and field count. What is hostile is a *type* (object where a string belongs), and no feature encodes type. Retraining can't fix that. A `body_nonscalar_ratio` feature separates it perfectly in our data.

### K. Deployment, operations, scale

92. **[I] What is your throughput?** Not load-tested. That is the honest answer. The arithmetic: about 5.4 ms of CPU per ML-path request implies ~185 req/s per core. Arithmetic, not a measurement. The first things to optimize are IF size and the HGB meta-learner.
93. **[I] What's your p99?** 34–53 ms measured at low concurrency on one worker on Docker Desktop for Windows. Under real concurrency it is unmeasured.
94. **[I] How would you scale it?** Several stateless gateway replicas behind a load balancer. Rate state is already shared in Redis. Move the brake and stats to Redis or Prometheus. More uvicorn workers per pod. Smaller IF or a compiled model.
95. **[I] HTTPS?** Terminate TLS at the load balancer or ingress in front. Then set `GUARD_TRUSTED_PROXY_HOPS=1` so the real client IP comes from that proxy's `X-Forwarded-For`.
96. **[I] Kubernetes?** The gateway image is a stateless container with a health endpoint. Readiness can read the `status` field and liveness the HTTP code. Mount models read-only from a ConfigMap or volume.
97. **[I] How do you update the model without downtime?** `POST /__guard/reload` hot-swaps models and baseline. The feature-contract check refuses a mismatched model, and the brake is deliberately *not* cleared by a reload.
98. **[I] Rollback?** Config-only: `GUARD_MODE=enforce-l1` or `monitor`, the brake kill switch, or restore the previous model directory (in git at `8e14907`) and reload.
99. **[I] Monitoring?** `/__guard/health` with degraded reasons, `/__guard/stats` by layer and gate, the event log, and the console. No Prometheus exporter yet.
100. **[I] Model drift?** Calibrate on a fresh clean window (with contamination gates), retrain on captured traffic offline, compare on the independent-client harness, and promote through the canary with the brake on.
101. **[I] What's the latency overhead vs the backend?** In the audit, the gateway was ~79% of end-to-end time: detection p50 13.9 ms vs backend 3.8 ms on a trivially fast mock backend. On a real backend doing DB work the ratio is much smaller. We'd still optimize IF first.
102. **[I] Single point of failure?** The gateway is in the request path, so it needs replicas. Redis is a SPOF for rate limiting (fails open), fixable with Redis Sentinel/Cluster.
103. **[S] Why one uvicorn worker?** Simplicity and an in-process brake/stats. More workers multiply throughput but need shared state for those two.
104. **[I] Does it support gRPC, WebSockets, GraphQL?** HTTP methods GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS only. GraphQL over POST passes through but there are no GraphQL-aware rules (query depth, introspection). gRPC and WebSockets are out of scope.

### L. Security of the security system

105. **[I] Can an attacker poison your model?** The training labels come from a header honoured only in lab mode, which is off and stripped in production. Calibration doesn't touch weights and aborts on contaminated windows, a median score ≥ 0.5, or large threshold jumps. Weights are retrained only offline.
106. **[I] Adversarial evasion: an attacker mimics normal shape?** Possible. Mimicry attacks are a known limit of anomaly detection. L1 still catches the known payload classes, and shape features don't capture semantics (§10). Adding typed body features and per-client sequence features would raise the cost.
107. **[I] Why fail closed? Doesn't that mean any extractor bug becomes a 403 outage?** Fail-open would be a bypass: find the input that crashes the extractor and you get through. Closed is the right default for attacker-controlled input, and it is configurable. A hostile-input test checks that extraction never raises.
108. **[I] Pickle is unsafe.** Yes, it executes code on load. Models are mounted read-only, reload can require an admin token, and the container runs non-root. Better: ONNX or a signed artefact with a hash recorded in `decision.json`, which the audit recommends.
109. **[I] Your admin endpoint is unauthenticated by default.** By default reload only re-reads files. The token becomes mandatory in practice once ML rollout > 0, and health reports `admin_unauthenticated` as a degraded reason. Health and stats are always open, so put them behind network policy. (Also: the token compare should be constant-time.)
110. **[I] Privacy / DPDP Act / GDPR?** No raw bodies, query strings, headers or IPs are logged, only numeric features and a hashed client id. Caveat: an unsalted hash of an IPv4 address can be reversed by brute force, so it is pseudonymisation. Use a keyed HMAC.
111. **[I] Can the canary be gamed?** Without a salt, cohort membership is computable, so an attacker could pick an IP outside it. Health warns `ml_canary_unsalted`. Set `GUARD_ML_ENFORCE_SALT`.
112. **[I] Can one attacker trip the brake to disable ML blocking?** No. It needs ≥5 distinct clients and ≥200 samples in the window, and the client set per bucket is capped.

### M. OWASP API Top 10 (2023) coverage. Industry panelists like this mapping.

| Risk | Coverage |
| --- | --- |
| API1 Broken Object Level Authorization (IDOR) | Partial: odd ID shapes are flagged (100% on the independent client's IDOR probes); valid-looking IDs need authorization context we don't have |
| API2 Broken Authentication | Partial: brute force via rate limits |
| API3 Broken Object Property Level Authorization (mass assignment) | **Not detected.** Needs `body_unknown_field_ratio` |
| API4 Unrestricted Resource Consumption | Yes: rate limits, 1 MiB body cap |
| API5 Broken Function Level Authorization | No (needs authz model) |
| API6 Unrestricted Access to Sensitive Business Flows | Partial: rate + endpoint breadth |
| API7 SSRF | Partial: cloud metadata hosts only |
| API8 Security Misconfiguration | Partial: `.env`/`.git`/admin-panel probes |
| API9 Improper Inventory Management | Partial: `path_known` flags unknown endpoints |
| API10 Unsafe Consumption of APIs | Out of scope (outbound) |

113. **[I] So which OWASP API risks does it actually stop?** Injection-class payloads (L1), resource consumption (rate limits, body cap), scanning for secrets, cloud-metadata SSRF. Authorization flaws need application context a backend-agnostic gateway doesn't have.

### N. Comparison with industry

114. **[I] How is this different from AWS WAF / Cloudflare / Akamai?** Those have huge rule sets, threat intelligence across many customers, and their own ML scoring at global scale. We don't compete on coverage. We are open, inline, run on one CPU, explain every block by layer, and come with a measured, reproducible evaluation including where we fail.
115. **[I] And Salt / Traceable / Wallarm (API security vendors)?** They learn API baselines from real traffic, often out-of-band, plus business-logic and authorization context. Our calibration has the same idea (learn this backend's normal) in a much smaller form. Our honest advantage is transparency, not detection.
116. **[I] Kong / NGINX / API gateways?** They handle routing, auth and rate limiting. We are a security filter that could sit behind or in front of one, or be rebuilt as a plugin.
117. **[I] ModSecurity anomaly scoring vs your L4?** CRS adds hand-set rule weights into an anomaly score with a threshold. L4 learns the combination from data, and gets the rate signal and two unsupervised scores as well.

### O. Literature

118. **[T] Which papers is this closest to?** Sowmya et al. 2023 (API traffic anomaly detection in microservices, RF + bagging, ~97.8% accuracy). Sadaf & Sultana 2020 (Autoencoder + Isolation Forest in fog computing, IEEE Access). Huang et al. 2026 (intelligent API gateway, EWMA + z-score). Mahmoud et al. 2025 (DSEM-NIDS, deep stacking ensemble). Levi & Dubin 2025 (OpenAPI-mapping API security).
119. **[T] What gap did you find in the literature?** (a) Most learned detectors run offline on telemetry and can't block. (b) Few combine unsupervised detectors with a learned combiner on the request path. (c) Calibration to a new backend is rarely addressed. (d) Most important now: evaluations usually use one data source, and we measured how much that overstates performance.
120. **[T] Those papers report 95–98%. You report 17% FPR. Why is yours worse?** Most of those numbers come from a single dataset or a random split. Under the same conditions ours scored F1 0.957–0.991 too. The 17% is what happens on traffic from a different source, a test most papers don't run. Compare like with like.
121. **[T] Why Isolation Forest + Autoencoder together?** Sadaf & Sultana showed they complement each other. IF finds odd feature *combinations* by isolation, the AE finds off-manifold *reconstructions*. Our ablation shows the stack beats each alone.

### P. Project process

122. **[T] What was the hardest bug?** The first enforcement run blocked all legitimate traffic: baseline features had been logged as constant 0 during capture, the AE learned "always zero", and production values varied. The lasting fix is a training-time gate that fails the build instead of waiting for false positives in production.
123. **[T] What did you learn?** Metrics can look perfect while the system is wrong. All four major bugs were invisible in metrics and showed up only in behaviour, which is why the project now relies on guards (contract check, variance gate, FPR budget, independent client) rather than only on test scores.
124. **[T] How did you test?** 137 pytest cases: rules both directions, features (hostile input, determinism, no endpoint identity, backend-agnostic shape), detector (short-circuit, fail-closed, contract refusal, bounded probability), enforcement (canary determinism, ramp monotonicity, brake guards), generator (shape diversity, never trips BLOCK on normal traffic), integration (413, label header ignored, XFF spoofing can't evade rate limits).
125. **[S] Why do 15 tests error on a laptop?** The pickles were saved with scikit-learn 1.4.1.post1, and a newer sklearn can't unpickle them. Inside the gateway container (pinned version) they run. It is an environment issue, not a project failure. The fix is to pin sklearn in dev requirements or export models to a version-neutral format.
126. **[T] What would you do with 3 more months?** (1) Add the three expressivity features and retrain. (2) Reach ≤1% FPR per endpoint and canary-enable ML on those endpoints. (3) Validate on CSIC 2010 and one independently built backend. (4) Load test, then optimize IF. (5) Close the L1 bypasses in §14. (6) Regenerate the CIs and McNemar for the current model and publish the measurement paper.
127. **[X] Is it patentable?** Possibly as a system with a technical effect. India's Patents Act §3(k) excludes "computer programme per se", so claims would need to describe the gateway apparatus and its technical effect (fewer false positives at bounded latency), not the algorithm. The prior-art search (US 8,990,942; 10,270,788; 11,934,563; 10,911,468; 7,424,744) found each element, but not the combination. A patent agent would need to confirm. Code is covered by copyright automatically.
128. **[X] Is your project a success if ML isn't enforcing?** Yes, for three reasons: L1 is production-quality with zero measured FPs; the system *measured* that ML enforcement would cause an outage and prevented it (live demo: 2,324 requests, 295 blocked by L1, 1,877 ML verdicts recorded, 0 enforced); and the finding that single-generator evaluation overstates performance is a real, reusable result.

### Q. Curveballs and pressure questions

129. **[X] If I send `' OR 1=1--` right now, what happens?** L1 `sqli.tautology` → 403, layer `L1-rules`, ~tens of microseconds of detection.
130. **[X] If I send `GET /api/products` with no query?** With the live model, allowed. Under the old model that exact request scored 0.9948, which is how we found the root cause.
131. **[X] Search for "O'Brien"?** Allowed. It is in the must-allow test list.
132. **[X] `/wp-admin`?** FLAG only, so with ML not enforcing it is forwarded, logged with `n_flags = 1`, and probably shows "would block" in the console. That is a documented gap.
133. **[X] What if I set `X-Forwarded-For` to a random IP every request?** Ignored by default (`TRUSTED_PROXY_HOPS = 0`), so you are still rate-limited by socket address. An integration test checks this.
134. **[X] What if I send `X-Ground-Truth: normal` with an attack?** Ignored in production, and stripped before forwarding. In lab mode it is honoured, which is why lab mode must never be deployed.
135. **[X] Why a 403 and not a 400 or 429?** 403 for a security block. A dedicated 429 with `Retry-After` for rate limits would be more correct HTTP. It's a reasonable improvement.
136. **[X] Can I see a request the ML flagged and why?** Console → Threat Investigation: rate/IF/AE scores against the threshold, the feature vector, the gate reason. No per-feature attribution (SHAP) yet.
137. **[X] What does the AE "see" for an SQLi?** Usually nothing. L1 blocks it first and it never reaches the model. The ML layers exist for what L1 doesn't catch.
138. **[X] What is one thing you would do differently from the start?** Build the independent validation client before the first model, not after. Every inflated number came from evaluating on the training generator.
139. **[X] Did you use AI tools?** Answer honestly with what your team actually did. If you used assistants for code or docs, say how you checked the output (tests, measurements, reading every change). A panel respects a clear account more than a denial.
140. **[X] Your docs disagree with each other.** Yes. The older documents predate later measurements. `HANDOVER.md` and `MODEL_SELECTION.md` are the source of truth, and the project keeps the old numbers visible on purpose so the change can be checked.
141. **[X] Isn't 47 µs vs 5.4 ms just "regex is faster than ML"?** Yes, and that is the point. The design routes most of the certain cases to the cheap path, so an SQL injection is rejected about 115× faster than a benign request is cleared, and the expensive work is spent only where the decision is uncertain.
142. **[X] What is the meaning of the name?** Micro(services) API Guard: a guard placed in front of microservice APIs.
143. **[X] Why should an industry person trust any of your numbers?** Every number traces to a script and an artefact in the repo, the selection rules were fixed before results were seen, losing models are committed, and the project publishes its own failures (`ZORO_1.0.md`, `BASELINE.md`).

---

## 16. Live demo script

### Before the panel arrives

```bash
cd src
docker compose up -d
curl http://localhost:5000/__guard/health        # expect "status": "healthy", "mode": "enforce-l1"

cd ../frontend
npm run dev                                       # http://localhost:5173
```

Keep a **screen recording and screenshots** of every step as a fallback. Docker Desktop on a shared network fails often.

### The demo (5–7 minutes)

1. **Normal request is allowed**
   `curl -i "http://localhost:5000/api/products?page=1&limit=3"` → 200, `X-Guard-Action: allow`.
2. **SQL injection is blocked at L1, with an explanation**
   `curl -G --data-urlencode "q=' UNION SELECT password FROM users --" http://localhost:5000/api/search`
   → 403 JSON with `layer`, `reason`, `categories`.
3. **Double encoding does not get through**
   `curl "http://localhost:5000/api/files/%252e%252e%252f%252e%252e%252fetc%252fpasswd"` → 403.
4. **A legitimate awkward input is not blocked**
   `curl -G --data-urlencode "q=o'brien" http://localhost:5000/api/search` → 200.
5. **Live traffic in the console**: `python traffic_simulator/live_demo.py` (≈2 rps). Show Overview
   (blocked vs would-block vs allowed), Threat Investigation (detector scores vs threshold), ML Intelligence
   (CIs), System Health (brake), Configuration (rollout knobs).
6. **Rate limit (do this last)**: **stop `live_demo.py` first**, then send ~50 requests quickly:
   PowerShell `1..50 | % { curl.exe -s -o NUL -w "%{http_code} " http://localhost:5000/health }`
   → 403s with `layer: L1-rate` after 40.

### What can go wrong

| Problem | Cause | Fix |
| --- | --- | --- |
| Everything returns 403 `L1-rate` | all demo traffic comes from **one IP** (your laptop). `live_demo` + curls + a burst share one budget; going over 240/min blocks you for up to 60 s | stop `live_demo` before the burst; wait 60 s; never run `generate.py` live |
| `status: degraded`, `redis_unavailable` | Redis container not healthy | `docker compose restart redis` |
| `models_not_loaded` | model files missing or sklearn mismatch outside the container | always run the gateway in Docker |
| Console shows no data | started from the wrong folder, or gateway not on 5000 | run from `frontend/`; check `GATEWAY_URL` |
| Windows `curl` mangles quotes | PowerShell aliases `curl` | use `curl.exe`, or Git Bash |
| Clone fails "Filename too long" | a long PDF name in `Paper/` | `git config --global core.longpaths true` |

### Things not to say during the demo

- "The AI blocked that." It was L1, a regex. Say "Layer 1 blocked it, no model ran."
- "It's real-time." The console polls. Say "auto-refreshing".
- "It works on any backend." Say "it's designed to; we haven't tested it on a second backend yet."

---

## 17. Theory refreshers

**Confusion matrix:** TP attack blocked · FP normal blocked · TN normal allowed · FN attack allowed.

| Metric | Formula | Meaning here |
| --- | --- | --- |
| Precision | TP / (TP + FP) | of what we block, how much was really an attack |
| Recall (TPR) | TP / (TP + FN) | of attacks, how many we caught |
| FPR | FP / (FP + TN) | of legitimate requests, how many we'd block. **The number operators care about** |
| F1 | 2PR / (P + R) | harmonic mean, which is low if either is low |
| ROC-AUC | P(score(attack) > score(normal)) | ranking quality, threshold-free; 0.5 = coin flip |
| PR-AUC (AP) | area under precision-recall | better when attacks are rare |

**Base-rate effect (good to bring up with industry):** if 0.1% of real traffic is malicious, a detector with 99%
recall and 1% FPR produces about 10 false alarms per real attack, so precision is about 9%. That is why the FPR
budget matters more than F1, and why production systems aim far below 1%, per endpoint.

**Overfitting vs this project's failure:** classic overfitting is train ≫ test on the same distribution. Here
test was also high. The failure was **distribution shift between generators** (dataset bias / shortcut
learning): the model learned a shortcut that held across every pool from one source.

**Shortcut learning:** a model uses an easy feature that correlates with the label in the training data but not in
the world, like "query string missing → attack" here.

**Catastrophic forgetting:** fine-tuning on new narrow data overwrites what was learned before.

**Data poisoning:** an attacker influences training data so the model learns their traffic is normal.

**Concept drift:** the normal traffic distribution changes over time, so a fixed model degrades.

**Isolation Forest score:** s = 2^(−E[h(x)]/c(n)); c(n) = 2H(n−1) − 2(n−1)/n.

**McNemar:** χ² = (|b − c| − 1)² / (b + c), df = 1.

**Bootstrap percentile CI:** resample with replacement, compute the statistic, take the 2.5/97.5 percentiles.

**Z-score:** (x − μ)/σ. **Min-max:** (x − lo)/(hi − lo), clipped to [0, 1].

**Shannon entropy:** H = −Σ pᵢ log₂ pᵢ.

**Stacking vs bagging vs boosting:** learned combiner / parallel resamples averaged / sequential residual fitting.

---

## 18. One-page cheat sheet

**One sentence:** an inline, backend-agnostic API security gateway: rules and rate limits block deterministically,
two unsupervised models + a gradient-boosted combiner detect anomalies, and an honest evaluation on independent
traffic decides how far the ML layer can be trusted.

**Ten numbers**

| | |
| --- | --- |
| L1 false positives (independent) | **0 / 508** |
| ML FPR, live model (independent) | **17.0%**, was 61.3% |
| ML ROC-AUC (independent) | **0.87**, was 0.56 |
| Attacks L1 missed that ML caught | **92.8%** |
| Endpoints under 1% FPR | **7 / 13** |
| Data-only fix | FPR **44.5% → 13.6%** |
| In-distribution (10 seeds) | F1 **0.957 [0.940, 0.976]**, zero-day **0.794** |
| Detection cost | **47 µs** L1, **5.43 ms** ML path |
| Features / rules | **34** / **26** (22 block, 4 flag) |
| AE / IF / threshold | **34-32-16-32-34** (3,314 params) / **300 trees** / **0.43** |

**Five decisions to defend:** no endpoint identity in features · BLOCK only the never-legitimate ·
L1 owns rate policy · threshold under an FPR budget · ML records by default, enforced only per endpoint/canary with a brake.

**Five honest limits:** 17% FPR vs 1% goal · synthetic traffic, one backend · 3 families invisible to shape features ·
no load test · L1 bypasses (JSON `\u` escapes, 64 KiB padding, headers, `WAITFOR`).

**The story in four beats:** looked perfect (F1 0.99) → measured on independent traffic (61% FP, AUC 0.56) →
found the cause by intervention (generator shapes) → fixed it in the data (17%, AUC 0.87) and built safe rollout.

---

## 19. Where every number comes from

| Number | File |
| --- | --- |
| Live model config, threshold 0.43, pools, in-distribution metrics | `src/ml_pipeline/models/decision.json` |
| Model selection table, four draws | `src/ml_pipeline/models/MODEL_SELECTION.md`, `src/ml_pipeline/model_selection*.json` |
| 10-seed CIs, per-seed values | `src/ml_pipeline/models/validation.json` (previous model) |
| Ablation + McNemar | `src/ml_pipeline/models/comparison.json` (previous model) |
| Tuning winner | `src/ml_pipeline/models/tuning.json` |
| Locked baseline 67.13%, 0/508 | `docs/BASELINE.md` |
| 31–88%, AUC ≈ 0.5, failure-mode table | `docs/ZORO_1.0.md` |
| Bare vs paginated score, data-only fix, defects | `docs/CHANGES_SINCE_PULL.md`, `docs/project_log.html` |
| Expressivity table | `docs/feature_case.html` |
| Latency microbenchmark, paper constants | `docs/HANDOVER.md`, `docs/PROJECT_EXPLAINED.md` |
| Gateway latency p50/p95/p99 | `README.md` Known Limitations |
| Rules, features, config defaults | `src/common/rules.py`, `features.py`, `config.py` |
| Patent prior art | `docs/IPR_and_Patent_Report.md` |
| Paper plan | `manuscript/REFRAME_PLAN.md` |
| L1 bypass probes (§14) | checked against `src/common/rules.py` + `normalize.py` while writing this guide |
