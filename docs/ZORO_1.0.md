# ZORO 1.0 — ML Enforcement Readiness Audit

**Subject:** Should MicroAPI Guard move from `GUARD_MODE=enforce-l1` to `GUARD_MODE=enforce`?
**Date:** 2026-09-11
**Status:** Audit complete. No code changed. Awaiting decision.
**Verdict:** **KEEP `enforce-l1`.** Enabling `enforce` today would block between 31% and 88% of
legitimate traffic, depending on traffic mix, to buy attack coverage the deterministic layer already
provides.

---

## A. Executive summary

The detection pipeline is well engineered and its training methodology is, on inspection,
better than most final-year work: session-level splits, unsupervised base detectors fitted
on normal traffic only, withheld zero-day families, a threshold picked under a
false-positive budget, and a test pool read exactly once. None of that is the problem.

The problem is that the model does not transfer to the traffic the gateway actually sees.

Measured against a ground-truth corpus sent through the live gateway:

| Measurement | Value |
| --- | --- |
| ML separability on real traffic (AUC) | **~0.5** (0.479 and 0.558 on two samples) |
| Legitimate requests the ML layer flags | **31-88%**, depending on traffic mix |
| Legitimate requests L1 flags | **0.0%** (0 of 140) |
| Attacks L1 blocks | 68.4% (13 of 19) |
| Attacks ML would additionally block | 6 |
| Legitimate requests lost per extra attack caught | **13.3** |

An AUC of about 0.5 is chance. On the requests that survive Layer 1, the model cannot tell an
attack from a normal request at all. Two independent samples measured 0.479 and 0.558; only six
attacks survive Layer 1 in a run this size, so the value cannot be pinned down more tightly than
"chance" — and "chance" is the whole claim being made.

The mechanism is visible in one table. Within any single endpoint the score barely moves;
across endpoints it spans the entire range:

| Endpoint | n | min p | max p | spread |
| --- | ---: | ---: | ---: | ---: |
| `/api/products/{id}` | 29 | 0.0001 | 0.0102 | 0.010 |
| `/api/orders` | 19 | 0.0001 | 0.0006 | 0.001 |
| `/api/users/{id}` | 12 | 0.0001 | 0.0025 | 0.002 |
| `/api/products` | 25 | 0.9979 | 0.9996 | 0.002 |
| `/api/users/login` | 20 | 0.9867 | 0.9981 | 0.011 |
| `/api/comments` | 13 | 0.9875 | 0.9979 | 0.010 |
| `/api/search` | 14 | 0.9393 | 0.9966 | 0.057 |

### Replicated on an independent sample

The run above was repeated with a different random seed and two different endpoint mixes, 200 fresh
legitimate requests in total:

| Traffic mix | Requests | Blocked by L1 | ML would block |
| --- | ---: | ---: | ---: |
| Read-heavy (item fetches, listings) | 100 | 0 (0.0%) | 31 (**31.0%**) |
| Write-heavy (logins, comments, search) | 100 | 0 (0.0%) | 88 (**88.0%**) |
| Pooled | 200 | 0 (0.0%) | 119 (**59.5%**) |

Per-endpoint rates reproduced exactly: `/api/products`, `/api/users/login`, `/api/comments` and
`/api/search` at 100%, `/api/products/{id}`, `/api/orders` and `/api/users/{id}` at 0%, with `/health`
the only borderline endpoint (78.6%, against 100% in the first sample).

**This is the correct way to state the result.** A single aggregate false-positive figure is misleading
because it depends entirely on how much of your traffic hits the always-flagged endpoints. The robust,
reproducible finding is the per-endpoint behaviour: the model's answer is fixed by which endpoint you
call.

**The model has learned endpoint identity, not maliciousness.** Three endpoints are always
clean, four are always hostile, and the payload barely matters. This is precisely the
failure mode `common/features.py` was rewritten to eliminate — its own design note explains
that the previous pipeline one-hot encoded `http_path` and so learned "path == /wp-admin =>
attack". The current feature set removed the explicit path encoding but reconstructed the
same shortcut out of the baseline-relative features.

No threshold fixes this. See section E: there is no operating point at which the model adds
security without destroying availability.

---

## B. Existing architecture

```
Client
  └─> FastAPI gateway (:5000, only published port)
        ├─ read body, capped at GUARD_MAX_BODY_BYTES (1 MiB)
        ├─ client identity (socket peer; XFF only with TRUSTED_PROXY_HOPS > 0)
        ├─ Redis sliding window + burst + endpoint-breadth counters
        ├─ normalisation (percent / double-percent / entity / unicode -> canonical)
        ├─ L1a  26 signature rules   ── BLOCK severity short-circuits ──> 403
        ├─ L1b  rate limits          ── over limit short-circuits ──────> 403
        ├─ feature extraction (34 behavioural features, common/features.py)
        ├─ L2   Isolation Forest     -> normalised anomaly score
        ├─ L3   NumPy autoencoder    -> normalised reconstruction error
        ├─ L4   HistGradientBoosting -> P(attack) from exactly 3 inputs
        └─ decision -> forward to backend, or 403
              └─> append-only JSONL event log (numeric features, never raw bodies)
```

Admin surface is three endpoints: `GET /__guard/health`, `GET /__guard/stats`,
`POST /__guard/reload`. Everything else on port 5000 is proxied. The backend and Redis have
no host port mapping, so the gateway cannot be bypassed. The models directory is mounted
read-only because pickles are executable content.

**Verified correct.** The architecture, the short-circuit order, and the isolation of the
admin namespace are all sound and should not be changed.

---

## C. Current enforcement behaviour

| Mode | L1 signatures | L1 rate | L4 ML |
| --- | --- | --- | --- |
| `monitor` | log only | log only | log only |
| `enforce-l1` *(current default)* | **block** | **block** | log only |
| `enforce` | **block** | **block** | **block** |

Under `enforce-l1` an ML verdict is written to the log with `action: "block"` and
`enforced: false`, and the request is still forwarded with an `X-Guard-Would-Block` response
header. The console renders this as "Would block", never as a block. That distinction is
already implemented correctly end to end and is the foundation the rest of this audit rests
on — the shadow data in section D exists because the system already records what it *would*
have done.

---

## D. ML evaluation

### D.1 What the repository claims

| Source | F1 | Zero-day recall | FPR |
| --- | --- | --- | --- |
| `decision.json` (seed 42, single seed) | 0.9913 | 1.000 | 0.94% |
| `validation.json` (10 seeds, 95% CI) | 0.957 [0.940–0.976] | 0.794 [0.668–0.914] | 0.69% |

`comparison.json` shows the stack beating each base detector on the same test rows, with
McNemar p-values below 1e-34 in every case.

These numbers are internally honest. `CLAUDE.md` already warns that seed 42 is the best of
the ten runs and must not be quoted alone. The multi-seed intervals are the reportable
figures.

### D.2 Why those numbers cannot currently be reproduced

**`src/data/events_training.jsonl` does not exist.** It is the labelled corpus every
published metric was computed from, it is excluded by `.gitignore` (`src/data/*.jsonl`), and
it is not present in the working tree. `src/data/events.jsonl` has 3,647 rows and
`label: null` on every one.

Consequence: no one — including this audit — can re-run `train.py`, `validate.py` or
`compare.py` and confirm the published figures. This is a reproducibility gap, not evidence
that the figures are wrong.

### D.3 What measurement was possible

Three independent substitutes were used. All are real; each has a stated limitation.

**(1) Ground-truth shadow run against the live gateway — the primary evidence.**
140 legitimate requests modelled on the backend's own API contract, with realistic variation
in username length, body size and endpoint mix, plus 25 attacks taken from the project's own
`traffic_simulator/test_requests.py`. Paced below the burst limit so nothing was rate-blocked.
Ground truth is known by construction because this audit generated it.

**(2) The live event log.** 3,459 records that reached the models in production, using the
feature vectors and scores the gateway itself wrote. Unlabelled, so used only for
distribution analysis.

**(3) The legacy labelled corpus** `data/api_traffic_features.jsonl`, 11,474 rows
(8,089 normal / 3,385 attack), mapped into the current event schema and scored through the
shipped models. *Limitation: the legacy generator recorded no burst counter and no
distinct-endpoint counter, so behavioural features were degraded to zero. This corpus tests
the payload-shape half of the detector and not the behavioural half.*

### D.4 Results

**Shadow run, benign corpus (n = 140, all legitimate):**

| Layer | Requests blocked | Rate |
| --- | ---: | ---: |
| L1 signatures and rate limits | 0 | **0.00%** |
| L4 ML (would block under `enforce`) | 80 | **57.14%** on this mix; 31-88% across mixes |

**Shadow run, attack corpus (19 logged of 25 sent; 6 were rejected by the client library
before dispatch, not by the gateway):**

| Outcome | Count | Rate |
| --- | ---: | ---: |
| Blocked by L1 (real 403) | 13 | 68.4% |
| Flagged by ML only | 6 | 31.6% |
| Missed by both layers | 0 | 0.0% |

**Legacy corpus, full stack at the shipped threshold** (read with the D.3 limitation in mind):

| Configuration | Precision | Recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: |
| L1 alone (today) | 1.0000 | 0.3870 | 0.5580 | **0.0000** |
| L1 + ML at 0.25 (`enforce`) | 0.3097 | 1.0000 | 0.4729 | **0.9327** |

Layer 1 produced **zero** false positives across 8,089 legitimate legacy rows and across all
140 ground-truth benign requests. That is the single strongest result in this audit and it is
why the deterministic layer should keep enforcing.

### D.5 The six "additional catches" are not detections

The six attacks ML flagged that L1 did not block were on `/wp-admin`, `/phpmyadmin`,
`/config.json`, `/api/search` and `/api/comments`. The model assigns p ≈ 0.98 to *every*
request on those endpoints, benign or not — 14 of 14 benign `/api/search` calls and 13 of 13
benign `/api/comments` calls scored above threshold in the same run.

So those six are not discriminative detections. They are the same blanket endpoint flag that
produces the 80 false positives, and they happen to land on attacks. Counting them as a
security benefit would be counting a stopped clock as accurate twice a day.

---

## E. Threshold analysis

Ground-truth traffic, sweeping the enforcement threshold:

| Threshold | Benign blocked | FP rate | Extra attacks caught | Full-stack recall |
| ---: | ---: | ---: | ---: | ---: |
| 0.100 | 80 / 140 | 57.14% | 6 / 6 | 100.0% |
| 0.250 *(shipped)* | 80 / 140 | **57.14%** | 6 / 6 | 100.0% |
| 0.500 | 80 / 140 | 57.14% | 6 / 6 | 100.0% |
| 0.700 | 78 / 140 | 55.71% | 6 / 6 | 100.0% |
| 0.900 | 78 / 140 | 55.71% | 6 / 6 | 100.0% |
| 0.950 | 77 / 140 | 55.00% | 6 / 6 | 100.0% |
| 0.990 | 71 / 140 | 50.71% | 1 / 6 | 73.7% |
| 0.995 | 68 / 140 | 48.57% | 1 / 6 | 73.7% |
| 0.999 | 4 / 140 | **2.86%** | **0 / 6** | 68.4% |

Read the last row carefully. The only threshold with a tolerable false-positive rate catches
**zero** additional attacks, and full-stack recall falls to 68.4% — exactly what Layer 1
achieves on its own. The model contributes nothing at any threshold where it is safe to
enforce, and is catastrophic at every threshold where it contributes.

**Is maximising F1 the right objective here?** No, and it is worth being explicit about why.
F1 weights a false positive and a false negative equally. For an API security gateway they
are not equal:

- A false negative lets one malicious request through to a backend that has its own
  defences. Cost is bounded and probabilistic.
- A false positive returns 403 to a paying user. At 57% it is not a security control, it is
  an outage with extra steps.

The correct objective is **maximum recall subject to a hard false-positive ceiling**, which
is exactly what `CALIBRATION_TARGET_FPR = 0.01` already encodes. The pipeline's stated
objective is right. The model simply cannot meet it on real traffic: the lowest achievable
FP rate that still catches anything is 48.57%, roughly fifty times the budget.

---

## F. Rule vs ML coverage matrix

From the shadow attack corpus, by family:

| Attack family | L1 blocks | ML adds | Verdict |
| --- | --- | --- | --- |
| SQL injection (union, tautology, stacked, timing) | ✅ 5 of 6 | blanket flag only | L1 owns this |
| Path traversal (incl. encoded, `....//`) | ✅ 4 of 4 | — | L1 owns this |
| XSS (script tag, event handler, js: URI) | ✅ 3 of 3 | — | L1 owns this |
| Command injection (chained, substitution, reverse shell) | ✅ 3 of 3 | — | L1 owns this |
| SSRF (cloud metadata) | ✅ 1 of 1 | — | L1 owns this |
| Deserialization marker | ✅ 1 of 1 | — | L1 owns this |
| VCS / secret files (`.env`, `.git`) | ✅ 2 of 2 | — | L1 owns this |
| Admin-panel scanning (`/wp-admin`, `/phpmyadmin`) | ⚠️ FLAG only | blanket flag | **gap** |
| Config/backup probing (`/config.json`) | ⚠️ FLAG only | blanket flag | **gap** |
| SSTI (`{{7*7}}`, `${jndi:...}`) | ⚠️ FLAG only | blanket flag | **gap** |
| Credential stuffing / brute force | via rate limit | — | L1b, Redis-dependent |
| Flooding | via rate limit | — | L1b, Redis-dependent |

**Rule gaps, documented separately from ML gaps as requested:**

1. `sqli.timing` requires an opening parenthesis after the keyword
   (`\b(?:sleep|pg_sleep|benchmark|waitfor\s+delay)\s*\(`). The T-SQL form
   `WAITFOR DELAY '00:00:05'` has no parenthesis and passes. Confirmed live: HTTP 200.
2. Scanner and SSTI signatures are FLAG severity by design, so they never block on their
   own. That is a deliberate choice, but it means the three gap rows above currently have
   **no enforcing layer at all** once you accept that ML cannot be enforced.
3. No signature covers HTTP request smuggling, XXE, NoSQL injection, GraphQL abuse, or mass
   assignment.

---

## G. False-positive analysis

Root cause, traced to a specific mechanism.

**The calibration baseline has degenerate per-endpoint variance.** From `calibration.json`:

| Endpoint | Count | body_mean | body_std |
| --- | ---: | ---: | ---: |
| `/api/users/login` | 73 | 43.425 | **0.4943** |
| `/api/users/register` | 50 | 117.660 | 6.5134 |
| `/api/orders` | 344 | 25.860 | 12.6004 |
| 8 further endpoints | — | 0.000 | **0.0000** |

For `/api/users/login`, one standard deviation is **half a byte**. Every login in the
training corpus used a near-identical body. `features._safe_z` clips at ±10, so a real login
whose username is four characters longer than the synthetic one is an instant 10-sigma
outlier. Measured directly:

| Login body size | `body_size_z` | Autoencoder error | Verdict |
| ---: | ---: | ---: | --- |
| 43.4 B (baseline centre) | −0.05 | 0.243 (20× `ae_hi`) | **BLOCK** |
| 46 B | +5.21 | 0.273 | **BLOCK** |
| 48 B | +9.26 | 1.137 | **BLOCK** |
| 52 B and above | +10.00 (clipped) | 1.327 | **BLOCK** |

Note the first row: even at the exact centre of the calibrated baseline the request is
blocked. Body size is the largest single contributor but it is not the only one.

**Downstream effect.** `ae_hi` is the 99.5th percentile of autoencoder error on the training
base pool, so 0.5% of training traffic exceeds it by construction. In production **21.6%**
of requests that reach the models exceed it (748 of 3,459) and saturate the normalised score
at exactly 1.0. Of those saturated rows, 32.1% carry `|body_size_z| ≥ 3` and 17.4% are
clipped at the ±10 limit, against 0.0% among non-saturated rows.

**This is a data-representativeness failure, not a modelling bug.** The traffic simulator
generates bodies with almost no per-endpoint variance; real clients do not. The model is
correctly reporting that production traffic does not look like its training set.

An earlier hypothesis in this audit — that `scaler.pkl` and `meta_lr.pkl` were committed
nine days after the other artefacts and therefore came from a different training run — was
tested and **rejected**: the observed minima of both base detectors match `ae_lo` and
`if_lo` in `decision.json` to six significant figures, which they could not if the pair were
mismatched. The provenance gap is real and is logged as a risk in section R, but it is not
the cause of the false positives.

---

## H. False-negative analysis

**Current posture (`enforce-l1`):** 6 of 19 shadow attacks were not blocked — the three
scanner probes, the two SSTI payloads, and one SQLi login attempt that Layer 1 caught with
only a FLAG-severity rule. Full-stack enforced recall is **68.4%**.

**Under `enforce`:** recall would rise to 100% on this corpus, but section D.5 shows the
mechanism is a blanket endpoint flag rather than detection, so the number would not
generalise to an attack on an endpoint the model has decided is clean. An attacker who
sends a genuine SQLi payload to `/api/orders` — an endpoint scoring 0.0001 to 0.0006 —
would be waved through by the model exactly as reliably as a legitimate user is blocked on
`/api/products`.

That asymmetry is the real false-negative risk and it is invisible in the aggregate recall
figure.

---

## I. Enforcement strategy comparison

| | Security benefit | FP risk | FN risk | Latency | Complexity | Rollback | Production suitable |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **A** L1 enforce, ML monitor *(current)* | Blocks 68.4% of attacks, zero FP | **None measured** | Moderate | +14 ms | None (shipped) | N/A | **Yes** |
| **B** L1 + ML at very high confidence (≥0.999) | **No measurable gain** — catches 0 extra attacks | 2.86% | Same as A | +14 ms | Low | Env var | No — pure downside |
| **C** L1 + ML at calibrated threshold (0.25) | +6 non-discriminative flags | **57.1%** | Endpoint-blind | +14 ms | None | Env var | **No — outage** |
| **D** L1 + ML + behavioural/rate enforcement | Rate layer already enforces; ML adds nothing usable | 57.1% | Same | +14 ms | Medium | Env var | No |
| **E** Multi-stage risk tiers (allow / observe / block) | Correct *shape*; needs a model with separability | Bounded by design | Tunable | +14 ms | **High** | Env var | **Not yet** — AUC 0.479 |

Option E is the right destination. It is not reachable today: a tiered policy needs a score
that ranks attacks above benign requests, and this one ranks them slightly *below*
(AUC 0.479). Staging cannot rescue a coin flip — it only changes how many users each tier
inconveniences.

---

## J. Recommended architecture

### **KEEP `GUARD_MODE=enforce-l1`.**

Then execute a remediation programme with hard gates. ML enforcement is a *later* decision
that this audit does not approve and cannot approve on current evidence.

**Stage 1 — restore reproducibility (prerequisite for everything else)**

Regenerate the labelled corpus using the project's documented lab path, confirm the
published metrics reproduce, and record the corpus hash in `decision.json`. Until this is
done no measurement of this system is verifiable by a third party.

**Stage 2 — fix the data, not the model**

The simulator must generate the variance real traffic has: username and body-size
distributions, varied content lengths per endpoint, varied client pacing. Add a variance
floor to `calibrate.py` so no endpoint can present a standard deviation below a few bytes,
which is what turns `body_size_z` into a hair trigger.

**Stage 3 — re-measure separability before touching enforcement**

Gate: **AUC ≥ 0.90 on held-out real traffic**, and a threshold existing that holds FPR
≤ 1% while catching attacks Layer 1 misses. If that gate is not met, ML stays in
observation permanently and that is an acceptable outcome — Layer 1 with zero false
positives is a genuinely useful control.

**Stage 4 — split detection from enforcement**

Introduce `GUARD_ML_DETECTION_THRESHOLD` (what gets logged and shown) separately from
`GUARD_ML_ENFORCEMENT_THRESHOLD` (what returns 403), with the enforcement threshold
defaulting to 1.0, meaning "never". This makes staged rollout a configuration change rather
than a code change, and makes the safe default the one you get by doing nothing.

**Stage 5 — staged enforcement with an automatic brake**

Enforce for a percentage of clients, with an automatic revert if the observed block rate on
known-good endpoints exceeds a ceiling.

---

## K. Changes implemented

**None.** As instructed by Phase 0 and Phase 19, this audit modified no source file, no
model artefact, no dataset and no Docker configuration.

The only writes to the repository during this work were appends to `src/data/events.jsonl`,
which is the gateway's own append-only log doing its normal job while the shadow traffic was
sent. It is gitignored.

`git status` shows `frontend/` (the previously delivered console) and this report as the
only additions.

### Files that *would* change, if Stage 2–4 is approved

| File | Change | Risk |
| --- | --- | --- |
| `src/traffic_simulator/generate.py` | realistic body-size and identity variance | Low — data only |
| `src/ml_pipeline/calibrate.py` | variance floor on per-endpoint `body_std` | Low — additive |
| `src/common/features.py` | std floor inside `_safe_z` | **High — changes the feature contract, forces a retrain; the gateway refuses to start on mismatch** |
| `src/common/config.py` | add the two new threshold variables | Low — additive, defaults preserve behaviour |
| `src/gateway/main.py` | use enforcement threshold; `status` reflects Redis; startup gate only under full `enforce` | Medium — touches the request path |
| `frontend/src/pages/*` | surface both thresholds | Low — display only |

---

## L. Test results

| Test | Result |
| --- | --- |
| Existing pytest suite | 77 passed, 10 skipped, 15 errors |
| — cause of the 15 errors | Host has scikit-learn 1.9.0; models were pickled under the pinned 1.4.1.post1. Pre-existing, environment-only. Models load correctly inside the container. |
| Benign corpus (140 requests) | 120 × HTTP 200, 0 blocked by L1 |
| Attack corpus (19 logged) | 13 × HTTP 403 with correct rule attribution |
| Frontend smoke test | 8 of 8 routes pass, no console errors, dev and preview |
| Docker health | gateway, backend, redis all healthy |

---

## M. Performance results

Gateway-recorded, from the 159 shadow requests:

| Stage | p50 | p95 | p99 | max |
| --- | ---: | ---: | ---: | ---: |
| Detection pipeline (`detect_ms`) | 13.87 ms | 19.39 ms | 34.16 ms | 69.49 ms |
| End to end (`latency_ms`) | 17.63 ms | 23.68 ms | 55.01 ms | 103.03 ms |
| Upstream backend | 3.75 ms | 5.38 ms | — | — |
| Client-observed | 29.06 ms | 47.39 ms | — | — |

**The gateway is 79% of the request's latency.** Detection costs roughly 3.7× the backend
call it protects. For the project's scale that is acceptable, and it is honest to state that
it has not been load-tested: these figures come from a single uvicorn worker at about
7 requests per second with no concurrency. p99 under burst load is **not measured** and must
not be claimed.

Enabling `enforce` would not change latency. Inference already runs on every request that
survives Layer 1; enforcement only changes what is done with the result.

---

## N. Security considerations

Verified sound and to be preserved:

- Raw bodies, query strings, headers and client IPs are **never** written to the event log.
  Only a numeric feature vector and a SHA-256 client prefix reach disk, so a login password
  cannot leak through the log.
- `GUARD_TRUST_LABEL_HEADER` defaults false. It is a training-data poisoning channel and the
  lab override that enables it is clearly marked "NEVER deploy this".
- `GUARD_TRUSTED_PROXY_HOPS` defaults to 0, so `X-Forwarded-For` is ignored and per-client
  controls cannot be spoofed by adding a header.
- Only port 5000 is published. Redis and the backend are unreachable from the host.
- The models directory is mounted read-only; pickles are executable content.
- The gateway runs unprivileged with `no-new-privileges`.
- The feature contract is checked at load time, so a model trained on a different feature
  list is refused rather than silently producing confident nonsense.

---

## O. Failure behaviour

Each condition was tested, not assumed.

| Condition | Behaviour | Open/Closed | Assessment |
| --- | --- | --- | --- |
| Inference raises | 403, `layer: L-error` | **Closed** | ✅ Correct. Attacker-controlled input must not fail open. |
| Redis unavailable | Requests keep flowing; signature rules still block; **rate limiting silently stops working** (0 of 60 burst requests blocked against a 40/5s limit); `degraded: true` logged | **Open** | ⚠️ Defensible for availability, but Redis is a single point of failure for every flood and brute-force control. |
| Redis unavailable, health endpoint | Still reports `"status": "healthy"` with `"redis": false` | — | ❌ **Defect.** An orchestrator probing `status` sees a healthy gateway with a dead security control. |
| Models unloadable, `enforce-l1` | **Gateway refuses to start** | Closed | ❌ **Defect.** ML is not enforced in this mode, so refusing to boot over it turns a security-component failure into a total outage. |
| Models unloadable, `monitor` | Starts, L1 only, `layer: L1-only` | Open | ✅ Correct. |
| Backend unavailable | 502 from the gateway, logged | Open | ✅ Correct. |
| Backend timeout | 504 after `GUARD_UPSTREAM_TIMEOUT` (15 s) | Open | ⚠️ 15 s is long; a slow backend holds connections. |
| Body over 1 MiB | 413 before any inspection | Closed | ✅ Correct. |
| Log queue full | Logging silently dropped, traffic continues | Open | ✅ Correct priority — shed telemetry before traffic. |
| Malformed / hostile input | Covered by `test_hostile_input_never_raises` | Closed | ✅ Correct. |

---

## P. Rollback procedure

Rollback is already safe and requires **no code change**:

```bash
# revert to the audited default
cd src
GUARD_MODE=enforce-l1 docker compose up -d gateway

# emergency: stop all ML influence immediately
GUARD_MODE=monitor docker compose up -d gateway   # nothing blocks at all

# verify
curl -s localhost:5000/__guard/health   # check mode, enforcing_ml, models_loaded
```

Model artefacts can be swapped and reloaded without a restart via
`POST /__guard/reload`, which re-reads the model files and the calibration baseline.

**Gap:** there is no automatic brake. Nothing reverts enforcement if the block rate spikes.
Stage 5 of the recommendation exists to close that.

---

## Q. Frontend changes

None required for this decision. The console already implements the distinction this audit
depends on:

- "Would block" is rendered as its own amber state, never as a block.
- Blocks are attributed to the layer the gateway recorded, never inferred from HTTP status.
- L1 signature blocks, L1 rate blocks and L4 ML detections are counted and coloured
  separately on every page.
- The investigation view shows base-detector scores against the threshold, and states
  plainly when a request short-circuited at L1 before any model ran.

If Stage 4 proceeds, the Configuration and ML Intelligence pages need one addition: show
`ML_DETECTION_THRESHOLD` and `ML_ENFORCEMENT_THRESHOLD` as separate values.

---

## R. Remaining limitations

1. **The labelled corpus is missing.** No published metric in this repository is currently
   reproducible. This is the highest-priority item.
2. **The shadow attack corpus is 19 requests, of which only 6 survive Layer 1.** Adequate to
   demonstrate that the model is not separable; not adequate to estimate AUC or recall precisely. The 6 client-rejected requests
   were rejected by Python's URL handling, not by the gateway.
3. **The legacy corpus analysis is caveated** — behavioural features were degraded to zero
   by the schema mapping, as stated in D.3.
4. **Artefact provenance is undocumented.** `scaler.pkl` and `meta_lr.pkl` entered git nine
   days after the other artefacts, in a commit whose message mentions only documentation and
   `.gitignore`. Numerical testing indicates the set is coherent, but nothing in the
   repository records which run produced them. `decision.json` should carry a hash of every
   artefact it describes.
5. **No load testing.** p99 under concurrency is unmeasured.
6. **The zero-day claim is untested against real zero-days.** `NOVEL_FAMILIES` withholding is
   a sound method, but the withheld families still come from the same generator.
7. **Redis is an unmonitored single point of failure** for all rate-based controls.

---

## S. Production-readiness scorecard

| Area | Status | Evidence |
| --- | --- | --- |
| Gateway architecture | 🟢 **GREEN** | Bypass-proof topology, correct short-circuit order, unprivileged, read-only models |
| L1 rule detection | 🟢 **GREEN** | 0 false positives across 8,229 legitimate requests; 13 of 19 attacks blocked |
| Observability | 🟢 **GREEN** | Every decision explainable; would-block distinct from blocked; no secrets logged |
| Rollback | 🟢 **GREEN** | Config-only, no code change, hot reload available |
| Privacy / secret hygiene | 🟢 **GREEN** | Numeric features only; client pseudonymised; label header off by default |
| Training methodology | 🟢 **GREEN** | Session-level splits, normal-only base fitting, withheld families, single test read |
| Latency | 🟡 **YELLOW** | p50 13.9 ms / p95 19.4 ms measured, but only at ~7 rps single-worker; no load test |
| Failure handling | 🟡 **YELLOW** | Fail-closed on inference is correct; Redis fails open unmonitored; boot refusal in `enforce-l1` is wrong |
| Rule coverage | 🟡 **YELLOW** | Strong on the classic families; `sqli.timing` gap confirmed; scanners and SSTI have no enforcing layer |
| Data quality | 🔴 **RED** | Labelled corpus missing; calibration variance degenerate (8 of 13 endpoints at 0.0) |
| ML detection quality | 🔴 **RED** | **AUC ~0.5 on real traffic** — chance; model scores endpoint, not request |
| ML enforcement readiness | 🔴 **RED** | 31-88% false-positive rate; no viable threshold exists |
| Reproducibility | 🔴 **RED** | Published metrics cannot be recomputed from repository contents |
| Scalability | 🔴 **RED** | Not measured at all |

---

## Final recommendation

> ### KEEP `GUARD_MODE=enforce-l1`
>
> Do not enable `enforce`. On ground-truth traffic it blocks between 31% and 88% of legitimate
> requests depending on traffic mix
> and its apparent extra catches are a blanket endpoint flag, not detection. Measured
> separability is AUC ~0.5 — chance — and the threshold sweep shows no operating
> point where the model is both safe and useful.
>
> Layer 1 is the genuinely production-worthy component: zero false positives across every
> legitimate request tested, and 68.4% attack coverage on its own. Keep it enforcing.
>
> Treat ML enforcement as a **gated future decision**, not a configuration toggle. The gate
> is AUC ≥ 0.90 on held-out real traffic with a threshold that holds FPR ≤ 1%. Reaching it
> requires fixing the training data and the calibration baseline, not tuning the threshold.

This is a stronger result for the project than switching the flag would have been. The
system was built to measure what enforcement *would* do before doing it, and that
capability just prevented a 57% outage. Demonstrating that is a better defence of the
architecture than any F1 number.

---

*No source file, model artefact, dataset or Docker configuration was modified in producing
this report.*
