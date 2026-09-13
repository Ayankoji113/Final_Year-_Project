# Changes since the last pull from GitHub

**Pull point:** `8e14907` — *docs: add project handover documentation and update
.gitignore to include model artifacts*. This is `origin/main`, and the last commit
that exists on GitHub.

**Current branch:** `feat/security-console-and-enforcement-audit`

Everything below was produced after that pull. It splits into two parts: one commit
that is already made locally but **not pushed**, and a large body of work that is
still **uncommitted** in the working tree.

| | Files | Lines |
| --- | ---: | ---: |
| Commit `042c68a` (local only, not pushed) | 53 | +9,109 |
| Modified, uncommitted | 17 | +1,042 / −79 |
| New source and doc files, uncommitted | 9 | ~2,088 |
| New scratch / artefact directories, uncommitted | 13 | — |

---

## Part 1 — Committed locally, not yet on GitHub

### `042c68a` Add security operations console and ML enforcement readiness audit

**What.** A complete React + TypeScript + Vite frontend under `frontend/`, plus the
enforcement audit `docs/ZORO_1.0.md`. 53 files, 9,109 lines. No backend file was
touched by this commit.

**Why.** The gateway made four-layer decisions that nobody could see. A pipeline that
blocks some requests, records a verdict on others and forwards the rest is impossible
to reason about from a JSONL file.

**How.**

- **8 pages** — Overview, Live Traffic, Threats, Threat Investigation, ML
  Intelligence, Request Logs, System Health, Configuration.
- **`frontend/vite.config.ts`** proxies `/__guard` to port 5000. The gateway sends no
  CORS headers, deliberately, because it is a reverse proxy for an API and not a
  browser app. So the console is served same-origin rather than adding CORS to the
  backend.
- **`frontend/plugins/microapiData.ts`** — a Vite dev/preview plugin serving
  `/__dash/events`, `/__dash/artifacts`, `/__dash/rules`, `/__dash/config-defaults`.
  It reads files and never writes. This exists because the gateway does not serve its
  event log over HTTP, and inventing a backend endpoint just to feed a dashboard was
  out of scope.
- **`frontend/src/utils/derive.ts`** — `outcomeOf()` returns `blocked`, `observed` or
  `allowed`. A block is attributed to the layer the gateway recorded, never inferred
  from an HTTP status code.
- **`frontend/scripts/smoke.mjs`** — Playwright smoke test across all 8 routes.

**Three display rules the console holds itself to.** A metric the backend does not
expose renders "Not available from current backend" rather than being filled in.
"Would block" is its own state, because an ML verdict under `enforce-l1` is recorded
but forwarded. Polling is labelled "Auto-refreshing", never "real-time".

**`docs/ZORO_1.0.md`** is a 20-phase audit answering whether to promote `GUARD_MODE`
from `enforce-l1` to `enforce`. Verdict: **do not promote.** ML enforcement would
have blocked 31–88% of legitimate traffic depending on endpoint mix. Layer 1 measured
0% false positives over the same traffic.

---

## Part 2 — Uncommitted working tree

### 2.1 Three gateway defects fixed

Each failure mode was actually triggered rather than read.

| Defect | Evidence | Fix |
| --- | --- | --- |
| A dead Redis reported `"healthy"` | Redis stopped, 60 requests against a 40-per-5s burst limit, **zero blocked**, health still green | `status` now derives from what actually works, with a `degraded_reasons` list. HTTP stays 200 so a liveness probe does not restart a working gateway. Liveness is the status code, readiness is the payload |
| A corrupt model file stopped the gateway booting **in a mode that never blocks on ML** | The startup gate tested `config.ENFORCING`, which is true for both enforce modes | Tests `config.ML_ENFORCING`. Full `enforce` still refuses to start; `enforce-l1` starts and warns |
| `n_flags` silently dead | `detector.inspect()` copies the event dict before setting it, so **every feature vector ever logged carried `n_flags = 0`** while the model scored with the true value | One line, `ev["n_flags"] = len(decision.rule_hits)`, after `inspect()` returns |

All three are in `src/gateway/main.py`.

The third is train/serve skew that in-distribution evaluation is structurally
incapable of detecting, because the feature was constant on both sides of the split.
One feature of 34 had been dead in every model this project has ever trained.

### 2.2 Phase A — an honest measurement harness

Every pool `train.py` builds comes from one generator, so a model can score F1 0.99
on held-out data and fail on anything else with no way to tell. There is no
production traffic available, so an independent second client is the honest
substitute.

- **`src/traffic_simulator/validate_client.py`** (new, 405 lines) — a legitimate
  traffic client written from the backend's API contract, sharing **no code, no word
  list and no payload builder** with `generate.py`. Disjoint identity pools,
  different pagination conventions, different body-field subsets, independently
  written attacks. Independence is asserted by test, not by intention.
- **`src/ml_pipeline/evaluate_live.py`** (new, 375 lines) — replays a labelled corpus
  through the running gateway and reports false positives overall and per endpoint,
  recall split into what L1 already catches versus what only ML can, precision, F1,
  ROC-AUC, PR-AUC, score separation, autoencoder saturation and `detect_ms`
  percentiles.
- **`docs/BASELINE.md`** (new) — the locked baseline, so every later claim is measured
  against a written-down number.

**Locked baseline, 622 requests, 618 paired:**

| Metric | Value |
| --- | ---: |
| Layer 1 false positives | **0 / 508 · 0.00%** |
| ML false positives | 341 / 508 · 67.13% |
| Attacks ML caught that L1 missed | 91 / 91 · 100% |
| Attacks missed by both | 0 |
| ROC-AUC / PR-AUC | 0.7391 / 0.2556 |
| Detection latency p50 / p95 | 11.41 / 15.26 ms |

### 2.3 Phase B — the root cause, and the fix

**Root cause, established by intervention.** The traffic generator emitted one
canonical request shape per endpoint.

| Request | Query params | Score (threshold 0.25) |
| --- | ---: | ---: |
| `GET /api/products` | 0 | **0.9948** |
| `GET /api/products?page=2&limit=20` | 2 | 0.0003 |
| `GET /api/comments` | 0 | **0.9979** |
| `GET /api/comments?page=1&limit=20` | 2 | 0.0002 |

The model learned the generator's URL habits, not what an attack is.
`common/features.py` deliberately excludes the URL to prevent exactly this. Its own
comment records that the previous pipeline one-hot encoded the path and learned
"path == /wp-admin means attack". The shortcut returned through `q_param_count`,
`q_total_len` and `q_special_ratio`, which together fingerprint how each endpoint is
normally called.

**`src/traffic_simulator/generate.py`** (+230 / −41, the largest single diff):

- `_query(pairs, omit_prob=0.35, bare_prob=0.15)` and
  `_body(required, optional, omit_prob=0.4)` helpers. `/api/products` went from 1
  query shape to 20, `/api/orders` from always-bare to 8, POST bodies from
  always-complete to 4–6 field combinations.
- **All three session profiles routed through the same helpers.** They previously
  emitted literal strings such as `/api/products?page=1&limit=20`, bypassing every
  variation mechanism, and they carry 42% of generated sessions.
- A **deliberate bare-call branch**, because four independent 35% coin flips produced
  the bare shape only 12 times in 3,260 requests.
- Realism additions: an `ACCENTED` word list, mixed-case `rtext()`, non-ASCII paths,
  PATCH/OPTIONS/HEAD, benign searches that trip FLAG-severity rules, and corrected
  order quantities with a bounded heavy tail.

**Per-endpoint score normalisation (B5).** Normal autoencoder reconstruction error
spans three orders of magnitude between endpoints, so one global ceiling saturates
some completely, and a saturated score gives benign and hostile requests the identical
value.

- `src/common/features.py` — `Baseline.MIN_SCORE_SAMPLES = 40` and
  `Baseline.score_stats(template)` returning per-endpoint `if` / `ae` bounds, or
  `None` below the sample floor.
- `src/gateway/detector.py` — module-level `_minmax()`; `inspect()` prefers the
  endpoint's own bounds and falls back to global, so a new backend with no
  per-endpoint history behaves exactly as it does today rather than worse.
- `src/ml_pipeline/train.py` — writes per-endpoint bounds into
  `baseline.endpoints[tpl]["scores"]`, and `meta_features()` mirrors the same
  normalisation so train and serve stay symmetric.
- `src/ml_pipeline/compare.py` — mirrors it, as `CLAUDE.md` requires.

**`FEATURE_NAMES` is untouched.** This is deviation from that endpoint's own normal,
the same construction `body_size_z` already uses, not endpoint identity fed to the
model.

**Result, changing only the training data, with no change to the model, features,
architecture or hyperparameters:**

| Model | False positives | Precision | F1 | ROC-AUC | AE saturation |
| --- | ---: | ---: | ---: | ---: | ---: |
| Shipped | 44.49% | 0.287 | 0.4461 | 0.7320 | 32.9% |
| After widening | **13.58%** | **0.537** | **0.6667** | **0.8358** | **11.8%** |

Recall fell, and it is not a regression. The shipped model's apparent 100% recall was
a blanket endpoint flag, the same phenomenon producing its 44% false positives.
Removing the blanket removed both, and the detections that vanished were never
discriminative.

### 2.4 Phase C — making the failure impossible to reintroduce

- **`src/tests/test_generate.py`** (new, 15 tests) — asserts distributional properties
  of the generator: every endpoint in at least 3 query shapes, the bare form at 5% of
  traffic or more, POST bodies varying, unusual methods exercised, and normal traffic
  never tripping a BLOCK rule. Verified it can actually fail by neutering the helpers.
- **`src/ml_pipeline/train.py`** — the zero-variance warning became a hard abort.
  `STRUCTURALLY_CONSTANT = {"path_decode_delta"}` is the one allowed exception, the
  gate raises `SystemExit`, and it is overridable only via
  `TRAIN_ALLOW_CONSTANT_FEATURES`. It had printed on every run for months and been
  read past every time, while costing two measured regressions. A warning nobody acts
  on is not a control.
- **`src/ml_pipeline/train.py`** — normalisation bounds moved from in-sample to
  out-of-sample, derived from `pools["meta"]` normal rows instead of the `base` rows
  the autoencoder was fitted on. The old ceiling sat at the **52nd percentile of real
  traffic**, flattening half of all legitimate requests to the score every attack
  gets.
- **`src/ml_pipeline/calibrate.py`** — gains `--rederive-bounds` and
  `--keep-trained-bounds`, and now re-derives those bounds globally and per endpoint
  from the deployment's own traffic. It previously reused them from `decision.json`,
  so a new backend inherited the training corpus's scale. Every existing abort gate is
  kept, and it still refuses to retrain the forest or the network.

### 2.5 Phase D — model selection

**`src/ml_pipeline/model_select.py`** (new) compares candidates across repeated
independent client draws. The selection rule was fixed **before** any numbers were
seen: decide on cross-generator performance, rank by ROC-AUC because it is
threshold-independent, break ties on recall at the project's own 1% false-positive
budget, and require the winner to beat the shipped model on false positives.

| Model | FPR mean | FPR range | ROC-AUC | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Shipped | 61.27% | 44.5–82.5% | 0.5595 | 100% | 0.320 |
| **models_b4** | 17.02% | 13.0–21.8% | **0.8716** | **92.8%** | **0.584** |
| models_final | 9.71% | 7.1–16.4% | 0.8331 | 48.0% | 0.437 |

The shipped model is far worse than any single draw suggested. On one draw its
ROC-AUC fell to **0.3888, below chance**, ranking attacks beneath legitimate traffic.

### 2.6 Phase E — safe enforcement machinery

Everything here is additive and defaults to current behaviour. Doing nothing keeps
the gateway byte-identical, and all three existing `GUARD_MODE` values work unchanged.

- **`src/gateway/enforcement.py`** (new, 273 lines) — `MLGate` and `_Brake`. Gate
  order, cheapest and most global first: mode → degraded → brake → below-threshold →
  endpoint → canary → enforce. The brake uses 10 time-buckets over
  `ML_BRAKE_WINDOW_SECS`, cached 1 second so it cannot become a CPU amplification
  target. It measures the **would-block rate across everything that reached the
  model**, which means the figure is meaningful at 0% rollout, so you can learn
  whether enforcement is safe before anyone gets a 403.
- **`src/common/config.py`** — `ADMIN_TOKEN`, `ML_DETECTION_THRESHOLD`,
  `ML_ENFORCEMENT_THRESHOLD`, `ML_ENFORCE_PERCENT` (with a `-1` inherit sentinel),
  `ML_ENFORCE_ENDPOINTS`, `ML_ENFORCE_SALT`, `ML_REQUIRE_RATE_STATE`, `ML_BRAKE_*`,
  `_rollout_percent()` and `ML_ROLLOUT_BPS`. **One knob carries "never"**, the
  percentage, because two never-defaults create the failure where an operator sets
  one, sees nothing happen, and loosens both.
- **`src/gateway/main.py`** — separates `ml_verdict` from `enforced`, wires the gate,
  and adds `_admin_ok(request)` plus `reload_models(request, ml_brake="")` accepting
  `?ml_brake=engage|reset`. `/__guard/*` previously sat on the only published port
  with no authentication at all, and a safety brake anyone on the network can clear is
  worse than no brake, because an operator believes they are protected.
- **New event-log fields** `enforce_gate`, `enforce_threshold` and `canary`. All
  additive, so every existing field keeps its name and meaning and both `train.py` and
  the console's chart layer work unmodified.
- **`src/tests/test_enforcement.py`** (new, 20 tests) — canary determinism, ramp
  monotonicity, gate order, brake guards, and a backward-compatibility table. One of
  these caught a real flaw: `reset()` cleared the latch but not the measurement
  window, so the brake re-engaged immediately.
- **`src/docker-compose.yml`** — passes `GUARD_ADMIN_TOKEN` and `GUARD_ML_*` through
  with safe defaults, since the new variables were otherwise never reaching the
  container.

### 2.7 Console updates for enforcement (E6)

| File | Change |
| --- | --- |
| `frontend/src/types/index.ts` | `MlEnforcement`, `MlBrake`, `GuardHealth.ml`, `GuardEvent.enforce_gate` / `enforce_threshold` / `canary`, `GuardStats.ml_detected` / `ml_enforced` / `ml_gate` |
| `frontend/src/utils/derive.ts` | `GATE_META` and `gateMeta()`, a plain-language reason per gate value |
| `frontend/src/pages/Configuration.tsx` | rollout panel: both thresholds, canary percentage, endpoint allowlist |
| `frontend/src/pages/SystemHealth.tsx` | brake panel: engaged state, trip snapshot, window |
| `frontend/src/components/investigation/InvestigationView.tsx` | per-request enforcement reason, so why a verdict was or was not acted on is recorded rather than inferred |
| `frontend/src/pages/Overview.tsx` | "ML detected / enforced" card |

### 2.8 Documentation and manuscript

| File | What |
| --- | --- |
| `docs/BASELINE.md` | the locked Phase A baseline and how to reproduce it |
| `docs/feature_case.html` | the feature-set decision: three attack families that shape features cannot express |
| `docs/project_log.html` | the full A–Z project record |
| `manuscript/REFRAME_PLAN.md` | the plan to reframe the IEEE paper around the cross-generator finding |

**The expressivity finding** in `docs/feature_case.html`: massassign, nosql and enum
are undetectable by shape features, and retraining cannot fix it. Each is separated
perfectly by a single candidate feature, a *different* one each time, at AUC 1.000
with roughly zero benign cost. That is what an expressive gap looks like rather than a
statistical one. A NoSQL injection on `/api/users/login` scores 0.436 while a genuine
login scores 0.936, so they are ordered the wrong way round and no threshold can
separate them.

### 2.9 `.gitignore`

Added `src/ml_pipeline/models_verify/`, `src/eval_corpus.json` and
`src/ml_pipeline/baseline_*.json`. Also confirmed `.claude/settings.local.json` is
ignored. It contains a live API key and **must never be committed**. It never has
been.

### 2.10 Scratch left on disk, not for commit

Diagnostic output from the measurement work, all untracked:
`src/clean_eval.json`, `src/eval_seed{101,202,303}.json`,
`src/data/events_training.jsonl.{prev,preB,b1,b2,b3,b4}`,
`src/ml_pipeline/models_{b,b2,b3,b4,final,fixed,wide}/`,
`src/ml_pipeline/model_selection*.json` and
`src/ml_pipeline/validation_widened.json`.

`src/traffic_simulator/live_demo.py` (new) is keepable. It drives continuous demo
traffic through the gateway at a pace that stays under the Layer-1 rate limit, so the
console has something live to show.

---

## Verification state

| Check | Result |
| --- | --- |
| `cd src && pytest tests/ -v` | 112 passed, 10 skipped, 15 errors (pre-existing host scikit-learn 1.9.0 against the pinned 1.4.1.post1) |
| `cd frontend && npm run build` | passes |
| `cd frontend && npm run smoke` | all 8 routes pass |
| Live demo, 2,324 requests | 2,029 allowed, 295 L1 blocks, 1,877 ML detections recorded, **0 enforced** |
| `src/ml_pipeline/models/` | untouched, the shipped artefacts are unchanged |

---

## Decisions taken at commit time

1. **Shipped model: `models_b4`.** Best ROC-AUC-with-recall on four independent client
   draws. Its corpus fails the C2 variance gate; the gate was not weakened, and the defect
   is recorded in `src/ml_pipeline/models/MODEL_SELECTION.md`. The previous model is
   recoverable from commit `8e14907`.
2. **Everything is committed** except scratch model sets, corpus snapshots and replay
   corpora, which are now in `.gitignore`.
3. **Phase D's global gate is still unmet.** 7 of 13 endpoints qualify for ML enforcement
   at the 1% false-positive budget with this model. `GUARD_MODE` stays `enforce-l1`.

---

## Out of scope, still open

From the ZORO 1.0 audit, unrelated to this work: the `sqli.timing` rule gap, where
`WAITFOR DELAY '00:00:05'` has no parenthesis and passes; Redis as an unmonitored
single point of failure for all rate controls; and the FLAG-severity scanner and SSTI
rules that have no enforcing layer while ML is not enforcing.
