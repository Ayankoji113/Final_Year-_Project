# MicroAPI Guard — The Whole Project, Explained

A start-to-finish walkthrough in plain language: what the problem is, what we
built, how each piece works, why it was built that way, and what to say when an
interviewer pushes back.

Read it top to bottom once. After that, the **Interview Q&A** section at the end
is the part worth re-reading before a call.

---

## Table of Contents

1. [The one-paragraph version](#1-the-one-paragraph-version)
2. [The problem we set out to solve](#2-the-problem-we-set-out-to-solve)
3. [The big idea: four layers, cost tracks certainty](#3-the-big-idea-four-layers-cost-tracks-certainty)
4. [Walking one request through the system](#4-walking-one-request-through-the-system)
5. [Layer 0 — Normalization](#5-layer-0--normalization)
6. [Layer 1 — Rules and rate limiting](#6-layer-1--rules-and-rate-limiting)
7. [The features: how a request becomes 34 numbers](#7-the-features-how-a-request-becomes-34-numbers)
8. [Layer 2 — Isolation Forest](#8-layer-2--isolation-forest)
9. [Layer 3 — Autoencoder](#9-layer-3--autoencoder)
10. [Layer 4 — The meta-learner](#10-layer-4--the-meta-learner)
11. [Where the training data came from](#11-where-the-training-data-came-from)
12. [How training actually works](#12-how-training-actually-works)
13. [How we evaluated it honestly](#13-how-we-evaluated-it-honestly)
14. [The results](#14-the-results)
15. [Deployment and operations](#15-deployment-and-operations)
16. [Security decisions worth defending](#16-security-decisions-worth-defending)
17. [Things that went wrong and what we learned](#17-things-that-went-wrong-and-what-we-learned)
18. [Known limitations](#18-known-limitations)
19. [Repo map](#19-repo-map)
20. [Interview Q&A](#20-interview-qa)
21. [Resume bullets](#21-resume-bullets)

---

## 1. The one-paragraph version

MicroAPI Guard is a security gateway that sits in front of any HTTP API as a
reverse proxy. Every request passes through four detection layers before it is
allowed to reach the real backend: fast deterministic rules and rate limits
first, then two unsupervised machine-learning models, then a small supervised
model that combines their opinions into one final probability. Obvious attacks
are killed in **47 microseconds** without touching a model; everything ambiguous
goes to the full pipeline at about **5.4 milliseconds**. The backend needs zero
code changes. Across 10 random seeds it reaches **F1 0.957** with a **0.7% false
positive rate**, and it catches **79%** of attack types it was never trained on.

---

## 2. The problem we set out to solve

**Modern apps are made of many small services, each exposing HTTP endpoints.**
That is a lot of doors. One unmonitored endpoint is enough — T-Mobile, Optus and
Peloton all leaked millions of records through exactly that.

There are two families of existing solutions, and both have a hole:

**Signature WAFs (Web Application Firewalls)** — ModSecurity and friends. They
carry a list of known-bad patterns. They are fast, deterministic, and they can
explain exactly why they blocked something. But they are **blind to anything
without a rule**. A brand-new attack technique walks straight through. And they
are notorious for false positives, because naive rules match on things like a
bare apostrophe — which blocks anyone named O'Brien.

**Recent ML research detectors** — graph neural networks over service
dependencies, LLMs reading log streams, deep Bayesian nets over distributed
traces. These are accurate, but they have two practical problems:

1. They need heavy infrastructure — GPUs, trace pipelines, log aggregators.
2. **They read telemetry after the fact.** By the time the log reaches the
   detector, the request already hit the database. They can *alert*; they cannot
   *block*.

So the gap is: **something that sits on the request path, blocks inline, runs on
a CPU, and still catches attacks nobody wrote a rule for.** That is MicroAPI
Guard.

---

## 3. The big idea: four layers, cost tracks certainty

The core insight is that **not every request deserves the same amount of
thinking.**

If a request contains `UNION SELECT`, you do not need a neural network to have an
opinion. It is an attack. Block it, spend microseconds, move on.

If a request looks perfectly ordinary but is the 300th one this client sent in a
minute, you do not need a neural network either — you need a counter.

Only requests that are **neither obviously malicious nor obviously excessive**
are worth spending milliseconds on.

```
                    ┌──────────────────────────────────────┐
   client ─────────►│          MicroAPI Guard              │────► your backend
                    │                                      │
                    │  L0  normalize (decode, fold, strip) │
                    │       ↓                              │
                    │  L1  signature rules + rate limits   │  ← deterministic
                    │       ↓  (BLOCK hits stop here)      │    ~47 µs
                    │  L2  Isolation Forest                │  ← unsupervised
                    │       ↓                              │
                    │  L3  Autoencoder                     │  ← unsupervised
                    │       ↓                              │    ~5.4 ms
                    │  L4  Gradient-boosted meta-learner   │  ← MAKES THE CALL
                    └──────────────────────────────────────┘
```

**The one rule that governs the whole design: only L4 decides.**

L1's rate score, L2's forest score and L3's reconstruction error are not
verdicts. They are three numbers that get handed to L4, which outputs a single
probability. If that probability crosses the threshold, the request is blocked.

(The one exception: a **BLOCK-severity L1 rule short-circuits** before any model
runs. Asking a statistical model for its opinion on a confirmed `UNION SELECT`
adds latency and adds a chance of being wrong about something already certain.)

---

## 4. Walking one request through the system

Here is `POST /api/users/1837/profile` arriving at the gateway. Follow
`src/gateway/main.py:226`.

**Step 1 — Read the body, but with a cap.**
`await request.body()` is unbounded. One large POST could pin the whole payload
in memory. We stream it and abort at 1 MiB (`read_body_capped`), returning 413.

**Step 2 — Identify the client.**
Who is this? By default we use the raw socket address, **not** `X-Forwarded-For`,
because XFF is client-controlled — anyone can set it and make every per-IP
control spoofable. We only read XFF when the operator explicitly declares how
many trusted proxy hops we sit behind.

**Step 3 — Update rate state in Redis.**
One pipelined round trip gives us three numbers: requests in the last 60s
(sustained abuse), requests in the last 5s (bursts a long window hides), and how
many *distinct endpoints* this client has touched (scanning).

**Step 4 — Build a canonical event.**
Method, path, query, first 64 KiB of body, content-type, the three rate counters.
This dict is the unit everything downstream consumes.

**Step 5 — Detect** (`gateway/detector.py:125`), run in a threadpool so the CPU
work of the tree ensemble does not block the async event loop for other
in-flight requests.

**Step 6 — Block or forward.** If blocked: 403 with the layer and reason. If
allowed: strip hop-by-hop headers, add `X-Forwarded-For` / `X-Guard-Request-Id`,
forward to the backend over a pooled HTTP client, relay the response.

**Step 7 — Log asynchronously.** The event goes on a queue; a background task
batches 50 records and appends them to `data/events.jsonl`. Disk latency never
appears in the client's response time. **What gets logged is the 34-number
feature vector and a hashed client ID — never the raw body.** So a password
typed into a login form cannot leak through the security log.

---

## 5. Layer 0 — Normalization

**File:** `src/common/normalize.py`

Signature matching is only as good as the normalization in front of it.
Attackers defeat naive regexes with encoding tricks:

| Trick | Example |
|---|---|
| Percent-encoding | `%2E%2E%2F` instead of `../` |
| Double-encoding | `%252E%252E%252F` |
| HTML entities | `&lt;script&gt;` |
| Unicode confusables | fullwidth `／` instead of `/` |
| Null-byte injection | `admin%00.jpg` |
| Mixed case | `UnIoN sElEcT` |

So before *any* rule runs, we collapse everything to one canonical form:

```python
s = url_decode_loop(s)               # percent-decode up to 4 times
s = html.unescape(s)                 # &lt; → <
s = unicodedata.normalize("NFKC", s) # fullwidth → ASCII
s = strip_control_chars(s)           # kill null bytes
s = collapse_whitespace(s).lower()   # case-fold
```

**Order matters and it is easy to get wrong.** You must decode *before* folding.
If you case-fold first, `%2E%2E%2F` is still `%2E%2E%2F` and your traversal rule
misses it entirely.

We also derive **`decode_delta`** here — how much shorter a string got when
decoded, as a ratio. Legitimate traffic carries a little encoding (spaces,
Unicode in names). Heavy nested encoding is an obfuscation signal. Rather than
block on it, we hand it to the model as a feature.

And **`path_template()`**: `/api/users/1837` → `/api/users/{id}`. This collapses
concrete paths into endpoint shapes. Crucially, **the template is never a model
feature** — more on why in §7.

---

## 6. Layer 1 — Rules and rate limiting

### 6a. Signature rules

**File:** `src/common/rules.py` — **26 rules, 22 BLOCK + 4 FLAG**, across 8
categories: `sqli`, `xss`, `traversal`, `cmdi`, `ssti`, `ssrf`, `deser`, `scan`.

Three design rules govern this file, and each one is an interview answer:

**1. BLOCK is reserved for things a legitimate client would essentially never
send.** Anything weaker is FLAG, which does *not* block — it becomes evidence the
ML layer weighs. This is the whole reason our L1 false-positive count is zero.

**2. Patterns match structure, not characters.** The previous version keyed on a
bare `'` and on `--`. That fires on `O'Brien` and on any hyphenated text. That is
precisely how WAFs earn their reputation for blocking real users. Compare:

```python
# BAD  — matches any apostrophe
r"'"

# GOOD — matches a boolean tautology terminated by a comment or paren
r"['\"\s(]\s*(?:or|and)\s+['\"]?[\w]+['\"]?\s*=\s*['\"]?[\w]+['\"]?\s*(?:--|#|/\*|$|\))"
```

**3. Everything matches the normalized form**, so all the encoding variants
collapse onto one signature.

The test suite asserts **both directions**: known attacks must hit, *and* a
corpus of awkward-but-legitimate requests (`?q=admin`, `?q=100%`, `O'Brien`,
`category=home appliances`) must not.

### 6b. Rate limiting

**File:** `src/gateway/ratelimit.py`

Three signals per client, one pipelined Redis round trip:

| Signal | Storage | Default limit | Catches |
|---|---|---|---|
| **Window** | sorted set, 60s | 240 req/min | sustained abuse |
| **Burst** | sorted set, 5s | 40 req/5s | spikes a long window hides |
| **Spread** | HyperLogLog | (feature only) | scanning / enumeration |

Two implementation details worth mentioning in an interview:

- **HyperLogLog for endpoint breadth.** A scanner might touch 10,000 distinct
  paths. A set would grow with them. HLL gives approximate cardinality in O(1)
  memory — which is exactly the property that makes the signal usable under
  attack.
- **Unique member per request.** We key the sorted-set member on
  `timestamp:id:perf_counter_ns`, not a bare timestamp. Bare timestamps collide
  under concurrency, so the counter silently under-counts *exactly when load is
  highest* — the worst possible time for a rate limiter to be wrong.

**Redis outage → degrade, don't die.** If Redis is unreachable, we return
`degraded=True`, lose the rate signal, and keep serving. The signature and model
layers still apply.

---

## 7. The features: how a request becomes 34 numbers

**File:** `src/common/features.py`

This is the most important file in the project, and the design constraint behind
it is the single best story to tell in an interview.

### The mistake we made first

The original pipeline one-hot encoded the HTTP path. The model learned
`path == /wp-admin → attack`. On paper it scored beautifully. In reality it had
become a **lookup table of one backend's URL vocabulary**:

- It could not transfer to a different backend — different URLs, model useless.
- It could not flag an attack aimed at a path that looked benign in training.

Both are fatal for a product whose selling points are "works in front of any
backend" and "catches zero-days". **That failure is why every feature is
shape-only.**

### The 34 features

Each measures *shape*, *statistics* or *behaviour* — things that mean the same
on any HTTP API:

| Group | Count | Examples |
|---|---|---|
| **Body shape** | 9 | `body_entropy`, `body_special_ratio`, `body_size_z`, `ct_json` |
| **Path shape** | 11 | `path_len`, `path_depth`, `path_entropy`, `path_decode_delta`, `path_known` |
| **Query shape** | 5 | `q_param_count`, `q_max_val_len`, `q_special_ratio`, `q_decode_delta` |
| **Behaviour** | 1 | `win_distinct_paths` |
| **Method** | 7 | `m_get`, `m_post`, …, `is_write` |
| **L1 evidence** | 1 | `n_flags` (count of FLAG-severity rule hits) |

`body_entropy` is Shannon entropy in bits per character — random, encoded or
compressed payloads score high; natural language and JSON score low.

### Three things we deliberately removed

These deletions are as important as the features that stayed.

**1. Header features (`header_count`, `ua_len`, `ua_entropy`, `has_ua`,
`has_referer`, `has_auth`) — removed.** Two independent arguments, either
sufficient:

- **Security.** Every one is client-controlled. An attacker copies a browser
  User-Agent and adds a Referer for free. Any accuracy gained evaporates against
  an adversary who spends ten seconds on evasion. Detection must rest on what a
  request *does*, not on how it introduces itself.
- **False positives.** They were the dominant cause, measurably. `header_count`
  got contaminated by our own traffic generator's headers (training sd 1.16, so a
  normal 4-header client sat 2.75σ out). A legitimate multi-client load measured
  **36.7% false positives** with these present.

**2. Rate magnitude (`win_log_count`, `burst_log_count`, `rate_z`) — removed.**
This one is subtle. Rate magnitude is **Layer 1's job**. When the autoencoder
*also* saw raw rate, it learned the rate distribution that happened to be in the
corpus (~9 req/min) and then rejected anything faster. So an operator who
configured 240 req/min silently got an effective limit near 20 — legitimate fast
clients blocked at **38%**, while the held-out test FPR still read a comfortable
1.3%. Two layers were enforcing contradictory policies.

The clean split: **L1 decides how fast is too fast** (explicit operator policy).
**L2/L3 decide whether the request looks wrong.** **L4 combines them.**

`win_distinct_paths` is kept, because *breadth* is a behaviour signal (scanning,
enumeration), not a volume signal — and it is what makes `exfil` and `scan`
detectable at all.

**3. Endpoint identity — removed**, as above.

### The Baseline: what makes portability work

Three features are defined *relative to a per-deployment baseline*:
`body_size_z` (how far this body size is from normal for this endpoint),
`path_known` (have we seen this endpoint before), and the rate statistics.

The `Baseline` object holds "what normal looks like **for this particular
backend**". The model consumes **deviations from the baseline, not raw
magnitudes** — which is exactly what lets one trained model serve a backend it
has never seen. Point it at a new API, run `calibrate.py`, and the same model
works. **Portability by calibration, not retraining.**

---

## 8. Layer 2 — Isolation Forest

**What it is:** an ensemble of 300 random trees (Liu et al., ICDM 2008). Each
tree recursively splits the data on a random feature at a random value. Anomalies
get isolated in **fewer splits** than normal points, because they sit alone in
sparse regions. The anomaly score is the average path length to isolate a point.

**Why it fits here:** it is unsupervised — it needs no attack labels — it is fast
at inference, and it handles the "attacks are rare and weird" shape of the
problem natively.

**Crucial detail: it is fitted on the `base` pool only, which contains *normal
rows only*.** The forest has never seen an attack. This is not a limitation; it
is the design. See §12.

---

## 9. Layer 3 — Autoencoder

**File:** `src/common/autoencoder.py` — **34 → 32 → 16 → 32 → 34**, dense,
ReLU, linear output, trained with Adam and early stopping. Written in **pure
NumPy**.

**How it detects anomalies:** an autoencoder learns to compress its input through
a narrow bottleneck and reconstruct it. Trained on normal traffic only, it gets
good at rebuilding normal traffic and bad at rebuilding anything else. **The
reconstruction error is the anomaly score.** No attack labels needed — this is
what gives the layer its zero-day property.

**Why NumPy and not PyTorch:** the old `requirements.txt` pulled in torch (~2 GB)
and then never imported it — the model was already NumPy. For a 34-dimensional
input and a 3-layer encoder/decoder, NumPy loads faster, has no CUDA/DLL surface,
and keeps the gateway image small. Nothing about the method is compromised: this
is still mini-batch backpropagation with Adam.

**Why it's a *denoising* autoencoder (the `noise` parameter):** this is a good
interview story. A plain autoencoder trained on normal-only traffic memorises the
*exact values* it saw. Several features are near-constant in any synthetic corpus
— `body_upper_ratio` had mean 0.0004, sd 0.0033. So a real request that merely
**capitalises a name** lands many sigma out, reconstructs badly, and gets
blocked. That produced a **38% false-positive rate** on legitimate traffic while
the held-out test FPR still read 1.3%, because the test split shared the training
corpus's quirks.

Corrupting the input with Gaussian noise during training forces the network to
learn **the shape of the normal manifold rather than its exact coordinates**.
Small benign deviations stop exploding the error. Attacks, which are far
off-manifold, still do.

(Hyperparameter search later settled on `noise=0.0` for the current feature set —
but the mechanism and the reasoning are why the knob exists.)

---

## 10. Layer 4 — The meta-learner

**This is the only component that decides.**

It takes exactly three inputs:

| Input | Source | Meaning |
|---|---|---|
| `rate` | L1 | `max(window/limit, burst/burst_limit)`, clipped to [0,1] |
| `isolation_forest` | L2 | forest score, min-max normalised using bounds saved at training |
| `autoencoder` | L3 | reconstruction error, normalised the same way |

Output: one probability. `p >= threshold` → block.

Two model choices are supported via `TRAIN_META`: `lr` (logistic regression) and
`hgb` (HistGradientBoosting). **`hgb` is the current default** — it lifted F1
from 0.854 to 0.957 and zero-day recall from 0.598 to 0.794, because the boundary
between the three scores is not linear.

**Why stack at all?** Because the base detectors disagree in useful ways. Measured
on identical test rows under the same 1% FPR budget:

| Model alone | F1 | Recall |
|---|---|---|
| L1 rate only | 0.515 | 0.349 |
| L2 Isolation Forest only | 0.406 | 0.264 |
| L3 Autoencoder only | 0.870 | 0.780 |
| **L4 stack** | **0.991** | **1.000** |

Every pairwise gap is significant under **McNemar's test** (p < 1e-34). That test
is the right one because it compares two classifiers on the *same* rows and uses
only the disagreements — which is why `compare.py` goes to the trouble of
rebuilding all four models over one shared split.

**A note on "fail closed".** Feature extraction and inference run on
attacker-controlled input. If something raises, failing *open* is an exploitable
bypass: find whatever crashes the extractor and you are waved through. So
`GUARD_FAIL_CLOSED=true` is the default and an inference error blocks the request.

---

## 11. Where the training data came from

**File:** `src/traffic_simulator/generate.py` (510 lines)

There is no public dataset of labelled HTTP traffic against a modern JSON API, so
we generated one against our own demo backend (`src/backend/main.py`, a FastAPI
e-commerce API with 15 endpoints: login, register, products, orders, search,
comments).

**The corpus: 14,960 requests across 1,061 client sessions.**

| Label | Count |
|---|---|
| normal | 9,224 |
| attack:flood | 1,981 |
| attack:exfil | 1,669 |
| attack:bruteforce | 1,419 |
| attack:scan | 314 |
| attack:sqli | 80 |
| attack:xss | 61 |
| attack:traversal | 48 |
| attack:cmdi | 37 |
| attack:payload | 19 |
| attack:ssti | 13 |

Normal traffic is generated from four behavioural profiles — human browsing, SPA
dashboard, backend integration, and poller — so "normal" is not one shape.

**How labels get attached:** the simulator sets an `X-Ground-Truth` header, and
lab mode sets `GUARD_TRUST_LABEL_HEADER=true` so the gateway records it. **This is
a training-data poisoning channel and must never be on in production** — anyone
who can set that header can hand-label the corpus your next model trains on. It
is off by default and the gateway strips the header before forwarding.

---

## 12. How training actually works

**File:** `src/ml_pipeline/train.py` (601 lines)

### The train/serve symmetry invariant

`common/` is imported by **both** the gateway and the trainer, specifically so
features cannot drift between fitting and serving. There is exactly one copy of
`extract()`.

This is enforced at load time: `detector.load()` refuses to load a model whose
saved `feature_names` differ from `common.features.FEATURE_NAMES`. A silent
feature-order mismatch produces a model that is **confidently wrong on every
request**, so the gateway simply will not start.

### The four pools

Rows are split by **client session**, not by row. `pool_of()` hashes
`client|SEED` into four buckets:

| Pool | Share | Contents | Purpose |
|---|---|---|---|
| `base` | 45% | **normal rows only** | fit scaler, forest, autoencoder |
| `meta` | 25% | known families only | train the L4 meta-learner |
| `val` | 15% | known families only | pick the threshold |
| `test` | 15% | **everything, incl. novel families** | read once, at the end |

**Why session-level and not row-level:** a random row split lets near-identical
requests from one session straddle the boundary. The model then "predicts" rows
it has effectively already seen, and every metric inflates.

**Why the base detectors see only `base`:** because `base` is disjoint from
`meta`, the L2/L3 scores fed to the meta-learner are **out-of-sample by
construction**. That is the elegant bit — it is why there is no k-fold OOF
stacking machinery in this codebase. The pool structure gives you for free what
cross-validation would otherwise cost.

### The eight training stages

```
[1/8] load + label + L1-annotate every row
[2/8] partition L1-blocked rows out of the ML path
[3/8] session-grouped pools, novel families withheld from meta/val
[4/8] derive the calibration baseline from `base`, recompute baseline features
[5/8] fit scaler → Isolation Forest → autoencoder on `base` only
[6/8] build 3-column meta-features, train L4 on `meta`
[7/8] pick the threshold on `val` under the FPR budget
[8/8] read `test` once; write artefacts + decision.json
```

### Two guards that exist because they were learned the hard way

**The train/serve skew fix (stage 4).** `body_size_z` and `path_known` are
defined against a calibration baseline that **did not exist while the corpus was
being captured** — so the gateway logged them as constant 0. Training on those
constants teaches the autoencoder "this is always zero". Then in production,
where the baseline *does* exist and the values vary, every ordinary request
produces a huge reconstruction error and gets blocked. **This actually happened**
— legitimate traffic scored autoencoder = 1.0 on the first enforcement run. So
`apply_baseline()` recomputes them from a baseline derived *only* from `base`.

**The zero-variance guard (stage 5).** A feature constant in training but varying
in production is the single most damaging failure mode for this design. sklearn's
scaler sets `scale_ = 1` when variance is 0, the autoencoder learns to emit
exactly that constant, and the first live request carrying any other value is
blocked. It has bitten this pipeline **twice** — once via the baseline features,
once via `path_dot_count` — so `train.py` now fails loudly on any feature with
sd < 0.01 in the training pool.

### Everything is env-configurable

`TRAIN_SEED`, `TRAIN_EVENT_LOG`, `TRAIN_NOVEL`, `TRAIN_AE_NOISE`,
`TRAIN_AE_HIDDEN`, `TRAIN_AE_BOTTLENECK`, `TRAIN_IF_TREES`, `TRAIN_META`,
`MODELS_DIR`. This is what lets `validate.py` and `tune.py` drive `train.py` as a
subprocess.

---

## 13. How we evaluated it honestly

This section is the part that separates a student project from a defensible one,
and it is where an interviewer will probe hardest.

### Zero-day recall is a real measurement

Three attack families — **`cmdi`, `exfil`, `ssti`** — are withheld from `meta`
and `val` entirely and appear **only in `test`**. So when we report zero-day
recall, we are genuinely measuring "attacks the model never saw during any part
of fitting or tuning". That is not a proxy. That is the thing.

### The threshold is picked under a false-positive budget

A gateway that blocks 5% of real users is unusable regardless of its recall. So
the operator-facing knob is `CALIBRATION_TARGET_FPR` (1%), and the threshold is
the F1-maximising point *subject to that ceiling*, chosen on `val`.

**Every baseline in `compare.py` gets the same budget.** Otherwise the comparison
just rewards whichever model was allowed to be loosest.

### `test` is read exactly once

At the end. No peeking, no iterating against it.

### L1-blocked rows are excluded from the ML stages

In production a request killed by a signature rule never reaches a model. Training
on those rows and then reporting the *model's* recall on them measures a decision
path that never executes. They are excluded, then re-attached for the end-to-end
number.

### Single-seed metrics are not reportable

The seed changes the session→pool assignment, the forest's sampling and the
network's initialisation. A single-run F1 quoted to four decimals implies
precision the experiment does not have.

`validate.py` retrains the entire pipeline under 10 seeds and reports a
**bootstrap percentile interval** over the seed means — not mean ± 1.96σ, because
with n=10 the normal approximation is doing more work than the data supports.

**This is the honesty point, and it is worth saying out loud in an interview:**
our best single seed (42) reaches F1 0.991 and *perfect* recall. We do not report
that as the result. **The interval is the result.**

### Hyperparameter search is kept separate from the reported numbers

`tune.py` maintains two separations so its output stays quotable:

1. It searches on **seeds 11–15** while `validate.py` reports on **seeds 1–10** —
   different seeds mean different session partitions.
2. It rotates `TRAIN_NOVEL` to a *different* family triple, so the real zero-day
   families never inform a hyperparameter choice.

It also writes to `models_tuning/` so a few hundred throwaway retrains cannot
clobber the live artefacts. (`validate.py` writes to `models_validate/` for the
same reason — it originally did not, and the shipped model silently became
whichever seed ran last.)

---

## 14. The results

### Layer 1 — deterministic

| | Result |
|---|---|
| Attack patterns blocked | 31 / 31 |
| False positives | 0 of 1,200 legitimate requests |

### Layers 2–4 — the learned ensemble

| Metric | Seed 42 | **10 seeds (95% CI)** |
|---|---|---|
| Precision | 0.9828 | **0.986 [0.982 – 0.990]** |
| Recall | 1.0000 | **0.931 [0.900 – 0.964]** |
| F1 | 0.9913 | **0.957 [0.940 – 0.976]** |
| ROC-AUC | 0.9991 | **0.989 [0.972 – 0.999]** |
| PR-AUC | 0.9982 | **0.989 [0.973 – 0.998]** |
| False positive rate | 0.0094 | **0.0069 [0.005 – 0.009]** |
| **Zero-day recall** | 1.0000 | **0.794 [0.668 – 0.914]** |

**Quote the right-hand column.** Seed 42 is the best of the ten runs.

### Latency

Measured single-threaded over 2,000 iterations after warm-up.

| Stage | Mean | p50 | p95 |
|---|---|---|---|
| L1 block (short-circuit) | **47 µs** | 48 µs | 57 µs |
| Isolation Forest (300 trees) | 3.37 ms | 3.20 ms | 4.33 ms |
| Autoencoder | 30 µs | 25 µs | 57 µs |
| Meta-learner (HGB) | 1.44 ms | 1.30 ms | 2.11 ms |
| **Full ML path** | **5.43 ms** | 5.06 ms | 7.48 ms |

Two observations worth having ready, because they are counter-intuitive and an
interviewer will enjoy them:

- **The strongest detector is the cheapest.** The autoencoder — best single
  model at F1 0.870 — costs 30 µs. The Isolation Forest is the *weakest*
  detector and eats **62% of the latency budget**.
- **The meta-learner upgrade cost 30×.** HGB is 1.44 ms against 46 µs for
  logistic regression. We took that trade for the accuracy, but it is a trade,
  and on a latency-critical deployment you would reconsider it.
- **Because L1 short-circuits, cost depends on traffic mix.** An SQL injection is
  rejected **115× faster** than a benign request is cleared. The attacker pays
  less than the legitimate user — and the system spends its budget only where the
  decision is genuinely uncertain.

---

## 15. Deployment and operations

```bash
cd src
docker compose up -d          # gateway on :5000
curl http://localhost:5000/__guard/health
```

Only port 5000 is published. The backend and Redis sit on an internal Docker
network, unreachable from the host — **so the gateway cannot be bypassed.**

### Three enforcement modes

| Mode | L1 rules & rate | L4 ensemble |
|---|---|---|
| `monitor` | logs only | logs only |
| **`enforce-l1`** *(default)* | **blocks** | logs only |
| `enforce` | blocks | blocks |

**Why `enforce-l1` is the default, and why that is not a hedge:** L1's signatures
and rate limits are deterministic. They mean the same thing on every backend and
measured zero false positives. The unsupervised layers are only as good as the
traffic they were trained on, and a model trained on synthetic traffic mis-scores
a real client population — measured at 14% false positives even after threshold
calibration.

So: **enforce what is certain, observe what is learned**, and promote to full
`enforce` only after retraining on the deployment's own captured traffic.

### Adapting to a new backend

`calibrate.py` re-derives the statistical baseline and the threshold from the new
deployment's traffic. It **deliberately does not retrain** the forest or the
network — two reasons:

- **Catastrophic forgetting**: incrementally refitting on a narrow slice of new
  traffic destroys what the model learned about the rest.
- **Poisoning**: if an attacker can influence the traffic you auto-retrain on,
  they can teach the model that their attack is normal.

### Admin endpoints

`GET /__guard/health` · `GET /__guard/stats` · `POST /__guard/reload` (hot-reload
models after retraining, no restart). Namespaced under `/__guard` so they cannot
shadow a backend route.

---

## 16. Security decisions worth defending

Each of these is a small decision with a real attack behind it.

| Decision | The attack it stops |
|---|---|
| Don't trust `X-Forwarded-For` by default | Spoof one header, defeat every per-IP control |
| Fail **closed** on inference error | Find what crashes the extractor, get waved through |
| Body cap at 1 MiB, streamed | One big POST pins memory |
| Never log raw bodies | Passwords leaking into the security log |
| Hash client IDs (SHA-256, 16 hex) | PII in an append-only log |
| Strip `x-ground-truth` before forwarding | Label header reaching the backend |
| `GUARD_TRUST_LABEL_HEADER=false` in prod | Training-data poisoning |
| Strip hop-by-hop headers both ways | Request smuggling / duplicated headers |
| Log queue sheds on overflow | **Shed logging before shedding traffic** |
| Only port 5000 published | Bypassing the gateway entirely |
| Admin routes namespaced `/__guard` | Shadowing a real backend route |

---

## 17. Things that went wrong and what we learned

Interviewers like this section more than the results table. All four are real.

**1. The model became a lookup table.** One-hot encoding the path gave great
metrics and zero generalisation. → Every feature is now shape-only.

**2. 38% false positives in production, 1.3% on the test set.** The test split
shared the training corpus's quirks, so it could not see the problem. Two causes:
near-constant features exploding on tiny benign deviations, and the autoencoder
learning the corpus's rate distribution. → Denoising autoencoder, header features
deleted, rate magnitude moved to L1 only.

**3. The gateway blocked all legitimate traffic on the first enforcement run.**
Baseline-relative features were logged as constant 0 during capture, so the
autoencoder learned "always zero". → `apply_baseline()` recomputes them; the
zero-variance guard now fails the build.

**4. The shipped model was silently the wrong one.** `validate.py` drove
`train.py` with only `TRAIN_SEED` overridden, so all ten seeds wrote into
`models/` and the committed artefacts were whichever seed ran last (seed 10, not
the canonical 42). → Both drivers now pass an isolated `MODELS_DIR`.

**The common thread:** every one of these was invisible in the metrics and only
showed up in behaviour. That is why the pipeline now has *guards* — the
zero-variance check, the feature-contract check, the FPR budget — rather than
just tests.

---

## 18. Known limitations

Say these before you are asked. It reads as confidence, not weakness.

- **The corpus is synthetic.** Generated against our own demo backend. Real
  traffic is messier, and §15 exists precisely because the gap is measurable.
- **Zero-day recall has a wide interval** — 0.794 [0.668, 0.914]. With only three
  withheld families, one family going badly moves the number a lot.
- **`enforce` is not the default**, and honestly so.
- **Throughput is unmeasured.** All latency numbers were taken at concurrency
  one. 5.4 ms of CPU-bound detection *implies* a ceiling near 185 req/s per core,
  but we have not load-tested and report no measured tail latency under
  contention. Say "implies", not "achieves".
- **Backend portability is a design property, not an experimental result.** The
  calibration path is built and reasoned through; we have not calibrated against
  an independently developed backend.
- **Redis is a dependency** for rate limiting. Without it the gateway degrades.
- **Stateless per-request inspection.** No cross-request correlation beyond the
  rate counters — a slow, distributed attack under the rate limit is out of scope.
- **HTTP only.** No gRPC, no WebSocket.

---

## 19. Repo map

```
src/
├── common/              ← imported by BOTH gateway and trainer (no drift)
│   ├── normalize.py         decode / fold / strip, path templating
│   ├── rules.py             26 signature rules
│   ├── features.py          the 34 features + Baseline    ← the important one
│   ├── autoencoder.py       NumPy dense AE
│   └── config.py            all env knobs
├── gateway/
│   ├── main.py              FastAPI reverse proxy, async logging
│   ├── detector.py          the 4-layer pipeline
│   └── ratelimit.py         Redis sliding windows + HLL
├── ml_pipeline/
│   ├── train.py             8-stage training  → models/
│   ├── tune.py              hyperparameter search (seeds 11–15)
│   ├── validate.py          10-seed bootstrap CIs
│   ├── compare.py           baselines + McNemar over one shared split
│   └── calibrate.py         adapt to a new backend without retraining
├── backend/main.py      demo FastAPI e-commerce API (15 endpoints)
├── traffic_simulator/   corpus generator, 4 normal profiles + 10 attack families
└── tests/               102 pytest tests
```

**Working-directory trap:** every script does `sys.path.insert(0, <src>)` and
expects **`src/` as the working directory**. Run `python ml_pipeline/train.py`
from `src/`, never `cd ml_pipeline && python train.py`.

**Corpus trap:** `config.EVENT_LOG` points at `data/events.jsonl`, the gateway's
**live, unlabelled** log. Training on it silently yields zero labelled rows. The
labelled corpus is `data/events_training.jsonl`, reached via `TRAIN_EVENT_LOG`.

```bash
cd src
TRAIN_EVENT_LOG=data/events_training.jsonl python ml_pipeline/train.py
```

---

## 20. Interview Q&A

### On the design

**Q: Why four layers instead of one good model?**
Cost should track certainty. A confirmed `UNION SELECT` does not need a neural
network's opinion — that adds latency and a chance of being wrong about something
already certain. 47 µs for the obvious, 5.4 ms for the ambiguous. It is also
defence in depth: the deterministic layer is explainable and has zero false
positives, so it can be enforced from day one while the learned layer is still
being trusted.

**Q: Why unsupervised base detectors when you have labels?**
Two reasons. First, zero-days: a supervised model can only recognise attack
classes it saw. Training on normal-only means anything off-manifold is
suspicious, whether or not we have a name for it. Second, it is what makes the
meta-features out-of-sample for free — the base pool is disjoint from the meta
pool, so no k-fold stacking machinery is needed.

**Q: Isn't stacking overkill? The autoencoder alone gets F1 0.870.**
And the stack gets 0.991 on identical rows under the same FPR budget, with
McNemar p = 5.5e-35. The three detectors fail on different things: the forest is
good at odd feature combinations, the autoencoder at off-manifold payloads, the
rate score at volume. The gain is measured, not assumed.

**Q: Why HistGradientBoosting over logistic regression for L4?**
Empirically: F1 0.854 → 0.957, zero-day recall 0.598 → 0.794. The boundary
between the three scores is not linear — a high forest score means something
different depending on whether the autoencoder agrees. `TRAIN_META=lr` still
works if someone wants the simpler model.

**Q: Why NumPy instead of PyTorch?**
The old requirements pulled in ~2 GB of torch that was never imported. For 34
inputs and a 3-layer encoder/decoder it is unnecessary: NumPy loads faster, has no
CUDA/DLL surface, and keeps the container small. It is still mini-batch
backpropagation with Adam and early stopping.

### On the evaluation

**Q: How do you know you aren't leaking?**
Four defences. Sessions are the split unit, not rows. Base detectors see only the
base pool. The threshold comes from `val`, never `test`. And `test` is read once,
at the end. The session split matters most — near-identical requests from one
session straddling the boundary is the classic way this problem inflates.

**Q: Your zero-day recall is 79% with a huge interval. Isn't that weak?**
It is honest. Three families are withheld from every fitting and tuning step and
appear only at test, so it measures the real thing rather than a proxy. The
interval is wide because there are only three families — one going badly moves it
a lot. Our best seed hits 100% and we deliberately do not report that.

**Q: Why McNemar and not a t-test?**
McNemar compares two classifiers on the *same* rows and uses only the
disagreements, which is what makes it powerful here. A t-test across seeds would
be unpaired — different seeds mean different test splits entirely. That is
exactly why `compare.py` rebuilds all four models over one shared split rather
than reading four separate training runs.

**Q: Your data is synthetic. Doesn't that invalidate the results?**
It bounds them, and we say so. There is no public labelled corpus for a modern
JSON API. What it does *not* do is invalidate the protocol — the withheld
families, the session splits and the FPR budget are all real constraints. And we
found the synthetic-data gap ourselves: 1.3% test FPR versus 38% on real
multi-client traffic. That discovery drove three feature-set changes.

### On the engineering

**Q: What happens under load?**
Structurally it is built for it: model inference runs in a threadpool so CPU work
does not block the async event loop, logging is queued and batched off the request
path and sheds on overflow (we shed logging before we shed traffic), HTTP
connections are pooled, and Redis is one pipelined round trip per request. But be
straight about the limit — **we have not load-tested it.** All latency figures are
at concurrency one. 5.4 ms of CPU-bound work implies a ceiling around 185 req/s
per core; that is arithmetic, not a measurement, and the Isolation Forest at 62%
of the budget is the obvious first thing to profile.

**Q: What if Redis goes down?**
The gateway degrades rather than failing. Rate features go to zero, the state is
marked `degraded`, and signature plus model layers keep working. The alternative
— failing the gateway — would turn a cache outage into a full outage.

**Q: Why fail closed?**
Feature extraction runs on attacker-controlled input. Failing open means the
bypass is "find the input that crashes the extractor". It is configurable, but the
default has to be closed.

**Q: How do you deploy this to a new backend without retraining?**
Every feature is shape-based, and three are defined relative to a per-deployment
baseline. `calibrate.py` re-derives that baseline and the threshold from the new
deployment's traffic. It deliberately does not touch the forest or the network —
incremental refitting on a narrow slice causes catastrophic forgetting, and if an
attacker can influence what you auto-retrain on, they can teach you their attack
is normal.

**Q: What was the hardest bug?**
The gateway blocking all legitimate traffic on the first enforcement run. Three
features were logged as constant 0 during corpus capture because the baseline did
not exist yet, so the autoencoder learned "always zero" — then in production,
where they vary, every ordinary request had enormous reconstruction error. The
fix was recomputing them at training time from a base-pool-only baseline. The
lasting fix was the zero-variance guard, which now fails the build instead of
letting it be discovered from false positives.

**Q: What would you do next?**
Validate on a real corpus — CSIC 2010 is the obvious candidate. Widen the
zero-day evaluation beyond three families. And build the operator feedback loop:
right now promoting to full `enforce` requires manual retraining on captured
traffic, and that should be a guided workflow with a poisoning-resistant review
step.

---

## 21. Resume bullets

Pick two or three. Every number below traces to a file in this repo.

> **MicroAPI Guard — ML-based API Security Gateway** · Python, FastAPI, Redis,
> scikit-learn, NumPy, Docker
>
> - Built a backend-agnostic reverse-proxy security gateway with a four-layer
>   detection pipeline (signature rules + rate limiting → Isolation Forest →
>   denoising autoencoder → gradient-boosted meta-learner), blocking attacks
>   inline with **47 µs** on the deterministic path and **5.4 ms** on the full
>   stack.
> - Achieved **F1 0.957 [0.940–0.976]** at a **0.7% false-positive rate** across
>   10 random seeds, and **79% recall on three attack families withheld from all
>   training and tuning** — a genuine zero-day measurement.
> - Designed a leakage-resistant evaluation protocol (session-level splits, base
>   detectors trained on normal traffic only, threshold selected under a 1% FPR
>   budget, test set read once) and validated the ensemble against every single
>   -layer baseline with **McNemar's test (p < 1e-34)**.
> - Made the model portable across backends by using shape-only features with no
>   endpoint identity, so a new deployment needs **calibration, not retraining**.
> - Diagnosed and fixed a **38% false-positive rate** on live multi-client
>   traffic that the held-out test set reported as 1.3%, tracing it to train/serve
>   skew in baseline-relative features and to client-controlled header signals;
>   added zero-variance and feature-contract guards so the class of bug fails the
>   build instead of reaching production.

**When you say the results out loud, quote the confidence interval, not the best
seed.** If someone notices you did that unprompted, you have already won the
technical-honesty part of the interview.
