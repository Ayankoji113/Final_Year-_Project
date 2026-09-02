# MicroAPI Guard

**Real-Time API Anomaly Detection Using a Learned Stacking Ensemble**

A backend-agnostic API security gateway. It reverse-proxies any HTTP backend,
inspects every request through a four-layer detection pipeline, and blocks
malicious traffic inline — without requiring a single change to the protected
service.

```
client ──► MicroAPI Guard ──► your backend
                │
                ├── L1  signature rules + rate limiting   (deterministic)
                ├── L2  Isolation Forest                  (unsupervised)
                ├── L3  Autoencoder                       (unsupervised)
                └── L4  Logistic Regression meta-learner  ← makes the decision
```

## Table of Contents
- [About](#about)
- [Features](#features)
- [Results](#results)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Usage](#usage)
- [Security Posture](#security-posture)
- [Known Limitations](#known-limitations)
- [Project Status](#project-status)
- [License](#license)
- [Contact](#contact)

## About

With the widespread adoption of microservice architectures, REST APIs have
become primary targets for cyberattacks. Traditional mechanisms — WAFs and
static rate-limiters — catch only what they already have a signature for, and
often block legitimate traffic during spikes.

MicroAPI Guard combines both approaches. Deterministic rules handle what is
certain; unsupervised models trained only on normal traffic handle what no
signature anticipates. A logistic-regression meta-learner combines their scores
into the final decision.

## Features

- **Transparent reverse proxy** — independent of the backend's language,
  framework and routes.
- **Encoding-resistant normalization** — payloads are percent-decoded up to four
  times, HTML-entity decoded and Unicode NFKC-folded *before* any rule runs, so
  double-encoded attacks cannot slip past.
- **Layer 1 short-circuit** — a confirmed signature match or rate-limit breach
  is blocked immediately, without invoking any model.
- **Path-agnostic features** — the 34 model features measure request *shape* and
  client *behaviour*. None encodes endpoint identity, which is what allows the
  same model to sit in front of a different backend.
- **Privacy-preserving logging** — the event log stores a numeric feature vector
  and a hashed client id. Raw request bodies are never written to disk.
- **Graded enforcement** — `enforce-l1` (default), `enforce`, and `monitor`.

## Results

Measured on a held-out test set of client sessions never used for fitting or
threshold selection. Headline figures are means over **10 random seeds** with
bootstrap 95% confidence intervals.

### Layer 1 — deterministic

| | Result |
|---|---|
| Attack patterns blocked | 31 / 31 |
| False positives | 0 of 1,200 legitimate requests |
| Median detection latency | 10.96 ms |

### Layers 2–4 — learned stacking ensemble

| Metric | Single run | 10 seeds (95% CI) |
|---|---|---|
| Accuracy | 0.9520 | — |
| Precision | 0.9611 | 0.978 [0.970 – 0.985] |
| Recall | 0.8989 | 0.764 [0.700 – 0.828] |
| F1-Score | 0.9290 | 0.854 [0.812 – 0.891] |
| ROC-AUC | 0.9926 | 0.987 [0.980 – 0.993] |
| PR-AUC | 0.9863 | 0.978 [0.968 – 0.986] |
| False Positive Rate | 0.0195 | 0.0099 [0.006 – 0.015] |
| Zero-day recall | 0.8865 | 0.598 [0.445 – 0.749] |

Zero-day recall is measured by withholding three attack families
(`cmdi`, `ssti`, `exfil`) from training entirely and scoring them only at test.

### Does the ensemble earn its place?

Every model thresholded under the same 1% false-positive budget, on identical
test rows:

| Model | F1 | Recall | McNemar vs. stack |
|---|---|---|---|
| L1 rate only | 0.515 | 0.349 | stack better, p = 2.9e-70 |
| L2 Isolation Forest only | 0.406 | 0.264 | stack better, p = 3.1e-96 |
| L3 Autoencoder only | 0.870 | 0.780 | stack better, p = 8.4e-12 |
| **L4 stack** | **0.929** | **0.899** | — |

## Tech Stack

- **Gateway:** Python 3.11, FastAPI, Uvicorn, HTTPX
- **State:** Redis (asyncio, sorted sets + HyperLogLog)
- **ML:** scikit-learn (Isolation Forest, Logistic Regression), NumPy
- **Deep learning:** dense denoising-capable autoencoder implemented in NumPy —
  no PyTorch dependency; the network is 34→32→12→32→34 trained with Adam and
  early stopping
- **Traffic generation:** Python standard library only (no Locust required)
- **Containerisation:** Docker & Docker Compose
- **Testing:** pytest (92 tests)

## Architecture

1. **Normalization** — decode, fold, strip.
2. **L1 signature rules** — 26 patterns (SQLi, XSS, path traversal, command
   injection, SSRF, scanners). `BLOCK` severity short-circuits; `FLAG` severity
   becomes evidence for the model.
3. **L1 rate limiting** — Redis sliding window, 240 req/min and 40 req/5 s per
   client, plus endpoint-breadth tracking for scan detection.
4. **Feature extraction** — 34 behavioural features.
5. **L2 Isolation Forest** and **L3 Autoencoder** — both fitted on normal
   traffic only, so neither needs attack labels.
6. **L4 Logistic Regression** — combines the rate, forest and autoencoder scores
   into the final probability. This is the only component that decides.
7. **Logging** — asynchronous, numeric-only.

## Getting Started

### Prerequisites
- Docker & Docker Compose (recommended)
- Python 3.11+ if running components directly

### Quick start

```bash
cd src
docker compose up -d
curl http://localhost:5000/__guard/health
```

Only port **5000** is published. The backend and Redis sit on an internal
network and are deliberately unreachable from the host, so the gateway cannot
be bypassed.

### Full pipeline from scratch

```bash
cd src

# 1. Lab mode: monitor only; trusts X-Forwarded-For and the label header
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d

# 2. Generate a labelled corpus (~5 min)
python traffic_simulator/generate.py --sessions 2600 --attack-ratio 0.32

# 3. Train
python ml_pipeline/train.py

# 4. Back to enforcing
docker compose down && docker compose up -d

# 5. Verify
pytest tests/ -v
```

Optional analyses:

```bash
python ml_pipeline/validate.py --seeds 10   # confidence intervals
python ml_pipeline/compare.py               # baselines + McNemar
python ml_pipeline/calibrate.py             # adapt to a new backend
```

## Configuration

All settings are environment variables (see `src/common/config.py`).

| Variable | Default | Notes |
|---|---|---|
| `BACKEND_URL` | `http://127.0.0.1:8000` | upstream service |
| `REDIS_URL` | `redis://localhost:6379` | rate-limit state |
| `GUARD_MODE` | `enforce-l1` | `enforce-l1` \| `enforce` \| `monitor` |
| `GUARD_FAIL_CLOSED` | `true` | inference error ⇒ block |
| `GUARD_TRUSTED_PROXY_HOPS` | `0` | **0 = ignore `X-Forwarded-For`** |
| `GUARD_TRUST_LABEL_HEADER` | `false` | **lab only** — poisoning channel |
| `GUARD_MAX_BODY_BYTES` | `1048576` | hard body cap |
| `GUARD_RATE_LIMIT` | `240` | requests / 60 s / client |
| `GUARD_BURST_LIMIT` | `40` | requests / 5 s / client |

### Enforcement modes

| Mode | L1 rules & rate | L4 ensemble |
|---|---|---|
| `monitor` | logs only | logs only |
| **`enforce-l1`** *(default)* | **blocks** | logs only |
| `enforce` | blocks | blocks |

`enforce-l1` is the correct default for a new deployment: enforce what is
certain, observe what is learned. Promote to `enforce` only after retraining on
traffic captured from your own deployment.

## Usage

```bash
# normal request — allowed
curl -i "http://localhost:5000/api/products?page=1&limit=3"

# SQL injection — blocked at L1
curl -G --data-urlencode "q=' UNION SELECT password FROM users --" \
     http://localhost:5000/api/search

# double-encoded path traversal — still blocked
curl "http://localhost:5000/api/files/%252e%252e%252f%252e%252e%252fetc%252fpasswd"
```

A block returns HTTP 403 with the deciding layer and the reason:

```json
{"error": "Request blocked by MicroAPI Guard",
 "layer": "L1-rules",
 "reason": "sqli.union: UNION SELECT is never emitted by a legitimate API client",
 "categories": ["sqli"]}
```

### Putting it in front of a different backend

```bash
BACKEND_URL=http://my-service:3000 GUARD_MODE=monitor docker compose up -d
# ... let representative NORMAL traffic flow ...
python ml_pipeline/calibrate.py --target-fpr 0.01
curl -X POST http://localhost:5000/__guard/reload
```

Calibration re-derives the statistical baseline and decision threshold. It does
**not** retrain the models — see the header comment in `calibrate.py` for why
(catastrophic forgetting and poisoning surface).

### Admin endpoints

Namespaced under `/__guard` so they cannot shadow a backend route.

| Endpoint | Purpose |
|---|---|
| `GET /__guard/health` | mode, model state, calibration state, Redis |
| `GET /__guard/stats` | counters broken down by deciding layer |
| `POST /__guard/reload` | hot-reload models and baseline |

> These are unauthenticated. Put them behind network policy or an auth proxy
> before exposing the gateway publicly.

## Security Posture

- Only port 5000 is published; backend and Redis have no host mapping.
- Request bodies are **never** written to disk — the event log stores a numeric
  feature vector and a hashed client id, so credentials cannot leak through it.
- `X-Forwarded-For` is ignored unless the operator declares trusted hops.
- Inference failure on attacker-controlled input **fails closed**.
- Request bodies are capped at 1 MiB (streaming, returns 413).
- Model files are mounted read-only in production (pickles are executable).
- Containers run non-root with `no-new-privileges`.

## Known Limitations

Stated plainly, because they matter for how this should be deployed.

1. **The ML layers are not safe to enforce on synthetic training alone.** Against
   a legitimate traffic source different from the training generator, the
   ensemble produced a 24.65% false-positive rate, and threshold calibration
   aborts rather than fixing it — roughly 8% of that traffic saturates the
   anomaly score and is inseparable at any threshold. This is why `enforce-l1`
   is the default.
2. **Coverage is unstable across seeds.** Zero-day recall ranges from 0.219 to
   1.000 across 10 seeds. Precision, FPR and ROC-AUC are stable; recall is not.
3. **All evaluation uses synthetic traffic.** No validation against production
   traffic or a public benchmark (e.g. CSIC 2010) has been performed.
4. **Feature-space collapse.** Only ~15% of logged events produce distinct
   feature vectors, so identical vectors appear on both sides of the split and
   test metrics are somewhat optimistic.
5. **Admin endpoints are unauthenticated**, and `/__guard/reload` can swap the
   active model.
6. **Layer 1 has not been adversarially fuzzed** with dedicated WAF-bypass
   tooling.
7. **The <20 ms target holds at the median only** — 10.96 ms median detection,
   but p95 is 23.4 ms and p99 is 52.8 ms, measured on Docker Desktop for Windows
   with a single worker under concurrent load.

## Project Status

| Phase | Status |
|---|---|
| Infrastructure & gateway | Complete |
| Dataset generation | Complete — 35,496 labelled events |
| ML training & stacking ensemble | Complete — leakage-free, session-grouped splits |
| Real-time inference | Complete — deployed, `enforce-l1` |
| Statistical validation | Complete — 10-seed CIs, McNemar |
| Calibration | Implemented; refuses unsafe windows by design |
| Validation on real/public traffic | **Not done** |

### Repository layout

| Path | Purpose |
|---|---|
| `src/common/` | Shared detection core — imported by both gateway and trainer |
| `src/gateway/` | Reverse proxy, rate limiter, detection pipeline |
| `src/ml_pipeline/` | `train.py`, `calibrate.py`, `validate.py`, `compare.py` |
| `src/traffic_simulator/` | Labelled traffic generation |
| `src/tests/` | pytest suite (92 tests) |
| `src/legacy/` | Previous models/dataset, kept for before-and-after comparison |
| `docs/` | Design documents and the review script |

## License

Open-source, intended for academic and security research purposes.

## Contact

- **Maintainer:** @Ayankoji113
- **Project Link:** [https://github.com/Ayankoji113/Final_Year-_Project](https://github.com/Ayankoji113/Final_Year-_Project)
