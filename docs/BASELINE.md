# Baseline — shipped model against independent traffic

**Locked 2026-09-12.** Every later claim about improving the ML layer is measured against
this table. Reproduce it with the commands at the bottom before trusting any comparison.

## Why this file exists

`train.py` reports on pools drawn from the same generator that produced its training data.
The shipped model scores F1 0.9913 on its own held-out test pool. That number describes how
well it fits `generate.py`, not how it behaves on traffic it has never seen.

This baseline uses `traffic_simulator/validate_client.py`, a second client written from the
backend's API contract and sharing no code, no word list and no payload builder with the
generator. It is the closest thing available to real traffic.

## Result

622 requests through the live gateway in `enforce-l1`, 618 paired to log entries.

| Metric | Value |
| --- | ---: |
| Legitimate requests | 508 |
| Attack requests | 110 |
| **Layer 1 false positives** | **0 / 508 · 0.00%** |
| **ML false positives** (would block under `enforce`) | **341 / 508 · 67.13%** |
| Attacks blocked by Layer 1 | 19 / 110 · 17.3% |
| Attacks caught by ML that Layer 1 missed | 91 / 91 · 100.0% |
| Attacks missed by both | 0 |
| Precision / Recall / F1 on L1 survivors | 0.2106 / 1.0000 / 0.3480 |
| ROC-AUC / PR-AUC | 0.7391 / 0.2556 |
| Autoencoder saturated on benign rows | 167 / 508 · 32.9% |
| Detection latency p50 / p95 | 11.41 ms / 15.26 ms |
| Decision threshold | 0.2500 |

## Reading it honestly

**Layer 1 holds.** Zero false positives across 508 legitimate requests from a client it was
never tuned against, and it did that while blocking 19 attacks outright. This is the part of
the system that is genuinely production-ready.

**The ML false-positive rate is worse here than previously reported, and that is the point.**
Earlier ad-hoc measurements in this project gave 45.8% and 29.2%. Those used benign traffic I
wrote by hand, which unconsciously resembled the generator. 67.13% is what happens against a
source built independently. The harder test is the honest one, and every improvement from
here must be measured the same way or it is not an improvement.

**Recall is excellent and must not be lost.** ML caught every one of the 91 attacks Layer 1
missed — including the whole unsigned group that has no signature at all: NoSQL injection,
mass assignment, IDOR enumeration, business-logic abuse and oversized enumeration. That is
the case for ML enforcement, and the reason the answer is "fix the false positives" rather
than "abandon the ML layer".

**Per-endpoint is where the failure actually lives.** The aggregate hides it:

| Endpoint | ML false positives |
| --- | ---: |
| `/api/comments` | 33 / 33 · 100% |
| `/health` | 32 / 32 · 100% |
| `/api/users/login` | 21 / 21 · 100% |
| `/api/users/register` | 3 / 3 · 100% |
| `/api/search` | 27 / 29 · 93% |
| `/api/products` | 105 / 119 · 88% |
| `/api/orders` | 23 / 33 · 70% |
| `/api/users/{id}` | 4 / 9 · 44% |
| `/api/products/{id}` | 93 / 225 · 41% |

Four of thirteen "endpoints" pass the 1% gate, but all four are single-request
`/api/orders/<token>` paths, so in practice **no real endpoint qualifies yet**.

## Reproducing

```bash
cd src
docker compose up -d                       # gateway in enforce-l1

# 1. send the independent corpus (3 rps: GUARD_RATE_LIMIT is 240/min = 4 rps,
#    and a rate-blocked request never reaches the models)
python traffic_simulator/validate_client.py \
  --sessions 90 --attack-ratio 0.22 --seed 777 --out eval_corpus.json --send --rps 3

# 2. score it. Must run in the container: the host has scikit-learn 1.9.0 and
#    the models were pickled under the pinned 1.4.1.post1.
docker run --rm \
  -v "$PWD/data:/app/data:ro" -v "$PWD/ml_pipeline:/app/ml_pipeline" \
  -v "$PWD/eval_corpus.json:/app/corpus.json:ro" \
  --entrypoint python src-gateway /app/ml_pipeline/evaluate_live.py \
  --corpus /app/corpus.json --events /app/data/events.jsonl \
  --out /app/ml_pipeline/baseline_shipped.json
```

To compare a candidate model on identical traffic without re-sending anything, add
`--models /app/ml_pipeline/models_wide`. Re-scoring reconstructs the rate input as zero,
which makes those numbers slightly conservative on rate-driven attacks.

## Two measurement traps found while building this

**Pacing.** The first run used 3 rps... no: it used 6 rps, which is 360/min against a 240/min
limit. 352 of 632 requests were rate-blocked at Layer 1, never reached the models, and simply
vanished from the measurement rather than appearing as an error. The client now defaults to
3 rps and warns when more than 35% of responses are 403.

**Pairing.** The event log is append-only and shared across runs. Matching corpus rows to log
entries by `(method, template)` in order silently paired benign requests against leftovers
from a previous run, producing a confident "Layer 1 blocks 16.67% of legitimate traffic" for
requests Layer 1 had never touched. The client now records its send window into the corpus
manifest and the scorer filters the log by it.

Both were my own errors, not system defects, and both would have produced plausible-looking
numbers. That is the argument for anchoring the measurement rather than eyeballing it.
