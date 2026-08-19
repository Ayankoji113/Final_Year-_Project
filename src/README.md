# MicroAPI Guard — `src/`

A backend-agnostic API security gateway. It reverse-proxies any HTTP backend,
inspects every request through a four-layer detection pipeline, and blocks
malicious traffic inline.

```
client ──► MicroAPI Guard ──► your backend
                │
                ├── L1  signature rules + rate limiting   (deterministic)
                ├── L2  Isolation Forest                  (unsupervised)
                ├── L3  Autoencoder                       (unsupervised)
                └── L4  Logistic Regression meta-learner  ← makes the decision
```

## Layout

| Path | Purpose |
|---|---|
| `common/` | Shared detection core — imported by **both** the gateway and the trainer, so features cannot drift between training and serving |
| `common/normalize.py` | Decoding/normalization (defeats percent-, double-, entity- and unicode-encoding bypasses) |
| `common/rules.py` | Layer 1 signatures. `BLOCK` = certain, `FLAG` = evidence for the model |
| `common/features.py` | The 43 behavioural features. **Deliberately contains no endpoint identity** |
| `common/autoencoder.py` | Layer 3, NumPy implementation with Adam + early stopping |
| `gateway/` | FastAPI reverse proxy, rate limiter, detection pipeline |
| `ml_pipeline/train.py` | Training + evaluation |
| `ml_pipeline/calibrate.py` | Adapt a trained model to a new backend |
| `traffic_simulator/generate.py` | Labelled traffic generator |
| `dashboard/app.py` | Streamlit monitoring UI |
| `tests/` | pytest suite |
| `legacy/` | Previous models/dataset, kept for before-and-after comparison |

## Quick start

```bash
cd src
docker compose up -d          # gateway on :5000; backend and Redis stay internal
curl http://localhost:5000/__guard/health
```

The gateway refuses to start in `enforce` mode without trained models — a
misconfiguration that would silently advertise protection it cannot deliver.

## Full pipeline from scratch

```bash
# 1. lab mode: monitor only, trusts X-Forwarded-For and the label header
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d

# 2. generate a labelled corpus (~5 min)
python traffic_simulator/generate.py --sessions 2600 --attack-ratio 0.32

# 3. train (writes ml_pipeline/models/)
python ml_pipeline/train.py

# 4. back to enforcing
docker compose down && docker compose up -d

# 5. verify
pytest tests/ -v
```

Dashboard: `docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d dashboard`
→ http://localhost:8501

## Putting it in front of a different backend

Nothing in the gateway knows your routes. Point it at the new upstream and
calibrate:

```bash
BACKEND_URL=http://my-service:3000 GUARD_MODE=monitor docker compose up -d
# ... let representative NORMAL traffic flow ...
python ml_pipeline/calibrate.py --target-fpr 0.01
curl -X POST http://localhost:5000/__guard/reload
```

Calibration re-derives the statistical baseline and re-picks the threshold. It
does **not** retrain the neural network or the forest — see the header comment
in `calibrate.py` for why (catastrophic forgetting and poisoning surface).

## Configuration

All via environment variables (`common/config.py`).

| Variable | Default | Notes |
|---|---|---|
| `BACKEND_URL` | `http://127.0.0.1:8000` | upstream |
| `REDIS_URL` | `redis://localhost:6379` | rate-limit state |
| `GUARD_MODE` | `enforce` | `enforce` \| `monitor` |
| `GUARD_FAIL_CLOSED` | `true` | inference error ⇒ block |
| `GUARD_TRUSTED_PROXY_HOPS` | `0` | **0 = ignore `X-Forwarded-For`.** Raise only if a proxy you control writes it |
| `GUARD_TRUST_LABEL_HEADER` | `false` | **lab only** — a training-data poisoning channel |
| `GUARD_MAX_BODY_BYTES` | `1048576` | hard body cap |
| `GUARD_RATE_LIMIT` | `240` | requests / 60 s / client |
| `GUARD_BURST_LIMIT` | `40` | requests / 5 s / client |

## Security posture

- Only port 5000 is published. The backend and Redis have **no** host mapping,
  so the gateway cannot be bypassed.
- Request bodies are **never** written to disk. The event log stores a numeric
  feature vector plus a hashed client id, so login passwords cannot leak
  through it.
- `X-Forwarded-For` is ignored unless the operator declares trusted hops.
- Model files are mounted read-only in production (they are pickles, i.e.
  executable content).
- Containers run as non-root with `no-new-privileges`.

## Admin endpoints

Namespaced under `/__guard` so they cannot shadow a backend route.

| Endpoint | Purpose |
|---|---|
| `GET /__guard/health` | mode, model state, calibration state, Redis |
| `GET /__guard/stats` | counters broken down by deciding layer |
| `POST /__guard/reload` | hot-reload models and baseline |

> These are unauthenticated. Put them behind network policy or an auth proxy
> before exposing the gateway publicly — see Known Limitations in the audit
> report.
