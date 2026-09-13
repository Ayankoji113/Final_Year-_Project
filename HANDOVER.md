# MicroAPI Guard — Project Handover

**Written:** 2026-09-13
**Branch:** `feat/security-console-and-enforcement-audit` (not yet merged into `main`)
**Scope:** the whole project. The paper-only handover is `docs/HANDOVER.md`.

Read this file first. It says what works, what the real numbers are, and what is
still open. When another document disagrees with this one, the documents listed in
section 3 are the source of truth.

---

## 1. Get it running

### Clone (Windows: enable long paths first)

A reference PDF in `Paper/` has a 156-character name. On Windows the checkout fails
with `Filename too long` unless long paths are on:

```bash
git config --global core.longpaths true
git clone https://github.com/Ayankoji113/Final_Year-_Project.git
cd Final_Year-_Project
git checkout feat/security-console-and-enforcement-audit
```

### Start the gateway, backend and Redis

Needs Docker Desktop.

```bash
cd src
docker compose up -d
curl http://localhost:5000/__guard/health     # expect "status": "healthy"
```

Only port 5000 is published. The trained model is already in
`src/ml_pipeline/models/`, so nothing needs training to run the system.

### Start the security console

Needs Node.js 18 or newer.

```bash
cd frontend
npm install
npm run dev                                   # http://localhost:5173
```

### Send demo traffic so the console has something to show

```bash
cd src
python traffic_simulator/live_demo.py         # Ctrl-C to stop
```

It stays under the rate limit on purpose. Above 4 requests per second Layer 1
rate-limits everything and the console fills with rate blocks.

### Run the tests

```bash
cd src
pip install -r requirements-dev.txt
pytest tests/ -q
```

Expected on a normal laptop: **112 passed, 10 skipped, 15 errors**. The 15 errors
are a scikit-learn version mismatch: the model files were saved with 1.4.1.post1 and
most laptops have a newer version. They are not failures in the project. Anything
touching the model files must run inside the gateway container, which has the right
version.

Verified on a fresh clone of this branch on 2026-09-13: tests as above, console
build succeeds, Docker Compose config valid.

---

## 2. What the project is, in one paragraph

An API security gateway that sits in front of any HTTP backend. Every request passes
through four layers. **Layer 1** is 26 signature rules plus Redis rate limiting, and
it blocks. **Layers 2 and 3** are an Isolation Forest and a NumPy autoencoder, both
trained only on normal traffic. **Layer 4** is a gradient-boosted meta-learner that
combines their scores and makes the ML decision. By default (`GUARD_MODE=enforce-l1`)
Layer 1 blocks and the ML layers only record what they would have blocked.

---

## 3. The honest numbers

### Layer 1 blocks, and is safe

| Measured on independent traffic | Result |
| --- | ---: |
| Legitimate requests wrongly blocked | 0 of 508 · **0.00%** |

### ML detects, but is not yet safe to block with

The live model is `models_b4`, chosen on four independent traffic draws.

| | Previous model | **models_b4 (live)** |
| --- | ---: | ---: |
| Legitimate requests wrongly flagged | 61.3% | **17.0%** |
| ROC-AUC | 0.56 | **0.87** |
| Attacks caught that Layer 1 missed | 100% | **92.8%** |
| F1 | 0.32 | **0.58** |
| Endpoints under the 1% target | 5 of 13 | **7 of 13** |

**The project goal is ML blocking with under 1% false positives. It is not met.**
Do not switch to `GUARD_MODE=enforce`.

### Why the old F1 of 0.99 is not the real number

The README's Results section and `docs/HANDOVER.md` quote F1 0.957–0.991. Those were
measured on test data from the **same traffic generator** used for training. The
generator always called each endpoint the same way, so the model learned "this
endpoint is normally called with these parameters" instead of "this is an attack".
A bare `GET /api/products` scored 0.99 (attack) while `?page=2&limit=20` scored 0.0003.

On traffic from a second, independent client, that model was near chance. Fixing the
generator alone cut false positives from 44% to 14%. **This finding is now the main
contribution of the paper.** Quote the table above, not 0.99.

### Where each number comes from

| Document | What it holds |
| --- | --- |
| `src/ml_pipeline/models/MODEL_SELECTION.md` | why `models_b4`, its defects, how to reproduce and roll back |
| `src/ml_pipeline/model_selection*.json` | raw results for every compared model |
| `docs/BASELINE.md` | the locked baseline every later claim is measured against |
| `docs/CHANGES_SINCE_PULL.md` | every change since `8e14907`, with why and how |
| `docs/ZORO_1.0.md` | the audit on whether to enable ML blocking |
| `docs/feature_case.html` | the three attack types the features cannot see |
| `docs/project_log.html` | the full story in order, including hypotheses that were wrong |
| `manuscript/REFRAME_PLAN.md` | plan to rewrite the paper around the independent-traffic finding |

---

## 4. Where things are

| Path | What |
| --- | --- |
| `src/gateway/main.py` | the gateway: proxy, pipeline, admin endpoints |
| `src/gateway/detector.py` | runs Layers 2–4 |
| `src/gateway/enforcement.py` | decides whether an ML verdict actually blocks |
| `src/common/` | shared by gateway and trainer so features can never drift |
| `src/ml_pipeline/train.py` | training |
| `src/ml_pipeline/models/` | **the live model** |
| `src/ml_pipeline/models_*/` | every candidate from model selection, kept for re-scoring |
| `src/traffic_simulator/generate.py` | labelled training traffic |
| `src/traffic_simulator/validate_client.py` | independent test traffic, shares no code with the generator |
| `src/ml_pipeline/evaluate_live.py`, `model_select.py` | measure models on independent traffic |
| `frontend/` | the 8-page security console |
| `manuscript/` | the IEEE paper |
| `CLAUDE.md` | the traps: read it before touching training or evaluation |

---

## 5. Traps that have already bitten this project

1. **Run scripts from `src/`.** Every script expects `src/` as the working directory.
2. **Training needs `TRAIN_EVENT_LOG=data/events_training.jsonl`.** The default points
   at the unlabelled live log and dies with "a pool is too small".
3. **Always pass `MODELS_DIR` when experimenting.** Otherwise training overwrites the
   live model in `models/`. This has happened.
4. **The training corpus is not in git.** It is 15–35 MB and regenerable. Regenerate
   it in lab mode, see `CLAUDE.md`.
5. **Never set `GUARD_TRUST_LABEL_HEADER=true` outside lab mode.** It lets anyone
   poison the training data.
6. **Do not raise `GUARD_ML_ENFORCE_PERCENT` above 0 without `GUARD_ADMIN_TOKEN`.**
   Otherwise anyone who can reach port 5000 can reset the safety brake.
7. **Pacing.** Any measurement faster than 4 requests per second gets rate-limited at
   Layer 1, and those requests silently vanish from ML metrics.

---

## 6. If you want ML to actually block

The machinery exists and defaults to off. Turn it on only for endpoints that measure
under 1% false positives, for a small share of clients:

```bash
cd src
GUARD_ADMIN_TOKEN=<pick-a-secret> \
GUARD_ML_ENFORCE_ENDPOINTS=/api/products \
GUARD_ML_ENFORCE_PERCENT=5 \
docker compose up -d gateway
```

Watch the System Health page. If the would-block rate passes 5%, the brake switches
ML blocking off by itself while Layer 1 keeps blocking. To stop it instantly:

```bash
curl -X POST 'http://localhost:5000/__guard/reload?ml_brake=engage' \
     -H "X-Guard-Admin-Token: <your-secret>"
```

---

## 7. Open work, in priority order

1. **Merge this branch into `main`** through a pull request, so a normal clone gets it.
2. **Reach the 1% target.** The biggest lever is adding features for the three blind
   attack types: `body_unknown_field_ratio` (mass assignment), `body_nonscalar_ratio`
   (NoSQL injection), `max_numeric_magnitude` (enumeration). Each separates its attack
   perfectly in `docs/feature_case.html`. It changes the 34-feature contract, so it
   needs a full retrain.
3. **Retrain `models_b4` on a corpus that passes the variance check.** Its corpus has
   6 constant features, recorded in `MODEL_SELECTION.md`.
4. **Rewrite the paper** per `manuscript/REFRAME_PLAN.md`. Still needs a confidence
   interval on the gap between generator and independent traffic, and a McNemar test
   for the new model.
5. **Regenerate** `models/validation.json`, `tuning.json`, `comparison.json`. They
   still describe the previous model.
6. **Update the README's Results section**, which still leads with the old 0.99 figures.
7. **Known gaps outside ML:** the `sqli.timing` rule misses `WAITFOR DELAY '00:00:05'`;
   Redis is a single point of failure for rate limiting.
