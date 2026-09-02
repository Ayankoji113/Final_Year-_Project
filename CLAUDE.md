# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

MicroAPI Guard — a backend-agnostic API security gateway with a four-layer detection
pipeline (L1 signature rules + rate limiting → L2 Isolation Forest → L3 autoencoder →
L4 meta-learner). `README.md` and `src/README.md` cover what it is, how to deploy it,
and the current results. This file covers what those don't: the traps.

## Working directory

Every script does `sys.path.insert(0, <src>)` and expects **`src/` as the working
directory**. Run `python ml_pipeline/train.py` from `src/`, never `cd ml_pipeline &&
python train.py`. Same for pytest — `tests/conftest.py` puts `src/` on the path.

## Commands

```bash
cd src

pytest tests/ -v                       # full suite
pytest tests/test_features.py -v       # one file
pytest tests/test_rules.py -k sqli     # one test

# training (see the corpus trap below — the env var is not optional)
TRAIN_EVENT_LOG=data/events_training.jsonl python ml_pipeline/train.py

python ml_pipeline/tune.py             # hyperparameter search  -> models/tuning.json
python ml_pipeline/validate.py --seeds 10   # 10-seed CIs       -> models/validation.json
python ml_pipeline/compare.py          # baselines + McNemar    -> models/comparison.json
python ml_pipeline/calibrate.py        # adapt to a new backend

docker compose up -d                   # gateway on :5000
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d   # lab mode
python traffic_simulator/generate.py --sessions 2600 --attack-ratio 0.32
```

There is no linter config, no `pyproject.toml`, no pytest config. Dependencies are
per-component `requirements.txt` files plus `requirements-dev.txt`.

## The corpus trap

`config.EVENT_LOG` points at `data/events.jsonl`, which is the **gateway's live log and
is unlabelled**. Training on it silently yields *zero* labelled rows and dies at "a pool
is too small to train on". The labelled corpus is `data/events_training.jsonl`, reached
via the `TRAIN_EVENT_LOG` override. `tune.py` defaults to it; `train.py`, `validate.py`
and `compare.py` do not.

Labels only exist because lab mode sets `GUARD_TRUST_LABEL_HEADER=true`, which is a
training-data poisoning channel and must never be on in a real deployment.

## Train/serve symmetry is the core invariant

`common/` is imported by **both** the gateway and the trainer specifically so features
cannot drift between fitting and serving. Three consequences that are easy to break:

- **Feature contract.** `gateway/detector.py:load()` refuses to load a model whose
  `decision.json` `feature_names` differ from `common/features.FEATURE_NAMES`. Changing
  the feature list therefore requires a retrain — the gateway will not start otherwise.
  (34 features, 26 L1 rules; some README prose says 43, which is stale.)
- **Baseline-relative features.** `rate_z`, `body_size_z` and `path_known` are defined
  against a calibration baseline that did not exist while the corpus was captured, so
  they were logged as constant 0. `train.py:apply_baseline()` recomputes them from a
  baseline derived *only* from the `base` pool. Skip that and the autoencoder learns
  "always zero" and blocks all legitimate traffic in production. This actually happened.
- **Zero-variance guard.** `train.py` fails loudly on features that are constant or
  near-constant (sd < 0.01) in the training pool, because those become multi-sigma
  outliers on ordinary production values. It has bitten twice; treat the warning as a
  blocker, not noise.

## Evaluation protocol — do not weaken it

- **Sessions, never rows.** `pool_of(client)` hashes `client|SEED` into base/meta/val/test.
  A random row-level split lets near-identical requests from one session straddle the
  boundary and inflates every metric.
- **Base detectors see only `base` (normal rows).** That makes meta-features
  out-of-sample by construction — this is why there is no k-fold OOF stacking.
- **Threshold is picked on `val`, under an FPR budget** (`CALIBRATION_TARGET_FPR`, 1%).
  Every baseline in `compare.py` gets the same budget, otherwise the comparison rewards
  whichever model was allowed to be loosest.
- **`test` is read once, at the end.**
- **`NOVEL_FAMILIES`** (`cmdi`, `exfil`, `ssti`) are withheld from `meta`/`val` and appear
  only in `test`, which is what makes zero-day recall a real measurement.
- **L1-blocked rows are excluded from the ML stages** and re-attached for the end-to-end
  number, because in production they never reach a model.

Single-seed metrics are not reportable. The 10-seed intervals in `models/validation.json`
are the honest figures and are much weaker than the seed-42 numbers in `decision.json`
(F1 0.854 [0.812–0.891] vs 0.929; zero-day recall 0.598 [0.445–0.749] vs 0.887).

## Hyperparameters and the search

`train.py` reads all knobs from env, defaulting to the committed values: `TRAIN_SEED`,
`TRAIN_EVENT_LOG`, `TRAIN_NOVEL`, `TRAIN_AE_NOISE`, `TRAIN_AE_HIDDEN`,
`TRAIN_AE_BOTTLENECK`, `TRAIN_IF_TREES`, `TRAIN_META` (`lr` | `hgb`), plus `MODELS_DIR`.

`validate.py` and `tune.py` both drive `train.py` as a **subprocess** and read results back
from `decision.json`. Anything a driver needs must be written into that file — there is no
other channel.

`tune.py` keeps two separations that make its output quotable, and both must survive any
edit: it searches on seeds 11–15 while `validate.py` reports on 1–10 (different seeds mean
different session partitions), and it rotates `TRAIN_NOVEL` to a *different* family triple
so the real zero-day families never inform a hyperparameter choice. It writes to
`models_tuning/` so a few hundred throwaway retrains can't clobber the live artefacts.

## compare.py duplicates the pipeline

`ml_pipeline/compare.py` rebuilds scaler → forest → autoencoder → meta-learner
independently of `train.py`, so that every model scores the *same* test rows (McNemar's
pairing assumption requires it). **A change to `train.py`'s modelling must be mirrored
there.** It is currently already out of sync — it does not read the hyperparameter env
vars and constructs `NumpyAutoencoder` with defaults.

## Deployment defaults worth knowing

`GUARD_MODE` defaults to `enforce-l1`: rules and rate limits block, ML anomalies are only
logged. Full `enforce` is meant to be switched on after retraining on the deployment's own
captured traffic. `calibrate.py` re-derives the baseline and threshold but deliberately
does **not** retrain the forest or the network — see its header for the catastrophic-
forgetting and poisoning reasoning.

## Repo layout beyond `src/`

`Paper/` holds ~18 reference PDFs, `docs/` the written chapters (literature survey, PRD,
system design, viva questions), `PPT/` review decks, `diagrams/` architecture sources.
`src/legacy/` is the superseded pipeline, kept for before-and-after comparison — don't
extend it.
