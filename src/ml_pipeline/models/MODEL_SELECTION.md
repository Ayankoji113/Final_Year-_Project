# Shipped model: `models_b4`

Installed into `models/` on 2026-09-13, replacing the 2026-09-02 seed-42 model.
The feature contract is unchanged (34 features), so the gateway loads it with no
code change. `GUARD_MODE` stays `enforce-l1`: this model **records** ML verdicts
and does not return 403 on its own.

## Why this model

The selection rule was fixed before any numbers were seen: judge on independent
traffic from `traffic_simulator/validate_client.py`, never on the training
generator; rank by ROC-AUC; break near-ties on recall at the 1% FPR budget; the
winner must beat the old model on false positives.

Four independent client draws, scored with `ml_pipeline/model_select.py`:

| Model | FPR mean | ROC-AUC | Recall (L1-missed attacks) | F1 | Endpoints under 1% FPR |
| --- | ---: | ---: | ---: | ---: | ---: |
| Previous `models/` | 61.27% | 0.5595 | 100% | 0.320 | 5.0 / 13 |
| models_b3 | 8.46% | 0.8867 | 48.4% | 0.456 | 9.8 / 13 |
| **models_b4 (shipped)** | **17.02%** | **0.8716** | **92.8%** | **0.584** | 7.0 / 13 |
| models_final | 9.71% | 0.8331 | 48.0% | 0.437 | 9.5 / 13 |

b3 and b4 are a near-tie on ROC-AUC. The tie-break decided it: at a 1% FPR
budget b3 catches 0.5% of attacks and b4 catches 13.4%. b4 also has the best F1
and roughly double the recall of every alternative.

Raw results: `ml_pipeline/model_selection.json`, `ml_pipeline/model_selection_final.json`.

## Known limitations — read before enabling ML enforcement

1. **The project goal is not met yet.** Global false positives are 17%, against a
   1% target. Do not set `GUARD_MODE=enforce`. Use the per-endpoint allowlist
   (`GUARD_ML_ENFORCE_ENDPOINTS`) and canary (`GUARD_ML_ENFORCE_PERCENT`) only on
   endpoints that measure under 1%.
2. **Its training corpus fails the C2 variance gate** in `train.py`: 6 features are
   constant in the base pool. It was trained before that gate became a hard abort.
   The gate was not weakened to admit it; retraining it today requires
   `TRAIN_ALLOW_CONSTANT_FEATURES`, and that should be treated as a known defect.
3. **In-distribution metrics in `decision.json` are much lower than the previous
   model's** (F1 0.631 vs 0.991). That is expected: the previous number came from a
   narrow generator that its own test pool shared. On independent traffic the
   previous model is near chance.
4. `validation.json`, `tuning.json` and `comparison.json` in this directory describe
   the **previous** model and have not been regenerated.
5. massassign, nosql and enum attacks are not detectable with the current 34 shape
   features. See `docs/feature_case.html`.

## Reproduce

The corpus is not committed (see `.gitignore`). Regenerate it with the widened
generator at the B4 stage, then:

```bash
cd src
TRAIN_EVENT_LOG=data/events_training.jsonl TRAIN_SEED=42 TRAIN_META=hgb \
TRAIN_ALLOW_CONSTANT_FEATURES=1 MODELS_DIR=ml_pipeline/models_b4 \
python ml_pipeline/train.py
```

Must run inside the gateway image: artefacts are pickled under scikit-learn
1.4.1.post1.

## Roll back

The previous model is in git history at commit `8e14907`:

```bash
git checkout 8e14907 -- src/ml_pipeline/models/
curl -X POST localhost:5000/__guard/reload
```
