"""Paired baseline comparison with McNemar's test.

Rebuilds the exact pipeline from train.py on ONE split, so every model produces
a prediction for the SAME test rows. That pairing is what McNemar's test
requires; comparing numbers taken from different runs or different seeds would
violate its assumption and the p-value would be meaningless.

Compared, all under the same false-positive budget:
    rate only  |  isolation forest only  |  autoencoder only  |  L4 stack
"""
import json
import os
import pickle
import sys
from collections import defaultdict

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config, features                        # noqa: E402
from common.autoencoder import NumpyAutoencoder            # noqa: E402
from sklearn.ensemble import IsolationForest               # noqa: E402
from sklearn.linear_model import LogisticRegression        # noqa: E402
from sklearn.preprocessing import StandardScaler           # noqa: E402

from ml_pipeline.train import (NOVEL_FAMILIES, SEED, apply_baseline,  # noqa: E402
                               build_baseline, l1_blocks, load_events,
                               metrics, parse_label, pick_threshold, pool_of)
from ml_pipeline.validate import mcnemar                   # noqa: E402


def build():
    # Honour the same override train.py uses, so both read the same corpus.
    raw = load_events(os.getenv("TRAIN_EVENT_LOG", config.EVENT_LOG))
    rows = []
    for r in raw:
        y, fam = parse_label(r)
        if y is None or not r.get("features"):
            continue
        rows.append({"y": y, "fam": fam, "client": r.get("client", "?"),
                     "f": r["features"], "l1": l1_blocks(r),
                     "template": r.get("template", "/"),
                     "body_size": r.get("body_size", 0)})

    ml_rows = [r for r in rows if not r["l1"]]
    pools = defaultdict(list)
    for r in ml_rows:
        pools[pool_of(r["client"])].append(r)

    base = [r for r in pools["base"] if r["y"] == 0]
    meta = [r for r in pools["meta"] if r["fam"] not in NOVEL_FAMILIES]
    val = [r for r in pools["val"] if r["fam"] not in NOVEL_FAMILIES]
    test = pools["test"]

    baseline = build_baseline(base)
    apply_baseline(rows, baseline)

    X = lambda p: features.to_matrix([r["f"] for r in p])   # noqa: E731
    Y = lambda p: np.array([r["y"] for r in p])             # noqa: E731

    Xb = X(base)
    scaler = StandardScaler().fit(Xb)
    Xb_s = scaler.transform(Xb)
    iforest = IsolationForest(n_estimators=300, contamination="auto",
                              max_samples=min(4096, len(Xb_s)),
                              random_state=SEED, n_jobs=-1).fit(Xb_s)
    ae = NumpyAutoencoder(Xb_s.shape[1], seed=SEED).fit(Xb_s, verbose=False)

    if_b = -iforest.decision_function(Xb_s)
    ae_b = ae.score(Xb_s)
    if_lo, if_hi = np.percentile(if_b, 1), np.percentile(if_b, 99.5)
    ae_lo, ae_hi = np.percentile(ae_b, 1), np.percentile(ae_b, 99.5)

    def scores(pool):
        Xs = scaler.transform(X(pool))
        i = np.clip((-iforest.decision_function(Xs) - if_lo) / (if_hi - if_lo + 1e-9), 0, 1)
        a = np.clip((ae.score(Xs) - ae_lo) / (ae_hi - ae_lo + 1e-9), 0, 1)
        r = np.clip(np.expm1([x["f"].get("win_log_count", 0.0) for x in pool])
                    / max(1, config.RATE_LIMIT), 0, 1)
        return r, i, a

    rm, im, am = scores(meta)
    lr = LogisticRegression(class_weight="balanced", max_iter=2000,
                            random_state=SEED).fit(np.column_stack([rm, im, am]),
                                                   Y(meta))
    rv, iv, av = scores(val)
    rt, it, at = scores(test)
    pv = lr.predict_proba(np.column_stack([rv, iv, av]))[:, 1]
    pt = lr.predict_proba(np.column_stack([rt, it, at]))[:, 1]

    return {"y_val": Y(val), "y_test": Y(test),
            "val": {"rate": rv, "iforest": iv, "autoencoder": av, "stack": pv},
            "test": {"rate": rt, "iforest": it, "autoencoder": at, "stack": pt}}


def main():
    print("=" * 70)
    print("  PAIRED BASELINE COMPARISON  (single split, identical test rows)")
    print("=" * 70)
    d = build()
    yv, yt = d["y_val"], d["y_test"]
    budget = config.CALIBRATION_TARGET_FPR

    preds, results = {}, {}
    print(f"\n  thresholds chosen on validation under a {budget:.1%} FPR budget\n")
    print(f"  {'model':22s} {'thr':>6s} {'f1':>8s} {'recall':>8s} "
          f"{'prec':>8s} {'FPR':>8s}")
    for name in ("rate", "iforest", "autoencoder", "stack"):
        t, _ = pick_threshold(d["val"][name], yv, target_fpr=budget)
        p = (d["test"][name] >= t).astype(int)
        preds[name] = p
        m = metrics(yt, p)
        results[name] = m
        print(f"  {name:22s} {t:6.3f} {m['f1']:8.4f} {m['recall']:8.4f} "
              f"{m['precision']:8.4f} {m['fpr']:8.4f}")

    print("\n" + "=" * 70)
    print("  McNEMAR: stack vs each single detector")
    print("=" * 70)
    print("  H0: the two classifiers make the same number of exclusive errors.")
    print("  Only discordant pairs contribute.\n")

    correct = {k: (v == yt) for k, v in preds.items()}
    out = {"metrics": {k: {kk: float(vv) for kk, vv in m.items()}
                       for k, m in results.items()}, "mcnemar": {}}
    for name in ("rate", "iforest", "autoencoder"):
        r = mcnemar(correct["stack"], correct[name])
        out["mcnemar"][f"stack_vs_{name}"] = r
        verdict = ("stack significantly better" if r["significant"] and r["n01"] > r["n10"]
                   else "single detector significantly better"
                   if r["significant"] else "no significant difference")
        print(f"  stack vs {name:14s} "
              f"stack-only-correct={r['n01']:5,}  {name}-only-correct={r['n10']:5,}")
        print(f"  {'':23s} p={r['p']:.2e}  ({r['method']})  -> {verdict}\n")

    path = os.path.join(config.MODELS_DIR, "comparison.json")
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"  written: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
