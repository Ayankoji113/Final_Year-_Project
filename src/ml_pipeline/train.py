"""MicroAPI Guard - training pipeline.

METHODOLOGY (and why it differs from the previous version)
==========================================================

Split strategy - GROUPED, not random
------------------------------------
Requests are grouped by client session. A random row-level split lets two
near-identical requests from the same session land on opposite sides, which
inflates every metric. We partition *sessions* into four disjoint pools:

    base   45%   normal rows only   -> fit scaler, Isolation Forest, Autoencoder
    meta   25%   labelled           -> fit the Logistic Regression meta-learner
    val    15%   labelled           -> pick the decision threshold
    test   15%   labelled           -> touched exactly once, at the very end

Stacking without leakage
------------------------
The old pipeline generated the meta-learner's training features by scoring the
*same rows* the base models were fitted on, then min-max normalised those
features using validation-set statistics. Both leak. The meta-learner ended up
with a negative Isolation Forest coefficient - it had learned an artefact.

Here the base detectors are fitted only on `base`, and never see `meta`, `val`
or `test`. Meta-features are therefore out-of-sample by construction, which is
what k-fold OOF stacking exists to simulate - we get it directly because the
base models are unsupervised and need no labels, so a disjoint pool costs
nothing. Normalisation ranges come from `base` alone.

Layer-1 filtering
-----------------
Requests that Layer 1 blocks outright never reach the model in production, so
training or evaluating the model on them would measure the wrong distribution.
They are excluded from the ML stages and re-attached for the end-to-end
pipeline evaluation, where L1's contribution is counted honestly.

Zero-day evaluation
-------------------
Whole attack families (cmdi, ssti, exfil) are withheld from `meta` and `val`
and appear only in `test`. Recall on those families is a real measurement of
detecting attack types never seen during training.
"""
import hashlib
import json
import os
import pickle
import sys
import time
from collections import Counter, defaultdict

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config, features, rules                     # noqa: E402
from common.autoencoder import NumpyAutoencoder                # noqa: E402
from common.features import Baseline                           # noqa: E402

import joblib                                                  # noqa: E402
from sklearn.ensemble import (HistGradientBoostingClassifier,  # noqa: E402
                              IsolationForest)
from sklearn.linear_model import LogisticRegression            # noqa: E402
from sklearn.metrics import (average_precision_score,          # noqa: E402
                             roc_auc_score)
from sklearn.preprocessing import StandardScaler               # noqa: E402

SEED = int(os.getenv("TRAIN_SEED", 42))

# Families withheld from meta/val so their test recall is a real zero-day
# measurement. Overridable so the hyperparameter search can select against a
# DIFFERENT triple (a pseudo-zero-day signal) and leave cmdi/exfil/ssti
# genuinely untouched for the final evaluation. See ml_pipeline/tune.py.
NOVEL_FAMILIES = {f.strip() for f in
                  os.getenv("TRAIN_NOVEL", "cmdi,exfil,ssti").split(",") if f.strip()}

# Hyperparameters. These defaults are the winners of the grid search in
# ml_pipeline/tune.py (24 configs x 5 seeds, selected on validation only).
# tune.py overrides them via env.
#
# The meta-learner is the one that mattered. Logistic regression averaged
# validation F1 0.600 with a seed-to-seed sd of 0.196; gradient boosting
# averaged 0.940 with sd 0.043. The instability everyone was attributing to the
# unsupervised base detectors was the linear meta-learner failing to separate
# score combinations that are not linearly separable.
AE_NOISE = float(os.getenv("TRAIN_AE_NOISE", 0.0))
AE_HIDDEN = int(os.getenv("TRAIN_AE_HIDDEN", 32))
AE_BOTTLENECK = int(os.getenv("TRAIN_AE_BOTTLENECK", 16))
IF_TREES = int(os.getenv("TRAIN_IF_TREES", 300))
META_MODEL = os.getenv("TRAIN_META", "hgb")           # lr | hgb

MODELS_DIR = config.MODELS_DIR
# Overridable so a preserved corpus can be retrained without regenerating
# traffic (feature-set changes only need a re-read of the logged vectors).
EVENT_LOG = os.getenv("TRAIN_EVENT_LOG", config.EVENT_LOG)

RULE_SEVERITY = {r.id: r.severity for r in rules.RULES}


# ── data loading ──────────────────────────────────────────────────────────────

def load_events(path):
    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def parse_label(rec):
    """'normal' -> (0, None);  'attack:sqli' -> (1, 'sqli')."""
    raw = rec.get("label")
    if not raw:
        return None, None
    raw = str(raw)
    if raw.startswith("attack"):
        parts = raw.split(":", 1)
        return 1, (parts[1] if len(parts) > 1 else "unknown")
    if raw.startswith("normal"):
        return 0, None
    return None, None


def l1_blocks(rec) -> bool:
    """Did Layer 1 settle this request on its own?

    Covers BOTH halves of Layer 1: signature rules and the hard rate limit.
    Including the rate half matters. In production a rate-limited request is
    rejected before any model runs, so training the ML layers on those rows -
    and then reporting the model's recall on volumetric attacks - measures a
    decision path that never executes. Excluding them scopes the ML layers to
    their real job: the traffic that is neither obviously malicious nor
    obviously excessive.
    """
    if any(RULE_SEVERITY.get(h) == rules.BLOCK for h in rec.get("rule_hits", [])):
        return True
    return rec.get("layer") == "L1-rate"


def pool_of(client: str) -> str:
    """Deterministic session -> pool assignment. Hash-based so it is stable
    across reruns and cannot accidentally correlate with time or label."""
    h = int(hashlib.sha256(f"{client}|{SEED}".encode()).hexdigest()[:8], 16) % 100
    if h < 45:
        return "base"
    if h < 70:
        return "meta"
    if h < 85:
        return "val"
    return "test"


# ── metrics ───────────────────────────────────────────────────────────────────

def confusion(y, p):
    y, p = np.asarray(y), np.asarray(p)
    tp = int(((p == 1) & (y == 1)).sum()); tn = int(((p == 0) & (y == 0)).sum())
    fp = int(((p == 1) & (y == 0)).sum()); fn = int(((p == 0) & (y == 1)).sum())
    return tp, tn, fp, fn


def metrics(y, p):
    tp, tn, fp, fn = confusion(y, p)
    n = max(1, len(y))
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {
        "accuracy": (tp + tn) / n, "precision": prec, "recall": rec, "f1": f1,
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "fnr": fn / (fn + tp) if (fn + tp) else 0.0,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
    }


def show(name, m, auc=None, ap=None):
    print(f"\n  {name}")
    print(f"    {'':12s} pred-normal  pred-attack")
    print(f"    {'true-normal':12s} {m['tn']:10,} {m['fp']:12,}")
    print(f"    {'true-attack':12s} {m['fn']:10,} {m['tp']:12,}")
    line = (f"    acc={m['accuracy']:.4f}  prec={m['precision']:.4f}  "
            f"rec={m['recall']:.4f}  f1={m['f1']:.4f}  "
            f"FPR={m['fpr']:.4f}  FNR={m['fnr']:.4f}")
    if auc is not None:
        line += f"\n    ROC-AUC={auc:.4f}  PR-AUC={ap:.4f}"
    print(line)


def pick_threshold(scores, y, target_fpr=None):
    """Maximise F1 on the validation pool; optionally respect an FPR ceiling.

    A security gateway that blocks 5% of real users is unusable regardless of
    its recall, so the operator-facing knob is the false-positive budget.
    """
    y = np.asarray(y)
    best = (0.0, 0.5)
    for t in np.arange(0.02, 0.99, 0.005):
        m = metrics(y, (scores >= t).astype(int))
        if target_fpr is not None and m["fpr"] > target_fpr:
            continue
        if m["f1"] > best[0]:
            best = (m["f1"], float(t))
    return best[1], best[0]


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    np.random.seed(SEED)
    print("=" * 70)
    print("  MicroAPI Guard - training pipeline")
    print("=" * 70)

    if not os.path.exists(EVENT_LOG):
        print(f"\n  ERROR: no event log at {EVENT_LOG}")
        print("  Run the gateway in monitor mode and generate traffic first:")
        print("    python traffic_simulator/generate.py")
        return 1

    print(f"\n[1/8] Loading {EVENT_LOG}")
    raw = load_events(EVENT_LOG)
    print(f"      {len(raw):,} events")

    rows = []
    for r in raw:
        y, fam = parse_label(r)
        if y is None or not r.get("features"):
            continue
        # Raw window count comes from the event metadata. Older corpora stored
        # it only as the log-scaled feature, so fall back to that.
        win = r.get("window_count")
        if win is None:
            win = float(np.expm1(r["features"].get("win_log_count", 0.0)))
        rows.append({"y": y, "fam": fam, "client": r.get("client", "?"),
                     "f": r["features"], "l1": l1_blocks(r),
                     "by_rule": bool(r.get("rule_hits")),
                     "template": r.get("template", "/"),
                     "body_size": r.get("body_size", 0),
                     "win": float(win)})
    print(f"      {len(rows):,} labelled events "
          f"({sum(1 for r in rows if r['y'] == 1):,} attack)")
    if len(rows) < 2000:
        print("      WARNING: very small corpus; results will be noisy.")

    # ── integrity check: the failure mode that invalidated the last build ────
    sig = Counter(hashlib.md5(
        json.dumps([round(float(r["f"].get(n, 0)), 4) for n in features.FEATURE_NAMES]
                   ).encode()).hexdigest() for r in rows)
    uniq = len(sig)
    print(f"      unique feature vectors: {uniq:,} / {len(rows):,} "
          f"({100 * uniq / max(1, len(rows)):.1f}% distinct)")
    if uniq < 0.2 * len(rows):
        print("      *** WARNING: heavy duplication. Metrics will be optimistic. ***")

    # ── L1 partition ─────────────────────────────────────────────────────────
    l1_rows = [r for r in rows if r["l1"]]
    ml_rows = [r for r in rows if not r["l1"]]
    l1_tp = sum(1 for r in l1_rows if r["y"] == 1)
    n_rule = sum(1 for r in l1_rows if r.get("by_rule"))
    print(f"\n[2/8] Layer 1 short-circuits {len(l1_rows):,} events "
          f"({l1_tp:,} attack, {len(l1_rows) - l1_tp:,} normal=false positive)")
    print(f"      of which {n_rule:,} by signature rule, "
          f"{len(l1_rows) - n_rule:,} by rate limit")
    print(f"      {len(ml_rows):,} events reach the ML layers")
    if l1_tp < len(l1_rows):
        print(f"      NOTE: {len(l1_rows) - l1_tp:,} legitimate requests were "
              f"caught by Layer 1.")
        print("      These are real false positives and count against the")
        print("      full-pipeline FPR reported at the end.")

    # ── pools ────────────────────────────────────────────────────────────────
    pools = defaultdict(list)
    for r in ml_rows:
        pools[pool_of(r["client"])].append(r)

    base = [r for r in pools["base"] if r["y"] == 0]          # normal only
    meta = [r for r in pools["meta"] if r["fam"] not in NOVEL_FAMILIES]
    val = [r for r in pools["val"] if r["fam"] not in NOVEL_FAMILIES]
    test = pools["test"]                                      # novel families kept

    print(f"\n[3/8] Session-grouped pools (novel families held out of meta/val)")
    for nm, p in (("base(normal)", base), ("meta", meta), ("val", val), ("test", test)):
        na = sum(1 for r in p if r["y"] == 1)
        print(f"      {nm:14s} {len(p):7,}  attack={na:6,}")
    if min(len(base), len(meta), len(val), len(test)) < 50:
        print("      ERROR: a pool is too small to train on.")
        return 1

    X = lambda p: features.to_matrix([r["f"] for r in p])      # noqa: E731
    Y = lambda p: np.array([r["y"] for r in p])                # noqa: E731

    # ── calibration baseline from base pool ──────────────────────────────────
    print("\n[4/8] Deriving statistical baseline from normal traffic")
    baseline = build_baseline(base)
    print(f"      {len(baseline.endpoints)} endpoint templates, "
          f"rate mean={baseline.rate_mean:.2f} std={baseline.rate_std:.2f}")

    # TRAIN/SERVE SKEW FIX.
    #
    # Three features are defined relative to the calibration baseline:
    # rate_z, body_size_z and path_known. While the corpus was being collected
    # no baseline existed yet, so the gateway logged all three as constant 0.
    # If we trained on those constants the autoencoder would learn "this is
    # always zero", and then in production - where the baseline DOES exist and
    # the values vary - every ordinary request would produce a huge
    # reconstruction error and be blocked. That is exactly what happened on the
    # first enforcement run: legitimate traffic scored autoencoder=1.0.
    #
    # We therefore recompute them here from the raw scalars, using a baseline
    # derived ONLY from the base pool, so training sees the same feature
    # definition the gateway will use at inference time.
    n_patched = apply_baseline(rows, baseline)
    print(f"      recomputed baseline-relative features on {n_patched:,} rows "
          f"(rate_z, body_size_z, path_known)")
    for nm in ("rate_z", "body_size_z", "path_known"):
        vals = np.array([r["f"].get(nm, 0.0) for r in rows], dtype=float)
        print(f"        {nm:14s} mean={vals.mean():+.4f} std={vals.std():.4f} "
              f"{'<-- STILL CONSTANT, skew risk' if vals.std() < 1e-9 else ''}")

    # ── scaler + base detectors, fitted on `base` ONLY ───────────────────────
    print("\n[5/8] Base detectors (unsupervised, normal traffic only)")
    Xb = X(base)

    # ZERO-VARIANCE GUARD.
    #
    # A feature that is constant across the training pool but varies in
    # production is the single most damaging failure mode for this design. The
    # scaler leaves it untouched (sklearn sets scale_=1 when variance is 0) and
    # the autoencoder learns to emit exactly that constant, so the first live
    # request carrying any other value produces a huge reconstruction error and
    # is blocked. It has bitten this pipeline twice - once via the
    # baseline-relative features, once via path_dot_count - so it is now
    # checked rather than discovered from false positives.
    sd_b = Xb.std(axis=0)
    dead = [features.FEATURE_NAMES[i] for i in np.where(sd_b < 1e-12)[0]]
    # NEAR-constant is almost as damaging as constant: a feature with sd 0.003
    # turns a routine capitalised name into a multi-sigma outlier. Flag anything
    # whose spread is tiny relative to a standardised scale.
    near = [(features.FEATURE_NAMES[i], float(sd_b[i]), float(Xb[:, i].mean()))
            for i in np.where((sd_b >= 1e-12) & (sd_b < 0.01))[0]]
    if dead:
        print("\n      *** ZERO-VARIANCE FEATURES IN TRAINING POOL ***")
        for nm in dead:
            print(f"          {nm}")
        print("      These are constant here but will vary in production, which")
        print("      causes the autoencoder to reject ordinary traffic. Either")
        print("      generate traffic that exercises them, or remove them from")
        print("      FEATURE_NAMES.")
    if near:
        print("\n      *** NEAR-CONSTANT FEATURES (sd < 0.01) ***")
        for nm, s, m in near:
            print(f"          {nm:24s} mean={m:.6f} sd={s:.6f}")
        print("      The corpus barely exercises these, so ordinary production")
        print("      values will read as extreme. The denoising autoencoder")
        print("      absorbs some of this, but widening the traffic generator")
        print("      is the real fix.")

    scaler = StandardScaler().fit(Xb)
    Xb_s = scaler.transform(Xb)

    iforest = IsolationForest(n_estimators=IF_TREES, contamination="auto",
                              max_samples=min(4096, len(Xb_s)),
                              random_state=SEED, n_jobs=-1).fit(Xb_s)
    print(f"      IsolationForest fitted on {len(Xb_s):,} normal rows")

    ae = NumpyAutoencoder(Xb_s.shape[1], hidden=AE_HIDDEN, bottleneck=AE_BOTTLENECK,
                          lr=1e-3, epochs=300, batch=256, patience=15, seed=SEED,
                          noise=AE_NOISE)
    ae.fit(Xb_s)
    print(f"      Autoencoder best val reconstruction MSE = {ae.best_val:.6f}")

    # Normalisation ranges from TRAINING data only (robust percentiles, so one
    # outlier cannot compress the whole scale).
    if_base = -iforest.decision_function(Xb_s)
    ae_base = ae.score(Xb_s)
    if_lo, if_hi = float(np.percentile(if_base, 1)), float(np.percentile(if_base, 99.5))
    ae_lo, ae_hi = float(np.percentile(ae_base, 1)), float(np.percentile(ae_base, 99.5))

    def meta_features(pool):
        Xs = scaler.transform(X(pool))
        i = np.clip((-iforest.decision_function(Xs) - if_lo) / (if_hi - if_lo + 1e-9), 0, 1)
        a = np.clip((ae.score(Xs) - ae_lo) / (ae_hi - ae_lo + 1e-9), 0, 1)
        # L1's continuous rate contribution, reconstructed the same way the
        # gateway does it at inference time.
        r = np.clip(np.array([x["win"] for x in pool]) / max(1, config.RATE_LIMIT), 0, 1)
        return np.column_stack([r, i, a]), i, a, r

    # ── meta-learner ─────────────────────────────────────────────────────────
    print(f"\n[6/8] Meta-learner ({META_MODEL}) over base-detector scores")
    Mm, _, _, _ = meta_features(meta)
    ym = Y(meta)
    if META_MODEL == "hgb":
        # Gradient boosting can express interactions the linear meta-learner
        # cannot - e.g. "a high autoencoder error only counts when the request
        # also arrives at an unknown endpoint". Three inputs and a few thousand
        # rows, so it is kept deliberately shallow to avoid fitting `meta`'s
        # noise instead of its structure.
        meta_lr = HistGradientBoostingClassifier(
            max_depth=3, max_iter=200, learning_rate=0.1,
            min_samples_leaf=40, l2_regularization=1.0,
            early_stopping=True, validation_fraction=0.15,
            random_state=SEED).fit(Mm, ym)
        print(f"      HistGradientBoosting, {meta_lr.n_iter_} boosting rounds")
    else:
        meta_lr = LogisticRegression(class_weight="balanced", max_iter=2000,
                                     random_state=SEED).fit(Mm, ym)
        print(f"      coefficients  rate={meta_lr.coef_[0][0]:+.3f}  "
              f"iforest={meta_lr.coef_[0][1]:+.3f}  "
              f"autoencoder={meta_lr.coef_[0][2]:+.3f}")
        print(f"      intercept     {meta_lr.intercept_[0]:+.3f}")
        if np.any(meta_lr.coef_[0] < -0.5):
            print("      NOTE: a strongly negative coefficient means that detector is")
            print("            anti-correlated with attacks - investigate before trusting.")

    # ── threshold on validation ──────────────────────────────────────────────
    Mv, iv, av, rv = meta_features(val)
    yv = Y(val)
    pv = meta_lr.predict_proba(Mv)[:, 1]
    thr, vf1 = pick_threshold(pv, yv, target_fpr=config.CALIBRATION_TARGET_FPR)
    if thr is None:
        thr, vf1 = pick_threshold(pv, yv)
    print(f"\n[7/8] Threshold selected on validation only: {thr:.3f} "
          f"(val F1={vf1:.4f}, FPR budget={config.CALIBRATION_TARGET_FPR})")

    # ── final evaluation - test pool touched for the first time ──────────────
    print("\n[8/8] TEST EVALUATION (held-out sessions, first and only use)")
    print("=" * 70)
    Mt, it_, at_, rt_ = meta_features(test)
    yt = Y(test)
    pt = meta_lr.predict_proba(Mt)[:, 1]
    pred = (pt >= thr).astype(int)

    m_stack = metrics(yt, pred)
    auc = roc_auc_score(yt, pt) if len(set(yt)) > 1 else float("nan")
    ap = average_precision_score(yt, pt) if len(set(yt)) > 1 else float("nan")
    show("ML stack (L2+L3 -> L4), on traffic that reaches the model", m_stack, auc, ap)

    # ── declared baselines (comparison, NOT selection) ───────────────────────
    print("\n  Baselines on the same test pool. Every model - including the")
    print("  stack - gets its threshold chosen on validation under the SAME")
    print(f"  false-positive budget ({config.CALIBRATION_TARGET_FPR:.1%}), otherwise the")
    print("  comparison rewards whichever model was allowed to be loosest.")
    baseline_rows = []
    for nm, sv, st in (("rate only", rv, rt_),
                       ("isolation forest only", iv, it_),
                       ("autoencoder only", av, at_)):
        t_, _ = pick_threshold(sv, yv, target_fpr=config.CALIBRATION_TARGET_FPR)
        mm = metrics(yt, (st >= t_).astype(int))
        a_ = roc_auc_score(yt, st) if len(set(yt)) > 1 else float("nan")
        baseline_rows.append((nm, mm, a_))
        print(f"    {nm:24s} f1={mm['f1']:.4f}  rec={mm['recall']:.4f}  "
              f"FPR={mm['fpr']:.4f}  AUC={a_:.4f}")
    print(f"    {'STACK (L4 meta-learner)':24s} f1={m_stack['f1']:.4f}  "
          f"rec={m_stack['recall']:.4f}  FPR={m_stack['fpr']:.4f}  AUC={auc:.4f}")

    best_base = max(baseline_rows, key=lambda r: r[1]["f1"])
    if best_base[1]["f1"] >= m_stack["f1"]:
        print(f"\n    HONEST RESULT: '{best_base[0]}' matches or beats the stack on F1.")
        print("    The ensemble's remaining claims are ROC-AUC, a calibrated")
        print("    probability, and graceful degradation when one detector is")
        print("    unavailable - not raw F1. Report it that way.")

    # ── per-family recall, separating seen from novel ────────────────────────
    # Families that Layer 1 catches outright barely appear in the ML test pool,
    # so their ML-layer n is tiny and their ML recall is not interpretable. We
    # therefore report both columns: what the model saw, and what the deployed
    # pipeline actually does to that family.
    l1_test_all = [r for r in l1_rows if pool_of(r["client"]) == "test"]
    l1_fam = Counter(r["fam"] for r in l1_test_all if r["y"] == 1)

    print("\n  Per-family detection on test:")
    print(f"    {'family':12s} {'ML n':>6s} {'ML recall':>10s} "
          f"{'L1 caught':>10s} {'pipeline recall':>16s}")
    fam_rows = defaultdict(list)
    for r, pr in zip(test, pred):
        if r["y"] == 1:
            fam_rows[r["fam"]].append(pr)
    for fam in sorted(set(fam_rows) | set(l1_fam)):
        v = fam_rows.get(fam, [])
        n_l1 = l1_fam.get(fam, 0)
        total = len(v) + n_l1
        caught = int(np.sum(v)) + n_l1
        ml_rec = f"{np.mean(v):.4f}" if v else "     n/a"
        tag = "  <-- NOVEL" if fam in NOVEL_FAMILIES else ""
        print(f"    {fam:12s} {len(v):6,} {ml_rec:>10s} {n_l1:10,} "
              f"{caught / max(1, total):16.4f}{tag}")
    print("    (a small ML n means Layer 1 already blocked that family - which")
    print("     is the intended behaviour, not a coverage gap)")

    novel = [p for r, p in zip(test, pred) if r["y"] == 1 and r["fam"] in NOVEL_FAMILIES]
    seen = [p for r, p in zip(test, pred) if r["y"] == 1 and r["fam"] not in NOVEL_FAMILIES]
    if novel:
        print(f"\n    zero-day recall (unseen families) : {np.mean(novel):.4f}  n={len(novel):,}")
    if seen:
        print(f"    known-family recall               : {np.mean(seen):.4f}  n={len(seen):,}")

    # ── end-to-end pipeline including Layer 1 ────────────────────────────────
    l1_test = [r for r in l1_rows if pool_of(r["client"]) == "test"]
    if l1_test:
        y_all = np.concatenate([yt, [r["y"] for r in l1_test]])
        p_all = np.concatenate([pred, np.ones(len(l1_test), dtype=int)])
        m_all = metrics(y_all, p_all)
        show("FULL PIPELINE (L1 rules + rate + L2/L3 -> L4) - what users actually get",
             m_all)

    # ── persist ──────────────────────────────────────────────────────────────
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.pkl"))
    joblib.dump(iforest, os.path.join(MODELS_DIR, "isolation_forest.pkl"))
    joblib.dump(meta_lr, os.path.join(MODELS_DIR, "meta_lr.pkl"))
    with open(os.path.join(MODELS_DIR, "autoencoder.pkl"), "wb") as fh:
        pickle.dump(ae, fh)
    with open(os.path.join(MODELS_DIR, "calibration.json"), "w") as fh:
        json.dump(baseline.to_dict(), fh, indent=2)

    decision = {
        "version": 3,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "seed": SEED,
        "feature_names": features.FEATURE_NAMES,
        "threshold": thr,
        "if_lo": if_lo, "if_hi": if_hi, "ae_lo": ae_lo, "ae_hi": ae_hi,
        "meta_inputs": ["rate", "isolation_forest", "autoencoder"],
        "pool_sizes": {"base": len(base), "meta": len(meta),
                       "val": len(val), "test": len(test)},
        "novel_families": sorted(NOVEL_FAMILIES),
        "hyperparams": {"ae_noise": AE_NOISE, "ae_hidden": AE_HIDDEN,
                        "ae_bottleneck": AE_BOTTLENECK, "if_trees": IF_TREES,
                        "meta": META_MODEL},
        # Selection metric. The hyperparameter search reads this and never the
        # test metrics below.
        "val_f1": round(float(vf1), 4),
        "test_metrics": {k: (round(float(v), 4) if isinstance(v, float) else v)
                         for k, v in m_stack.items()},
        "test_roc_auc": round(float(auc), 4),
        "test_pr_auc": round(float(ap), 4),
        "zero_day_recall": round(float(np.mean(novel)), 4) if novel else None,
        "unique_feature_ratio": round(uniq / max(1, len(rows)), 4),
    }
    with open(os.path.join(MODELS_DIR, "decision.json"), "w") as fh:
        json.dump(decision, fh, indent=2)

    print("\n" + "=" * 70)
    print(f"  Artefacts written to {MODELS_DIR}")
    print("  scaler.pkl  isolation_forest.pkl  autoencoder.pkl  meta_lr.pkl")
    print("  decision.json  calibration.json")
    print("=" * 70)
    return 0


def apply_baseline(all_rows, baseline: Baseline) -> int:
    """Recompute the baseline-relative features in place.

    Must be called with a baseline derived only from the training pool, and
    must be applied to every pool, so that train, validation and test all use
    the identical feature definition the gateway uses in production.
    """
    from common.features import _safe_z

    for r in all_rows:
        f = r["f"]
        window = float(r.get("win", 0.0))
        f["rate_z"] = _safe_z(window, baseline.rate_mean, baseline.rate_std) \
            if baseline.ready else 0.0
        stats = baseline.body_stats(r.get("template", "/"))
        f["body_size_z"] = _safe_z(float(r.get("body_size", 0)), stats[0], stats[1]) \
            if stats else 0.0
        f["path_known"] = 1.0 if baseline.knows(r.get("template", "/")) else 0.0
    return len(all_rows)


def build_baseline(base_rows) -> Baseline:
    """Per-endpoint body-size and global rate statistics from normal traffic."""
    per = defaultdict(list)
    rates = []
    for r in base_rows:
        per[r["template"]].append(float(r.get("body_size", 0)))
        rates.append(float(r.get("win", 0.0)))
    endpoints = {}
    for tpl, sizes in per.items():
        if len(sizes) < 5:          # too few samples to be a baseline
            continue
        endpoints[tpl] = {"body_mean": float(np.mean(sizes)),
                          "body_std": float(np.std(sizes)),
                          "count": len(sizes)}
    return Baseline({
        "endpoints": endpoints,
        "rate": {"mean": float(np.mean(rates)) if rates else 0.0,
                 "std": float(np.std(rates)) if rates else 0.0},
        "n_samples": len(base_rows),
    })


if __name__ == "__main__":
    sys.exit(main())

