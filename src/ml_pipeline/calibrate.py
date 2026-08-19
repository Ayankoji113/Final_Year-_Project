"""Calibration - adapt a trained MicroAPI Guard to a backend it has never seen.

THE HONEST CLAIM
----------------
This does NOT fine-tune the neural network or the forest. It re-derives the
statistical baseline the features are measured against, and re-picks the
decision threshold to hit an operator-chosen false-positive budget on the new
backend's own traffic.

That is a deliberate design choice, not a shortcut:

  * Fine-tuning an autoencoder on a short window of new traffic invites
    catastrophic forgetting - the network drifts toward the calibration window
    and loses the general notion of "normal" it learned from the full corpus.
  * Any online adaptation is a poisoning surface. An attacker who can generate
    traffic during the calibration window teaches the model that their traffic
    is normal. Threshold + baseline recalibration bounds that damage; weight
    updates do not.

Because the feature set is deliberately path-agnostic (see common/features.py),
what actually has to change between backends is small: what body sizes are
typical per endpoint, how fast clients usually go, and where the cut-off sits.

PROCEDURE
---------
  1. Run the gateway in monitor mode in front of the new backend.
  2. Send or allow representative NORMAL traffic. No attacks.
  3. Run this script. It refuses to proceed if the sample is too small or looks
     contaminated.
  4. Reload the gateway (POST /__guard/reload) and switch to enforce.
"""
import argparse
import json
import os
import shutil
import sys
import time
from collections import Counter, defaultdict

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config, features, rules            # noqa: E402
from common.features import Baseline, _safe_z         # noqa: E402

import joblib                                         # noqa: E402
import pickle                                         # noqa: E402

RULE_SEVERITY = {r.id: r.severity for r in rules.RULES}


def load_events(path, since=None):
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if since and r.get("ts", 0) < since:
                continue
            if r.get("features"):
                out.append(r)
    return out


def contamination_report(rows):
    """How much of the calibration window looks hostile?"""
    blocked = sum(1 for r in rows
                  if any(RULE_SEVERITY.get(h) == rules.BLOCK
                         for h in r.get("rule_hits", [])))
    flagged = sum(1 for r in rows if r.get("rule_hits"))
    return blocked, flagged


def build_baseline(rows) -> Baseline:
    per = defaultdict(list)
    rates = []
    for r in rows:
        per[r.get("template", "/")].append(float(r.get("body_size", 0)))
        rates.append(float(np.expm1(r["features"].get("win_log_count", 0.0))))
    endpoints = {}
    for tpl, sizes in per.items():
        if len(sizes) < 5:
            continue
        endpoints[tpl] = {"body_mean": float(np.mean(sizes)),
                          "body_std": float(np.std(sizes)),
                          "count": len(sizes)}
    return Baseline({
        "endpoints": endpoints,
        "rate": {"mean": float(np.mean(rates)) if rates else 0.0,
                 "std": float(np.std(rates)) if rates else 0.0},
        "n_samples": len(rows),
    })


def main():
    ap = argparse.ArgumentParser(description="Calibrate MicroAPI Guard to a new backend")
    ap.add_argument("--models-dir", default=config.MODELS_DIR)
    ap.add_argument("--events", default=config.EVENT_LOG)
    ap.add_argument("--target-fpr", type=float, default=config.CALIBRATION_TARGET_FPR)
    ap.add_argument("--min-samples", type=int, default=config.CALIBRATION_MIN_SAMPLES)
    ap.add_argument("--max-contamination", type=float, default=0.02,
                    help="abort if more than this fraction trips a BLOCK rule")
    ap.add_argument("--since-minutes", type=int, default=None,
                    help="only use events from the last N minutes")
    ap.add_argument("--force", action="store_true", help="override safety gates")
    args = ap.parse_args()

    print("=" * 68)
    print("  MicroAPI Guard - backend calibration")
    print("=" * 68)

    since = time.time() - args.since_minutes * 60 if args.since_minutes else None
    rows = load_events(args.events, since)
    print(f"\n  calibration window : {len(rows):,} events")

    # ── gate 1: enough data ──────────────────────────────────────────────────
    if len(rows) < args.min_samples and not args.force:
        print(f"  ABORT: need >= {args.min_samples:,} events, have {len(rows):,}.")
        print("  A baseline built from too little traffic is unstable: the")
        print("  thresholds it produces will swing with normal daily variation.")
        return 1

    # ── gate 2: contamination ────────────────────────────────────────────────
    blocked, flagged = contamination_report(rows)
    frac = blocked / max(1, len(rows))
    print(f"  rule-blocking events : {blocked:,} ({frac:.2%})")
    print(f"  rule-flagged events  : {flagged:,}")
    if frac > args.max_contamination and not args.force:
        print(f"\n  ABORT: {frac:.2%} of the window trips a BLOCK rule "
              f"(limit {args.max_contamination:.2%}).")
        print("  Calibrating on traffic that contains attacks teaches the")
        print("  system that those attacks are normal. Collect a clean window.")
        return 1

    # Attack-looking traffic is excluded from the baseline regardless.
    clean = [r for r in rows
             if not any(RULE_SEVERITY.get(h) == rules.BLOCK
                        for h in r.get("rule_hits", []))]
    print(f"  clean events used    : {len(clean):,}")

    # ── build the new baseline ───────────────────────────────────────────────
    new_bl = build_baseline(clean)
    print(f"\n  endpoint templates   : {len(new_bl.endpoints)}")
    print(f"  rate mean/std        : {new_bl.rate_mean:.2f} / {new_bl.rate_std:.2f}")

    old_path = os.path.join(args.models_dir, "calibration.json")
    old_bl = None
    if os.path.exists(old_path):
        with open(old_path) as fh:
            old_bl = Baseline(json.load(fh))
        shared = set(old_bl.endpoints) & set(new_bl.endpoints)
        only_new = set(new_bl.endpoints) - set(old_bl.endpoints)
        print(f"  shared endpoints     : {len(shared)}")
        print(f"  new endpoints        : {len(only_new)}")
        if old_bl.rate_std > 0:
            drift = abs(new_bl.rate_mean - old_bl.rate_mean) / (old_bl.rate_std + 1e-9)
            print(f"  rate drift           : {drift:.2f} sd from previous baseline")
            if drift > 3:
                print("    NOTE: large drift. Verify this window is representative")
                print("          before enforcing with it.")

    # ── re-score with the EXISTING base models (no refit) ────────────────────
    print("\n  scoring calibration traffic with the existing detectors")
    print("  (base models are NOT refitted - no catastrophic forgetting)")
    with open(os.path.join(args.models_dir, "decision.json")) as fh:
        decision = json.load(fh)
    if decision.get("feature_names") != features.FEATURE_NAMES:
        print("  ABORT: feature contract mismatch; retrain instead of calibrating.")
        return 1

    scaler = joblib.load(os.path.join(args.models_dir, "scaler.pkl"))
    iforest = joblib.load(os.path.join(args.models_dir, "isolation_forest.pkl"))
    meta_lr = joblib.load(os.path.join(args.models_dir, "meta_lr.pkl"))
    with open(os.path.join(args.models_dir, "autoencoder.pkl"), "rb") as fh:
        ae = pickle.load(fh)

    # Recompute baseline-relative features with the NEW baseline, exactly as
    # the gateway will once it reloads.
    for r in clean:
        f = r["features"]
        window = float(np.expm1(f.get("win_log_count", 0.0)))
        f["rate_z"] = _safe_z(window, new_bl.rate_mean, new_bl.rate_std)
        st = new_bl.body_stats(r.get("template", "/"))
        f["body_size_z"] = _safe_z(float(r.get("body_size", 0)), st[0], st[1]) if st else 0.0
        f["path_known"] = 1.0 if new_bl.knows(r.get("template", "/")) else 0.0

    X = features.to_matrix([r["features"] for r in clean])
    Xs = scaler.transform(X)
    i_n = np.clip((-iforest.decision_function(Xs) - decision["if_lo"]) /
                  (decision["if_hi"] - decision["if_lo"] + 1e-9), 0, 1)
    a_n = np.clip((ae.score(Xs) - decision["ae_lo"]) /
                  (decision["ae_hi"] - decision["ae_lo"] + 1e-9), 0, 1)
    rate = np.clip([np.expm1(r["features"].get("win_log_count", 0.0))
                    for r in clean], 0, None) / max(1, config.RATE_LIMIT)
    rate = np.clip(rate, 0, 1)
    p = meta_lr.predict_proba(np.column_stack([rate, i_n, a_n]))[:, 1]

    # ── threshold for the requested false-positive budget ────────────────────
    # The window is assumed to be (mostly) normal, so the threshold that yields
    # the target FPR is simply the corresponding upper percentile of scores.
    new_thr = float(np.percentile(p, 100.0 * (1.0 - args.target_fpr)))
    new_thr = float(min(0.999, max(0.05, new_thr)))
    would_block = float((p >= new_thr).mean())

    print(f"\n  score distribution   : p50={np.percentile(p,50):.4f}  "
          f"p95={np.percentile(p,95):.4f}  p99={np.percentile(p,99):.4f}  "
          f"max={p.max():.4f}")
    print(f"  previous threshold   : {decision.get('threshold'):.4f}")
    print(f"  calibrated threshold : {new_thr:.4f}  "
          f"(target FPR {args.target_fpr:.2%}, observed {would_block:.2%})")

    # Saturation check. If a slab of legitimate traffic scores at the very top
    # of the range, no threshold separates it from attacks - raising the cut
    # just walks up a vertical cliff. Calibration cannot fix this; only better
    # features or training traffic that covers this client population can.
    ceiling = float((p >= 0.999).mean())
    if would_block > 2 * args.target_fpr:
        print(f"\n  WARNING: cannot reach the target false-positive budget.")
        print(f"           {ceiling:.2%} of this window scores >= 0.999, i.e. it is")
        print("           saturated at the top of the range and is therefore")
        print("           inseparable from attack traffic at ANY threshold.")
        print("           Calibration is not the remedy here - the model needs")
        print("           training traffic that covers this client population,")
        print("           or features that discriminate it. Deploy in monitor")
        print("           mode and review the flagged requests before enforcing.")

    if new_thr < 0.2 and not args.force:
        print("\n  ABORT: calibrated threshold is implausibly low, which means the")
        print("  window scores as anomalous overall. That usually indicates the")
        print("  traffic is not representative, or is contaminated.")
        return 1

    # ── gate 3: is the window actually normal? ───────────────────────────────
    #
    # The percentile rule assumes the window is mostly normal traffic. If the
    # median request already scores as an anomaly, that assumption is false and
    # the percentile is measuring the wrong distribution - it will happily push
    # the threshold up until almost nothing is blocked, silently disabling the
    # detector. Refuse instead.
    #
    # This gate exists because the first real calibration run hit exactly that
    # case: a single client sent 900 req/min against a 240 req/min limit, every
    # request scored 1.0, and the script wrote a 0.999 threshold anyway.
    median = float(np.median(p))
    if median >= 0.5 and not args.force:
        print(f"\n  ABORT: median score is {median:.4f} - the window scores as")
        print("  anomalous overall, so it cannot define 'normal'. Common causes:")
        print(f"    - the traffic exceeds the configured rate limit "
              f"({config.RATE_LIMIT}/{config.RATE_WINDOW_SECS}s per client), so")
        print("      it is abusive by the system's own policy;")
        print("    - it all originates from one client while the model expects")
        print("      many distinct clients;")
        print("    - the window contains attacks.")
        print("  Collect a window that resembles real production traffic.")
        return 1

    prev_thr = float(decision.get("threshold", 0.5))
    if new_thr > prev_thr + 0.3 and not args.force:
        print(f"\n  ABORT: threshold would jump {prev_thr:.3f} -> {new_thr:.3f}.")
        print("  A large upward jump means this window looks far more anomalous")
        print("  than training did, and accepting it would blunt the detector.")
        return 1

    # ── persist (with a backup) ──────────────────────────────────────────────
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for name in ("calibration.json", "decision.json"):
        src = os.path.join(args.models_dir, name)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(args.models_dir, f"{name}.{stamp}.bak"))

    with open(os.path.join(args.models_dir, "calibration.json"), "w") as fh:
        json.dump(new_bl.to_dict(), fh, indent=2)

    decision["threshold"] = new_thr
    decision["calibrated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    decision["calibration_samples"] = len(clean)
    decision["calibration_target_fpr"] = args.target_fpr
    decision["calibration_observed_fpr"] = round(would_block, 4)
    with open(os.path.join(args.models_dir, "decision.json"), "w") as fh:
        json.dump(decision, fh, indent=2)

    print(f"\n  written. backups saved with suffix .{stamp}.bak")
    print("  next: curl -X POST http://<gateway>/__guard/reload")
    print("        then restart with GUARD_MODE=enforce")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    sys.exit(main())
