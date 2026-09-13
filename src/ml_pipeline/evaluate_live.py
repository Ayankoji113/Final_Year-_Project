"""Score a labelled corpus through the real gateway and report every metric.

WHY THIS EXISTS
---------------
`train.py` reports on pools drawn from the same generator that produced its
training data, so its numbers describe how well the model fits that generator —
not how it behaves on traffic it has not seen. The shipped model scores F1 0.99
on its own held-out test pool and 45.8% false positives on real requests.

This harness closes that gap. It replays a corpus whose labels are known by
construction, reads back what the gateway actually did, and reports the metrics
that decide whether ML enforcement is safe:

  - false-positive rate, overall AND per endpoint, because the failure is
    per-endpoint: four endpoints measured 100% while three measured 0%, and an
    aggregate number hides that completely
  - recall split into attacks Layer 1 already blocks and attacks only ML can
    catch, because only the second group justifies ML enforcement at all
  - separability (ROC-AUC / PR-AUC) on Layer-1 survivors
  - autoencoder saturation, the mechanism behind the false positives

RUN IT INSIDE THE GATEWAY CONTAINER. The host has scikit-learn 1.9.0 and the
models were pickled under the pinned 1.4.1.post1, so `Detector.load()` fails on
the host with a confusing unpickling error.

    docker run --rm -i \
      -v "$PWD/data:/app/data:ro" -v "$PWD/ml_pipeline/models:/app/m:ro" \
      -v "$PWD/eval_corpus.json:/app/corpus.json:ro" \
      --entrypoint python src-gateway /app/ml_pipeline/evaluate_live.py \
      --corpus /app/corpus.json --events /app/data/events.jsonl --models /app/m

Two modes:
  --from-log     score using the probabilities the GATEWAY recorded (what
                 production actually did — the default, and the honest one)
  --models DIR   re-score the logged feature vectors through a different model
                 set, so candidate models can be compared on identical traffic
                 without re-sending a single request
"""
import argparse
import json
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np                                  # noqa: E402

from common import features                         # noqa: E402


# ── loading ──────────────────────────────────────────────────────────────────

def load_corpus(path):
    """Return (corpus, window). `window` is the (start, end) wall-clock span the
    client recorded while sending.

    The window matters more than it looks. The event log is append-only and
    shared with every other run, so without it the in-order (method, template)
    pairing happily matches corpus rows against leftovers from a previous run.
    That produced a confident 16.67% "Layer 1 false positive rate" on a set of
    requests Layer 1 had not touched at all."""
    with open(path, "r", encoding="utf-8") as fh:
        d = json.load(fh)
    if isinstance(d, dict):
        return d["corpus"], (d.get("started_at"), d.get("finished_at"))
    return d, (None, None)


def load_events(path, tail, window=(None, None)):
    lo, hi = window
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            ts = r.get("ts", 0)
            if lo is not None and ts < lo:
                continue
            if hi is not None and ts > hi:
                continue
            rows.append(r)
    return rows[-tail:] if tail else rows


def align(corpus, events):
    """Pair each sent request with the event the gateway logged for it.

    The gateway logs a normalised `template`, not the raw path, so matching is
    on (method, template) in order. The log is append-only and the client sends
    serially, so order is reliable. Any row that cannot be paired is dropped and
    counted rather than guessed at — a mislabelled row would corrupt every
    number below it.
    """
    import re
    def tmpl(p):
        p = p.split("?", 1)[0]
        segs = []
        for s in p.split("/"):
            if not s:
                continue
            if s.isdigit() or re.fullmatch(r"[0-9a-f]{8}-?[0-9a-f-]{4,}", s, re.I):
                segs.append("{id}")
            else:
                segs.append(s)
        return "/" + "/".join(segs)

    paired, unpaired = [], 0
    ev = list(events)
    for c in corpus:
        want = (c["method"], tmpl(c["path"]))
        hit = None
        for i, e in enumerate(ev):
            if (e.get("method"), e.get("template")) == want:
                hit = ev.pop(i)
                break
        if hit is None:
            unpaired += 1
        else:
            paired.append((c, hit))
    return paired, unpaired


# ── metric helpers ───────────────────────────────────────────────────────────

def pct(vals, p):
    if len(vals) == 0:
        return float("nan")
    s = sorted(vals)
    return s[min(len(s) - 1, max(0, int(math.ceil(p / 100 * len(s))) - 1))]


def auc(pos, neg):
    """Probability a random attack outscores a random benign request.

    Written out rather than imported from sklearn.metrics so this file runs even
    where sklearn cannot unpickle the models.
    """
    if not pos or not neg:
        return float("nan")
    wins = sum(1 for a in pos for b in neg if a > b)
    ties = sum(1 for a in pos for b in neg if a == b)
    return (wins + 0.5 * ties) / (len(pos) * len(neg))


def pr_auc(pos, neg):
    """Average precision, by sweeping every observed score as a threshold."""
    if not pos or not neg:
        return float("nan")
    scored = sorted([(s, 1) for s in pos] + [(s, 0) for s in neg], reverse=True)
    tp = fp = 0
    total = len(pos)
    prev_recall, area = 0.0, 0.0
    for s, y in scored:
        tp += y
        fp += 1 - y
        recall = tp / total
        precision = tp / (tp + fp)
        area += precision * (recall - prev_recall)
        prev_recall = recall
    return area


def rate(n, d):
    return float("nan") if d == 0 else n / d


# ── report ───────────────────────────────────────────────────────────────────

def report(paired, unpaired, threshold, label):
    l1 = lambda e: e["action"] == "block" and e["layer"] in ("L1-rules", "L1-rate")   # noqa: E731

    benign = [(c, e) for c, e in paired if c["label"] == "normal"]
    attack = [(c, e) for c, e in paired if c["label"] == "attack"]
    b_surv = [(c, e) for c, e in benign if not l1(e)]
    a_surv = [(c, e) for c, e in attack if not l1(e)]

    print("=" * 78)
    print(f"  {label}")
    print("=" * 78)
    print(f"  paired {len(paired)} requests   unpaired {unpaired}"
          f"{'  <-- investigate' if unpaired > len(paired) * 0.05 else ''}")
    print(f"  benign {len(benign)}  ({len(b_surv)} reach the models)")
    print(f"  attack {len(attack)}  ({len(a_surv)} reach the models)")
    print(f"  decision threshold {threshold:.4f}")

    # ── the number the whole exercise is about ──────────────────────────────
    l1_fp = sum(1 for c, e in benign if l1(e))
    ml_fp = sum(1 for c, e in b_surv if e.get("probability", 0) >= threshold)
    print()
    print("  FALSE POSITIVES on legitimate traffic")
    print(f"    Layer 1 blocks today          {l1_fp:>5} / {len(benign):<5} "
          f"{rate(l1_fp, len(benign)):>7.2%}")
    print(f"    ML would block under enforce  {ml_fp:>5} / {len(benign):<5} "
          f"{rate(ml_fp, len(benign)):>7.2%}   <-- the gate is 1.00%")

    print()
    print("  FALSE POSITIVES per endpoint   (an aggregate hides the real shape)")
    from collections import Counter
    tot = Counter(e["template"] for c, e in b_surv)
    bad = Counter(e["template"] for c, e in b_surv
                  if e.get("probability", 0) >= threshold)
    print(f"    {'endpoint':<34}{'ML+':>6}{'sent':>7}{'rate':>9}  gate")
    for t, n in sorted(tot.items(), key=lambda kv: (-kv[1][0] if isinstance(kv[1], tuple) else -kv[1])):
        r = rate(bad.get(t, 0), n)
        mark = "PASS" if r <= 0.01 else "fail"
        print(f"    {t:<34}{bad.get(t, 0):>6}{n:>7}{r:>9.1%}  {mark}")
    qualified = [t for t, n in tot.items() if rate(bad.get(t, 0), n) <= 0.01]
    print(f"    -> {len(qualified)} of {len(tot)} endpoints qualify for ML enforcement")

    # ── detection ───────────────────────────────────────────────────────────
    a_l1 = sum(1 for c, e in attack if l1(e))
    a_ml = sum(1 for c, e in a_surv if e.get("probability", 0) >= threshold)
    print()
    print("  DETECTION")
    print(f"    blocked by Layer 1            {a_l1:>5} / {len(attack):<5} "
          f"{rate(a_l1, len(attack)):>7.1%}")
    print(f"    caught by ML only             {a_ml:>5} / {len(a_surv):<5} "
          f"{rate(a_ml, len(a_surv)):>7.1%}   <-- ML's whole justification")
    print(f"    missed by both                {len(a_surv) - a_ml:>5} / {len(attack):<5}")

    fams = {}
    for c, e in attack:
        f = c.get("family") or "?"
        d = fams.setdefault(f, [0, 0, 0])
        d[0] += 1
        if l1(e):
            d[1] += 1
        elif e.get("probability", 0) >= threshold:
            d[2] += 1
    print(f"    {'family':<14}{'n':>5}{'L1':>5}{'ML':>5}{'missed':>8}")
    for f, (n, a, b) in sorted(fams.items()):
        print(f"    {f:<14}{n:>5}{a:>5}{b:>5}{n - a - b:>8}")

    # ── separability ────────────────────────────────────────────────────────
    pb = [e.get("probability", 0.0) for c, e in b_surv]
    pa = [e.get("probability", 0.0) for c, e in a_surv]
    tp, fp = a_ml, ml_fp
    fn, tn = len(a_surv) - a_ml, len(b_surv) - ml_fp
    prec = rate(tp, tp + fp)
    rec = rate(tp, tp + fn)
    f1 = float("nan") if (prec != prec or rec != rec or prec + rec == 0) else 2 * prec * rec / (prec + rec)
    print()
    print("  SEPARABILITY on Layer-1 survivors")
    print(f"    precision {prec:>7.4f}   recall {rec:>7.4f}   F1 {f1:>7.4f}")
    print(f"    ROC-AUC   {auc(pa, pb):>7.4f}   PR-AUC {pr_auc(pa, pb):>7.4f}"
          f"     (0.5 = coin flip)")
    print(f"    benign  p50 {pct(pb, 50):.4f}  p95 {pct(pb, 95):.4f}  p99 {pct(pb, 99):.4f}")
    print(f"    attack  p50 {pct(pa, 50):.4f}  p95 {pct(pa, 95):.4f}")

    sat = sum(1 for c, e in b_surv
              if (e.get("scores") or {}).get("autoencoder", 0) >= 0.999)
    print(f"    autoencoder saturated on {sat} / {len(b_surv)} benign rows "
          f"({rate(sat, len(b_surv)):.1%})")

    # ── latency ─────────────────────────────────────────────────────────────
    det = [e["detect_ms"] for c, e in paired if "detect_ms" in e]
    lat = [e["latency_ms"] for c, e in paired if "latency_ms" in e]
    print()
    print("  LATENCY")
    print(f"    detection  p50 {pct(det, 50):>7.2f}  p95 {pct(det, 95):>7.2f}  "
          f"p99 {pct(det, 99):>7.2f} ms")
    print(f"    end to end p50 {pct(lat, 50):>7.2f}  p95 {pct(lat, 95):>7.2f}  "
          f"p99 {pct(lat, 99):>7.2f} ms")

    return {"benign": len(benign), "attack": len(attack),
            "fp_l1": rate(l1_fp, len(benign)), "fp_ml": rate(ml_fp, len(benign)),
            "recall_l1": rate(a_l1, len(attack)), "recall_ml_only": rate(a_ml, len(a_surv)),
            "precision": prec, "recall": rec, "f1": f1,
            "roc_auc": auc(pa, pb), "pr_auc": pr_auc(pa, pb),
            "endpoints_qualified": len(qualified), "endpoints_total": len(tot),
            "ae_saturated": rate(sat, len(b_surv)),
            "detect_p50": pct(det, 50), "detect_p95": pct(det, 95),
            "threshold": threshold}


def rescore(paired, models_dir):
    """Re-score the logged feature vectors through a different model set.

    The gateway already wrote the exact feature vector it used, so a candidate
    model can be compared on byte-identical inputs without re-sending traffic.
    """
    from gateway.detector import Detector
    det = Detector()
    if not det.load(models_dir):
        raise SystemExit(f"could not load models from {models_dir}")
    m = det.meta
    FN = features.FEATURE_NAMES

    usable = [(c, e) for c, e in paired if len(e.get("features") or {}) == len(FN)]
    X = np.array([[float(e["features"].get(n, 0.0)) for n in FN] for c, e in usable],
                 dtype=np.float32)
    Xs = det.scaler.transform(X)
    i = np.clip((-det.iforest.decision_function(Xs) - m["if_lo"]) /
                (m["if_hi"] - m["if_lo"] + 1e-9), 0, 1)
    a = np.clip((det.autoencoder.score(Xs) - m["ae_lo"]) /
                (m["ae_hi"] - m["ae_lo"] + 1e-9), 0, 1)
    # The rate input is reconstructed as zero: these are replayed rows, and the
    # live counters that produced the original score are gone. Stated here
    # because it makes re-scored numbers slightly conservative on rate-driven
    # attacks rather than silently different.
    p = det.meta_lr.predict_proba(np.column_stack([np.zeros(len(Xs)), i, a]))[:, 1]

    out = []
    for (c, e), prob, aen in zip(usable, p, a):
        e2 = dict(e)
        e2["probability"] = float(prob)
        e2["scores"] = dict(e.get("scores") or {}, autoencoder=float(aen))
        out.append((c, e2))
    return out, det.threshold


def _trained_threshold(models_dir, fallback):
    try:
        with open(os.path.join(models_dir, "decision.json"), "r", encoding="utf-8") as fh:
            return float(json.load(fh)["threshold"])
    except Exception:
        return fallback


def main():
    ap = argparse.ArgumentParser(description="Score a labelled corpus through the gateway")
    ap.add_argument("--corpus", required=True, help="JSON from validate_client.py")
    ap.add_argument("--events", default=None, help="path to events.jsonl")
    ap.add_argument("--tail", type=int, default=0,
                    help="only consider the last N log rows (0 = all)")
    ap.add_argument("--models", default=None,
                    help="re-score through this model set instead of using logged probabilities")
    ap.add_argument("--threshold", type=float, default=None)
    ap.add_argument("--out", default=None, help="write the summary as JSON")
    args = ap.parse_args()

    from common import config
    events_path = args.events or config.EVENT_LOG

    corpus, window = load_corpus(args.corpus)
    if window[0] is None:
        print("  NOTE: this corpus carries no send window, so pairing falls back to "
              "order alone and may match rows from an earlier run. Re-send with a "
              "current validate_client.py to get an anchored measurement.")
    events = load_events(events_path, args.tail, window)
    paired, unpaired = align(corpus, events)
    if not paired:
        raise SystemExit("no corpus row could be paired with a log entry — wrong "
                         "--events file, or the traffic was never sent")

    label = "AS THE GATEWAY DECIDED  (logged probabilities)"
    threshold = args.threshold
    if args.models:
        paired, trained_thr = rescore(paired, args.models)
        threshold = args.threshold if args.threshold is not None else trained_thr
        label = f"RE-SCORED THROUGH {args.models}"
    if threshold is None:
        # The gateway decides with the TRAINED threshold from decision.json, not
        # the env fallback. Scoring against config.ML_THRESHOLD (0.5) when the
        # gateway is using 0.25 reports a system that does not exist.
        threshold = _trained_threshold(args.models or config.MODELS_DIR,
                                       config.ML_THRESHOLD)

    summary = report(paired, unpaired, threshold, label)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        print(f"\n  summary written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
