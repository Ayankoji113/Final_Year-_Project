"""Statistical validation - multi-seed confidence intervals and McNemar's test.

WHAT EACH TEST ACTUALLY TESTS, AND WHEN IT IS APPROPRIATE
=========================================================

Multi-seed confidence intervals
-------------------------------
Retrains the whole pipeline under N different seeds. The seed changes the
session->pool assignment, the Isolation Forest's sampling and the autoencoder's
initialisation, so the spread across seeds captures the variance that a single
run hides. A single-run F1 quoted to four decimals implies a precision the
experiment does not have.

We report a bootstrap percentile interval over the seed means rather than
mean +/- 1.96*sd, because with N=10 the normal approximation is doing more work
than the data supports.

McNemar's test
--------------
Tests whether two classifiers DISAGREE asymmetrically on the SAME test set. It
uses only the discordant pairs: b = A right/B wrong, c = A wrong/B right. The
null hypothesis is b == c.

  APPROPRIATE  : stack vs autoencoder-only on the identical test rows - paired,
                 same samples, binary correct/incorrect outcomes.
  INAPPROPRIATE: comparing models evaluated on different test sets or different
                 seeds. Those are unpaired, and McNemar's pairing assumption is
                 exactly what makes it powerful. For across-seed comparison use
                 the confidence intervals above, or a paired t-test / Wilcoxon
                 signed-rank over per-seed scores.

We use the exact binomial version when b + c < 25, where the chi-square
approximation is unreliable. With continuity correction otherwise. This matters:
the uncorrected chi-square form is anti-conservative and will hand you
significance you have not earned.
"""
import argparse
import json
import os
import subprocess
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config  # noqa: E402

try:
    from scipy import stats as sps
except ImportError:
    sps = None


# ── McNemar ───────────────────────────────────────────────────────────────────

def mcnemar(correct_a, correct_b):
    """correct_a / correct_b: boolean arrays over the SAME test rows."""
    a = np.asarray(correct_a).astype(bool)
    b = np.asarray(correct_b).astype(bool)
    if a.shape != b.shape:
        raise ValueError("McNemar requires paired predictions on identical rows")

    n01 = int((a & ~b).sum())    # A right, B wrong
    n10 = int((~a & b).sum())    # A wrong, B right
    n = n01 + n10

    if n == 0:
        return {"n01": 0, "n10": 0, "p": 1.0, "method": "no discordant pairs",
                "significant": False}

    if n < 25:
        # Exact binomial: reliable when discordant pairs are few.
        if sps is not None:
            p = float(sps.binomtest(n01, n, 0.5).pvalue)
        else:
            from math import comb
            tail = sum(comb(n, k) for k in range(0, min(n01, n - n01) + 1)) / (2 ** n)
            p = float(min(1.0, 2 * tail))
        method = "exact binomial"
    else:
        chi2 = (abs(n01 - n10) - 1) ** 2 / n          # continuity-corrected
        if sps is not None:
            p = float(sps.chi2.sf(chi2, df=1))
        else:
            from math import erfc, sqrt
            p = float(erfc(sqrt(chi2 / 2.0)))
        method = "chi-square with continuity correction"

    return {"n01": n01, "n10": n10, "p": p, "method": method,
            "significant": p < 0.05}


def bootstrap_ci(values, n_boot=10000, alpha=0.05, seed=0):
    v = np.asarray(values, dtype=float)
    if len(v) < 2:
        return float(v.mean()), float("nan"), float("nan")
    rng = np.random.RandomState(seed)
    means = np.array([rng.choice(v, size=len(v), replace=True).mean()
                      for _ in range(n_boot)])
    return (float(v.mean()),
            float(np.percentile(means, 100 * alpha / 2)),
            float(np.percentile(means, 100 * (1 - alpha / 2))))


# ── multi-seed driver ─────────────────────────────────────────────────────────

# Scratch artefact directory, same discipline as tune.py. Without it every seed
# overwrites models/ and the shipped gateway artefacts become whichever seed ran
# last - not the canonical model. This has already happened once.
SCRATCH = config.MODELS_DIR + "_validate"


def run_seeds(seeds, train_script):
    """Retrain end to end under each seed and collect the test metrics."""
    runs = []
    for s in seeds:
        print(f"\n{'='*66}\n  SEED {s}\n{'='*66}")
        env = dict(os.environ, TRAIN_SEED=str(s), MODELS_DIR=SCRATCH)
        r = subprocess.run([sys.executable, train_script], env=env,
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"  seed {s} FAILED:\n{r.stdout[-1500:]}\n{r.stderr[-800:]}")
            continue
        with open(os.path.join(SCRATCH, "decision.json")) as fh:
            d = json.load(fh)
        m = d["test_metrics"]
        runs.append({"seed": s, "f1": m["f1"], "recall": m["recall"],
                     "precision": m["precision"], "fpr": m["fpr"],
                     "roc_auc": d["test_roc_auc"], "pr_auc": d["test_pr_auc"],
                     "zero_day_recall": d.get("zero_day_recall")})
        print(f"  seed {s}: f1={m['f1']:.4f} recall={m['recall']:.4f} "
              f"fpr={m['fpr']:.4f} auc={d['test_roc_auc']:.4f}")
    return runs


def main():
    ap = argparse.ArgumentParser(description="Statistical validation")
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--out", default=os.path.join(config.MODELS_DIR,
                                                  "validation.json"))
    args = ap.parse_args()

    train_script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "train.py")
    seeds = list(range(1, args.seeds + 1))
    runs = run_seeds(seeds, train_script)
    if len(runs) < 2:
        print("\n  Not enough successful runs for statistics.")
        return 1

    print(f"\n{'='*66}")
    print(f"  MULTI-SEED RESULTS  (n={len(runs)} seeds)")
    print(f"{'='*66}")
    print(f"  {'metric':18s} {'mean':>8s}  {'95% CI':>20s}  {'min':>8s} {'max':>8s}")
    summary = {}
    for key in ("f1", "recall", "precision", "fpr", "roc_auc", "pr_auc",
                "zero_day_recall"):
        vals = [r[key] for r in runs if r.get(key) is not None]
        if not vals:
            continue
        mean, lo, hi = bootstrap_ci(vals)
        summary[key] = {"mean": mean, "ci95": [lo, hi],
                        "min": min(vals), "max": max(vals), "n": len(vals)}
        print(f"  {key:18s} {mean:8.4f}  [{lo:8.4f}, {hi:8.4f}]  "
              f"{min(vals):8.4f} {max(vals):8.4f}")

    print("\n  Report these intervals, not a single run's four-decimal figure.")

    with open(args.out, "w") as fh:
        json.dump({"seeds": seeds, "runs": runs, "summary": summary}, fh, indent=2)
    print(f"\n  written: {args.out}")

    print(f"\n{'='*66}")
    print("  McNEMAR - stack vs best single detector")
    print(f"{'='*66}")
    print("  Requires paired per-row predictions from a single test split.")
    print("  Run:  python ml_pipeline/compare.py")
    print("  (McNemar across seeds would be invalid - the pairs differ.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
