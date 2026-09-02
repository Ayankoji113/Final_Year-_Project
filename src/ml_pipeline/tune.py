"""Hyperparameter search for the MicroAPI Guard stack.

WHY THIS EXISTS
===============
The reported single-split result (F1 0.929, zero-day recall 0.887 at seed 42)
is not what the pipeline does on average. Across ten seeds the mean F1 is 0.854
[0.812, 0.891] and the mean zero-day recall is 0.598 [0.445, 0.749]. A confidence
interval that wide means the headline number is largely a statement about which
seed was picked, not about the method.

So the objective here is the multi-seed mean, and shrinking its spread counts as
much as raising it.

WHAT MAKES THE RESULT QUOTABLE
==============================
Two separations, both of which have to hold or the tuned number means nothing:

1. Search seeds vs reporting seeds.
   `pool_of()` in train.py hashes `client|SEED`, so a different seed produces a
   completely different session -> pool partition. This search runs on seeds
   11-15. `validate.py` reports on seeds 1-10. The sessions this search selects
   against are therefore not the sessions the final number is measured on.

2. Real zero-days vs pseudo zero-days.
   The headline zero-day claim rests on cmdi/ssti/exfil never appearing in
   training. Tuning against those families would quietly destroy that claim -
   the hyperparameters would have been chosen with knowledge of the very attacks
   we say the model has never seen.

   Instead the search overrides TRAIN_NOVEL to a DIFFERENT triple
   (bruteforce, scan, flood) drawn from the same family list. That yields a
   genuine unseen-family recall signal to optimise against, while cmdi/ssti/exfil
   stay untouched until the confirmation run.

   This is the honest answer to "how do you tune for zero-day detection without
   seeing the zero-days": you hold out a different set of days.

THE OBJECTIVE
=============
    score = 0.5 * val_f1 + 0.5 * pseudo_zero_day_recall

`val_f1` is measured on the validation pool, which is what the threshold is
already chosen on. The zero-day half is what the panel's question actually
targets, so it gets equal weight rather than being an afterthought.

USAGE
=====
    python ml_pipeline/tune.py                  # full grid
    python ml_pipeline/tune.py --seeds 3        # quicker, noisier
    python ml_pipeline/tune.py --quick          # 4-config smoke run

Writes models/tuning.json. Applies nothing - the winning config is printed for
you to paste into train.py's defaults, so that promotion stays a deliberate act.
"""
import argparse
import itertools
import json
import os
import subprocess
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config  # noqa: E402

TRAIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "train.py")

# Seeds disjoint from validate.py's 1..10.
SEARCH_SEEDS = [11, 12, 13, 14, 15]

# Held out during the search INSTEAD of cmdi/exfil/ssti, so the real zero-day
# families never inform a hyperparameter choice. Drawn from FAMILIES in
# traffic_simulator/generate.py.
#
# The choice of triple is not arbitrary. Most families are caught outright by
# Layer 1 and so barely reach the ML test pool - holding out xss/traversal/payload
# leaves n=6 unseen-family rows, and a recall computed over six samples is noise
# dressed as a metric. bruteforce, scan and flood are the families that actually
# survive L1 in volume (~800 rows combined), so they give the search a signal
# with enough samples to rank configurations by.
PSEUDO_NOVEL = "bruteforce,scan,flood"

GRID = {
    "TRAIN_AE_NOISE": ["0.0", "0.05", "0.1", "0.2"],
    "TRAIN_AE_BOTTLENECK": ["8", "12", "16"],
    "TRAIN_META": ["lr", "hgb"],
}

QUICK_GRID = {
    "TRAIN_AE_NOISE": ["0.0", "0.1"],
    "TRAIN_AE_BOTTLENECK": ["12"],
    "TRAIN_META": ["lr", "hgb"],
}


def configs(grid):
    keys = list(grid)
    for combo in itertools.product(*(grid[k] for k in keys)):
        yield dict(zip(keys, combo))


# Search runs write here instead of models/, so a few hundred throwaway
# retrains cannot clobber the artefacts the gateway is currently serving.
SCRATCH = os.path.join(config.MODELS_DIR + "_tuning")


def run_once(cfg, seed):
    """One training run. Returns (val_f1, pseudo_zero_day_recall) or None."""
    env = dict(os.environ, TRAIN_SEED=str(seed), TRAIN_NOVEL=PSEUDO_NOVEL,
               MODELS_DIR=SCRATCH, **cfg)
    r = subprocess.run([sys.executable, TRAIN], env=env,
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"        seed {seed} FAILED: {r.stdout[-400:]}{r.stderr[-400:]}")
        return None
    with open(os.path.join(SCRATCH, "decision.json")) as fh:
        d = json.load(fh)
    zd = d.get("zero_day_recall")
    return float(d["val_f1"]), (float(zd) if zd is not None else 0.0)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seeds", type=int, default=len(SEARCH_SEEDS),
                    help="how many search seeds to average over (max 5)")
    ap.add_argument("--quick", action="store_true", help="4-config smoke run")
    ap.add_argument("--out", default=os.path.join(config.MODELS_DIR, "tuning.json"))
    # config.EVENT_LOG points at events.jsonl, which is the gateway's live
    # unlabelled log - training on it yields zero labelled rows. The labelled
    # corpus is a separate file, so make it the default here rather than
    # letting every run need the env var.
    ap.add_argument("--events", default=os.getenv(
        "TRAIN_EVENT_LOG", os.path.join(config.DATA_DIR, "events_training.jsonl")))
    args = ap.parse_args()
    if not os.path.exists(args.events):
        print(f"  ERROR: no labelled corpus at {args.events}")
        return 1
    os.environ["TRAIN_EVENT_LOG"] = args.events

    seeds = SEARCH_SEEDS[:max(1, min(args.seeds, len(SEARCH_SEEDS)))]
    grid = QUICK_GRID if args.quick else GRID
    all_cfgs = list(configs(grid))

    print("=" * 72)
    print("  HYPERPARAMETER SEARCH")
    print("=" * 72)
    print(f"  corpus       {args.events}")
    print(f"  configs      {len(all_cfgs)}")
    print(f"  search seeds {seeds}   (reporting seeds 1-10 are untouched)")
    print(f"  pseudo-novel {PSEUDO_NOVEL}   (real zero-days cmdi/exfil/ssti untouched)")
    print(f"  objective    0.5*val_f1 + 0.5*pseudo_zero_day_recall")
    print(f"  runs         {len(all_cfgs) * len(seeds)}")

    t0 = time.time()
    results = []
    for n, cfg in enumerate(all_cfgs, 1):
        label = "  ".join(f"{k.replace('TRAIN_', '').lower()}={v}"
                          for k, v in cfg.items())
        print(f"\n[{n}/{len(all_cfgs)}] {label}")
        f1s, zds = [], []
        for s in seeds:
            got = run_once(cfg, s)
            if got is None:
                continue
            f1, zd = got
            f1s.append(f1)
            zds.append(zd)
            print(f"        seed {s}: val_f1={f1:.4f}  pseudo_zd={zd:.4f}")
        if not f1s:
            print("        no successful runs, skipping config")
            continue
        mf1, mzd = float(np.mean(f1s)), float(np.mean(zds))
        score = 0.5 * mf1 + 0.5 * mzd
        results.append({"config": cfg, "seeds": seeds[:len(f1s)],
                        "val_f1": f1s, "pseudo_zero_day": zds,
                        "mean_val_f1": mf1, "mean_pseudo_zero_day": mzd,
                        "sd_val_f1": float(np.std(f1s)),
                        "sd_pseudo_zero_day": float(np.std(zds)),
                        "score": score})
        print(f"        MEAN val_f1={mf1:.4f} (sd {np.std(f1s):.4f})  "
              f"pseudo_zd={mzd:.4f} (sd {np.std(zds):.4f})  score={score:.4f}")

    if not results:
        print("\n  Every config failed. Check that the event log exists.")
        return 1

    results.sort(key=lambda r: r["score"], reverse=True)

    print("\n" + "=" * 72)
    print("  RANKING")
    print("=" * 72)
    print(f"  {'rank':>4s}  {'score':>7s} {'val_f1':>8s} {'sd':>7s} "
          f"{'pseudo_zd':>10s} {'sd':>7s}  config")
    for i, r in enumerate(results, 1):
        label = " ".join(f"{k.replace('TRAIN_', '').lower()}={v}"
                         for k, v in r["config"].items())
        print(f"  {i:4d}  {r['score']:7.4f} {r['mean_val_f1']:8.4f} "
              f"{r['sd_val_f1']:7.4f} {r['mean_pseudo_zero_day']:10.4f} "
              f"{r['sd_pseudo_zero_day']:7.4f}  {label}")

    best = results[0]
    print("\n" + "=" * 72)
    print("  WINNER")
    print("=" * 72)
    for k, v in best["config"].items():
        print(f"    {k}={v}")
    print(f"\n  Set these as the defaults in train.py, then CONFIRM on the")
    print(f"  untouched seeds - the search score is not a reportable result:")
    print(f"    python ml_pipeline/validate.py --seeds 10")
    print(f"    python ml_pipeline/compare.py")

    # A win inside the seed-to-seed noise is not a win.
    if len(results) > 1:
        margin = best["score"] - results[1]["score"]
        noise = best["sd_val_f1"] / max(1, len(best["val_f1"])) ** 0.5
        if margin < noise:
            print(f"\n  CAUTION: the winner beats second place by {margin:.4f}, which is")
            print(f"  inside the standard error of the mean ({noise:.4f}). Prefer the")
            print("  simpler config, or re-run with more seeds before promoting.")

    with open(args.out, "w") as fh:
        json.dump({"search_seeds": seeds, "pseudo_novel": PSEUDO_NOVEL,
                   "objective": "0.5*val_f1 + 0.5*pseudo_zero_day_recall",
                   "results": results, "best": best["config"]}, fh, indent=2)
    print(f"\n  written: {args.out}   ({time.time() - t0:.0f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
