"""Finalise the model: compare candidates across REPEATED independent client draws.

Every cross-generator figure in this project so far comes from a single run of
validate_client.py. Choosing a model on one draw is the same mistake the work
criticises, so this replays several independent corpora, each with a different
seed, and reports every candidate as a mean with a spread.

Selection rule, fixed BEFORE the numbers are seen:

  1. Decide on cross-generator performance. In-distribution results are
     diagnostic only - a model that fits its own generator and fails on
     anything else is not the better model.
  2. Rank by ROC-AUC, which measures how well a model orders attacks above
     legitimate traffic and does not depend on the threshold. The threshold is
     a separate choice and the current selection of it is known to be broken.
  3. Break ties on recall at the project's own 1% false-positive budget.
  4. Require the winner to beat the shipped model on the false-positive rate,
     since that is the defect this work exists to fix.

Run from src/, with the gateway up in enforce-l1 and the console serving
/__dash on 5173.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)


def run_client(seed, sessions, out):
    """Send one independent corpus through the live gateway."""
    cmd = [sys.executable, os.path.join(SRC, "traffic_simulator", "validate_client.py"),
           "--sessions", str(sessions), "--attack-ratio", "0.22",
           "--seed", str(seed), "--out", out, "--send", "--rps", "3"]
    r = subprocess.run(cmd, cwd=SRC, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-800:], r.stderr[-800:])
        raise SystemExit(f"client failed on seed {seed}")
    return r.stdout


def score(corpus_host, models_rel):
    """Score one corpus through one model set, inside the gateway container.

    The host has scikit-learn 1.9.0 and the artefacts were pickled under the
    pinned 1.4.1.post1, so this cannot run outside the container.
    """
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{SRC}/data:/app/data:ro".replace("\\", "/"),
        "-v", f"{SRC}/ml_pipeline:/app/ml_pipeline:ro".replace("\\", "/"),
        "-v", f"{corpus_host}:/app/corpus.json:ro".replace("\\", "/"),
        "--entrypoint", "python", "src-gateway",
        "/app/ml_pipeline/evaluate_live.py",
        "--corpus", "/app/corpus.json", "--events", "/app/data/events.jsonl",
        "--models", f"/app/ml_pipeline/{models_rel}",
    ]
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    t = r.stdout

    def g(pat, cast=float, default=float("nan")):
        m = re.search(pat, t)
        return cast(m.group(1)) if m else default

    return {
        "threshold": g(r"decision threshold ([0-9.]+)"),
        "fpr": g(r"ML would block under enforce\s+\d+ / \d+\s+([0-9.]+)%") / 100.0,
        "recall_ml": g(r"caught by ML only\s+\d+ / \d+\s+([0-9.]+)%") / 100.0,
        "precision": g(r"precision\s+([0-9.]+)"),
        "f1": g(r"F1\s+([0-9.]+)"),
        "roc_auc": g(r"ROC-AUC\s+([0-9.]+)"),
        "pr_auc": g(r"PR-AUC\s+([0-9.]+)"),
        "endpoints_ok": g(r"-> (\d+) of \d+ endpoints qualify", int, 0),
    }


def summarise(vals):
    vals = [v for v in vals if v == v]
    if not vals:
        return float("nan"), float("nan"), float("nan")
    n = len(vals)
    mean = sum(vals) / n
    return mean, min(vals), max(vals)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="*", default=[101, 202, 303, 404],
                    help="pass no values to score only --reuse corpora")
    ap.add_argument("--sessions", type=int, default=60)
    ap.add_argument("--models", nargs="+",
                    default=["models", "models_b3", "models_b4"])
    ap.add_argument("--reuse", nargs="*", default=[],
                    help="corpora already sent, to include without re-sending")
    ap.add_argument("--out", default=os.path.join(HERE, "model_selection.json"))
    args = ap.parse_args()

    corpora = list(args.reuse)
    for seed in args.seeds:
        path = os.path.join(SRC, f"eval_seed{seed}.json")
        print(f"[client] seed {seed}: sending ...", flush=True)
        t0 = time.time()
        run_client(seed, args.sessions, path)
        print(f"[client] seed {seed}: done in {time.time() - t0:.0f}s", flush=True)
        corpora.append(path)
        # The sliding window is 240 requests per 60 s. Back-to-back runs would
        # start inside the previous run's window and be rate-blocked, and a
        # rate-blocked request never reaches the models, so it would silently
        # vanish from the measurement instead of erroring.
        time.sleep(65)

    results = {m: [] for m in args.models}
    for path in corpora:
        for m in args.models:
            results[m].append(score(path, m))
            print(f"[score] {os.path.basename(path)} x {m}: "
                  f"fpr={results[m][-1]['fpr']:.4f} auc={results[m][-1]['roc_auc']:.4f}",
                  flush=True)

    print()
    print("=" * 78)
    print(f"  MODEL SELECTION  -  {len(corpora)} independent client draws")
    print("=" * 78)
    print(f"  {'model':<12}{'FPR mean':>11}{'range':>17}{'AUC mean':>11}{'range':>17}")
    for m in args.models:
        fm, flo, fhi = summarise([r["fpr"] for r in results[m]])
        am, alo, ahi = summarise([r["roc_auc"] for r in results[m]])
        print(f"  {m:<12}{fm:>10.2%} [{flo:>6.2%},{fhi:>7.2%}]{am:>11.4f} "
              f"[{alo:.4f},{ahi:.4f}]")
    print()
    print(f"  {'model':<12}{'recall':>10}{'precision':>11}{'F1':>9}{'PR-AUC':>9}{'eps ok':>8}")
    for m in args.models:
        for key, fmt in (("recall_ml", "{:>10.1%}"), ("precision", "{:>11.4f}"),
                         ("f1", "{:>9.4f}"), ("pr_auc", "{:>9.4f}"),
                         ("endpoints_ok", "{:>8.1f}")):
            pass
        rm, _, _ = summarise([r["recall_ml"] for r in results[m]])
        pm, _, _ = summarise([r["precision"] for r in results[m]])
        f1m, _, _ = summarise([r["f1"] for r in results[m]])
        prm, _, _ = summarise([r["pr_auc"] for r in results[m]])
        em, _, _ = summarise([float(r["endpoints_ok"]) for r in results[m]])
        print(f"  {m:<12}{rm:>10.1%}{pm:>11.4f}{f1m:>9.4f}{prm:>9.4f}{em:>8.1f}")

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump({"corpora": corpora, "results": results}, fh, indent=2)
    print(f"\n  written to {args.out}")


if __name__ == "__main__":
    sys.exit(main())
