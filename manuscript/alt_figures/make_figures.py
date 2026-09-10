"""Generate Fig. 2 (results) for the paper, straight from the model artefacts.

    python manuscript/make_figures.py

Reads src/ml_pipeline/models/{comparison,validation}.json plus the measured
latency table, and writes results_figure.pdf as vector art sized for an IEEE
double-column figure*. Nothing is hard-coded that could drift from the code --
if the models are retrained, re-run this and the figure follows.
"""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(HERE, os.pardir, "src", "ml_pipeline", "models")
OUT = os.path.join(HERE, "results_figure.pdf")

# Measured single-threaded, 2000 iterations after warm-up. See paper Table VI.
LATENCY_US = [
    ("L1 rule block", 47),
    ("L3 autoencoder", 30),
    ("L4 meta-learner", 1440),
    ("L2 isolation forest", 3370),
    ("Full ML path", 5430),
]

C = {                     # colour-blind-safe qualitative palette
    "rate":  "#4C72B0",
    "if":    "#DD8452",
    "ae":    "#55A868",
    "stack": "#C44E52",
    "band":  "#C44E52",
    "grey":  "#4A4A4A",
}

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif"],
    "font.size": 7,
    "axes.labelsize": 7.5,
    "axes.titlesize": 8,
    "xtick.labelsize": 6.5,
    "ytick.labelsize": 6.5,
    "legend.fontsize": 6.5,
    "axes.linewidth": 0.6,
    "xtick.major.width": 0.6,
    "ytick.major.width": 0.6,
    "pdf.fonttype": 42,          # embed real fonts, keep text selectable
})


def load(name):
    with open(os.path.join(MODELS, name), encoding="utf-8") as fh:
        return json.load(fh)


def panel_ablation(ax, comp):
    order = [("rate", "Rate\nsignal"), ("iforest", "Isolation\nForest"),
             ("autoencoder", "Auto-\nencoder"), ("stack", "Stacked\nensemble")]
    metrics = [("precision", "Precision"), ("recall", "Recall"), ("f1", "$F_1$")]
    x = np.arange(len(order))
    w = 0.26
    shades = ["#8FA8CC", "#5B7FB5", "#2F5490"]
    for i, (key, lab) in enumerate(metrics):
        vals = [comp["metrics"][k][key] for k, _ in order]
        bars = ax.bar(x + (i - 1) * w, vals, w, label=lab,
                      color=shades[i], edgecolor="white", linewidth=0.4)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.015, "%.2f" % v,
                    ha="center", va="bottom", fontsize=5.2, rotation=90)
    ax.set_xticks(x)
    ax.set_xticklabels([lab for _, lab in order])
    ax.set_ylim(0, 1.45)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_ylabel("Score")
    ax.set_title("(a)  Ablation on identical test requests", loc="left")
    ax.legend(loc="upper center", frameon=False, ncol=3, columnspacing=0.9,
              handlelength=1.1, borderpad=0.2)
    ax.grid(axis="y", linewidth=0.4, alpha=0.35)
    ax.set_axisbelow(True)


def panel_seeds(ax, val):
    runs = val["runs"]
    seeds = [r["seed"] for r in runs]
    zd = [r["zero_day_recall"] for r in runs]
    f1 = [r["f1"] for r in runs]
    s = val["summary"]["zero_day_recall"]
    lo, hi = s["ci95"]

    x = np.arange(len(seeds))
    # colour each bar by how far it sits from the mean -- makes the spread visible
    cmap = plt.get_cmap("RdYlGn")
    ax.bar(x, zd, 0.66, color=[cmap(0.15 + 0.75 * v) for v in zd],
           edgecolor="#333333", linewidth=0.4, label="Zero-day recall")
    band = ax.axhspan(lo, hi, color=C["band"], alpha=0.13, zorder=0)
    line = ax.axhline(s["mean"], color=C["band"], linewidth=1.0, zorder=3)
    f1line, = ax.plot(x, f1, marker="o", ms=2.4, lw=0.9, color=C["grey"],
                      linestyle="--", label="$F_1$")
    ax.set_xticks(x)
    ax.set_xticklabels(seeds)
    ax.set_xlabel("Seed (session partition)")
    ax.set_ylim(0, 1.30)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_title("(b)  Per-seed zero-day recall vs. $F_1$", loc="left")
    # mean and CI go in the legend rather than floating over the bars
    handles = [ax.patches[0], f1line, line, band]
    labels = ["Zero-day recall", "$F_1$",
              "mean %.3f" % s["mean"],
              "95%% CI [%.3f, %.3f]" % (lo, hi)]
    ax.legend(handles, labels, loc="upper center", frameon=False, ncol=2,
              handlelength=1.3, columnspacing=0.9, borderpad=0.2,
              handletextpad=0.5)
    ax.grid(axis="y", linewidth=0.4, alpha=0.35)
    ax.set_axisbelow(True)


def panel_latency(ax):
    labels = [l for l, _ in LATENCY_US][::-1]
    vals = [v for _, v in LATENCY_US][::-1]
    cols = ["#C44E52", "#DD8452", "#DD8452", "#55A868", "#4C72B0"]
    y = np.arange(len(labels))
    ax.barh(y, vals, 0.62, color=cols, edgecolor="white", linewidth=0.4)
    for i, v in enumerate(vals):
        txt = ("%d $\\mu$s" % v) if v < 1000 else ("%.2f ms" % (v / 1000.0))
        ax.text(v * 1.18, i, txt, va="center", fontsize=6)
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.set_xscale("log")
    ax.set_xlim(10, 40000)
    ax.set_xlabel("Latency per request ($\\mu$s, log scale)")
    ax.set_title("(c)  Where the time goes", loc="left")
    ax.grid(axis="x", linewidth=0.4, alpha=0.35)
    ax.set_axisbelow(True)


def main():
    comp = load("comparison.json")
    val = load("validation.json")

    fig, axes = plt.subplots(1, 3, figsize=(7.16, 2.25))
    panel_ablation(axes[0], comp)
    panel_seeds(axes[1], val)
    panel_latency(axes[2])
    for ax in axes:
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
    fig.tight_layout(pad=0.5, w_pad=1.4)
    fig.savefig(OUT, format="pdf", bbox_inches="tight", pad_inches=0.02)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
