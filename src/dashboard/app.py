"""MicroAPI Guard - live monitoring dashboard.

A deliberate presentation rule runs through this file: individual detector
scores are labelled EVIDENCE, and the Logistic Regression meta-learner's output
is labelled DECISION. They are never shown as peers.

That matters because a reader who sees "Autoencoder: 0.97" next to a blocked
request will conclude the autoencoder blocked it. It did not - it contributed
one of three inputs to L4, which decided. Every panel that shows a base score
also shows which layer actually made the call.
"""
import json
import os
import sys
from collections import Counter

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import config  # noqa: E402

st.set_page_config(page_title="MicroAPI Guard", page_icon="🛡", layout="wide")

LAYER_LABEL = {
    "L1-rules": "L1 · signature rule",
    "L1-rate": "L1 · rate limit",
    "L4-meta": "L4 · meta-learner (ensemble)",
    "L-error": "fail-closed (inference error)",
    "L1-only": "L1 only (models not loaded)",
    "": "allowed",
}


@st.cache_data(ttl=5)
def load(path, limit):
    if not os.path.exists(path):
        return pd.DataFrame()
    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    rows = rows[-limit:]
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    df["time"] = pd.to_datetime(df["ts"], unit="s")
    for k in ("rate", "isolation_forest", "autoencoder", "meta_lr"):
        df[k] = df["scores"].apply(
            lambda s: s.get(k) if isinstance(s, dict) else None)
    df["decided_by"] = df["layer"].map(lambda x: LAYER_LABEL.get(x, x or "allowed"))
    return df


@st.cache_data(ttl=10)
def model_meta():
    try:
        with open(os.path.join(config.MODELS_DIR, "decision.json")) as fh:
            return json.load(fh)
    except Exception:
        return {}


st.title("🛡 MicroAPI Guard")
st.caption("Real-time API anomaly detection · learned stacking ensemble")

with st.sidebar:
    st.header("Controls")
    log_path = st.text_input("Event log", config.EVENT_LOG)
    limit = st.slider("Events to load", 500, 50_000, 5_000, step=500)
    only_blocked = st.checkbox("Blocked only", value=False)
    if st.button("Refresh now"):
        st.cache_data.clear()
    st.divider()
    meta = model_meta()
    if meta:
        st.subheader("Active model")
        st.write(f"trained: `{meta.get('trained_at', '?')}`")
        st.write(f"threshold: `{meta.get('threshold', '?')}`")
        st.write(f"features: `{len(meta.get('feature_names', []))}`")
        tm = meta.get("test_metrics", {})
        if tm:
            st.write(f"test F1: `{tm.get('f1')}` · recall `{tm.get('recall')}` "
                     f"· FPR `{tm.get('fpr')}`")
        if meta.get("zero_day_recall") is not None:
            st.write(f"zero-day recall: `{meta['zero_day_recall']}`")
        st.caption("Decision is made by the L4 logistic-regression meta-learner.")

df = load(log_path, limit)
if df.empty:
    st.warning(f"No events at `{log_path}`. Start the gateway and send traffic.")
    st.stop()

view = df[df["action"] == "block"] if only_blocked else df

# ── headline counters ────────────────────────────────────────────────────────
total = len(df)
blocked = int((df["action"] == "block").sum())
enforced = int(df["enforced"].sum()) if "enforced" in df else 0
degraded = int(df["degraded"].sum()) if "degraded" in df else 0

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Requests", f"{total:,}")
c2.metric("Flagged anomalous", f"{blocked:,}", f"{100*blocked/max(1,total):.1f}%")
c3.metric("Actually blocked", f"{enforced:,}",
          help="Lower than 'flagged' when running in monitor mode")
c4.metric("Allowed", f"{total-enforced:,}")
c5.metric("Degraded decisions", f"{degraded:,}",
          help="Redis or model unavailable when this request was judged")

st.divider()

# ── which layer decided ──────────────────────────────────────────────────────
left, right = st.columns([1, 1])
with left:
    st.subheader("Which layer made the decision")
    st.caption("Deterministic rules short-circuit before the models run. "
               "Everything else is decided by the L4 ensemble.")
    counts = Counter(df[df["action"] == "block"]["decided_by"])
    if counts:
        st.bar_chart(pd.Series(counts).sort_values(ascending=False))
    else:
        st.info("No blocks recorded yet.")

with right:
    st.subheader("Attack categories observed")
    cats = Counter(c for lst in df.get("categories", []) if isinstance(lst, list)
                   for c in lst)
    if cats:
        st.bar_chart(pd.Series(cats).sort_values(ascending=False))
    else:
        st.info("No rule categories matched yet.")

# ── traffic over time ────────────────────────────────────────────────────────
st.subheader("Traffic over time")
ts = df.set_index("time").assign(
    allowed=lambda d: (d["action"] == "allow").astype(int),
    blocked=lambda d: (d["action"] == "block").astype(int),
)[["allowed", "blocked"]].resample("5s").sum()
st.area_chart(ts)

# ── decision vs evidence ─────────────────────────────────────────────────────
st.divider()
st.subheader("Ensemble decision vs. base-detector evidence")
st.caption(
    "**DECISION** is the L4 logistic-regression probability - the only value "
    "compared against the threshold. **EVIDENCE** columns are the three base "
    "detector scores that feed L4; none of them decides on its own."
)

ml = view[view["layer"].isin(["L4-meta", ""])].dropna(subset=["meta_lr"])
if not ml.empty:
    e1, e2 = st.columns([2, 1])
    with e1:
        st.markdown("**DECISION — L4 meta-learner probability**")
        st.line_chart(ml.set_index("time")[["meta_lr"]].tail(400))
    with e2:
        st.markdown("**EVIDENCE — mean base scores**")
        st.bar_chart(ml[["rate", "isolation_forest", "autoencoder"]].mean())
    thr = model_meta().get("threshold")
    if thr:
        st.caption(f"Blocking threshold on the DECISION value: **{thr:.3f}**")
else:
    st.info("No ML-layer decisions in this window (all traffic settled at Layer 1).")

# ── event table ──────────────────────────────────────────────────────────────
st.divider()
st.subheader("Recent events")
cols = ["time", "method", "template", "status", "action", "decided_by",
        "meta_lr", "rate", "isolation_forest", "autoencoder",
        "categories", "reason", "latency_ms", "detect_ms", "client"]
cols = [c for c in cols if c in view.columns]
tbl = view[cols].tail(400).iloc[::-1].rename(columns={
    "meta_lr": "DECISION (L4)", "rate": "evidence: rate",
    "isolation_forest": "evidence: iforest", "autoencoder": "evidence: autoencoder",
    "decided_by": "decided by", "client": "client (hashed)",
})
st.dataframe(tbl, width="stretch", height=460)

# ── latency ──────────────────────────────────────────────────────────────────
if "detect_ms" in df.columns:
    st.divider()
    st.subheader("Latency")
    st.caption("`detect_ms` is detection only. `latency_ms` includes the "
               "upstream round trip, so the two must not be conflated.")
    l1, l2 = st.columns(2)
    with l1:
        st.markdown("**Detection latency (ms)**")
        st.write(df["detect_ms"].describe(
            percentiles=[.5, .95, .99]).to_frame().T)
    with l2:
        st.markdown("**End-to-end gateway latency (ms)**")
        st.write(df["latency_ms"].describe(
            percentiles=[.5, .95, .99]).to_frame().T)
