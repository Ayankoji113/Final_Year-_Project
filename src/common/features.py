"""Behavioural feature extraction - the single source of truth.

The gateway and the training pipeline both call `extract()`. There is no second
copy of this logic to drift out of sync.

DESIGN CONSTRAINT - why there is no endpoint identity in here
-------------------------------------------------------------
The previous pipeline one-hot encoded `http_path`, so the model learned
"path == /wp-admin => attack". That memorises one backend's URL vocabulary: it
cannot transfer to a different backend, and it cannot flag an attack aimed at a
path that looked benign during training. Both are fatal for a product whose
selling points are "works in front of any backend" and "catches zero-days".

Every feature below is therefore a *shape* or *rate* measurement that means the
same thing on any HTTP API:

  - structural   : how deep/long/odd is the path, how much entropy in the body
  - statistical  : how far is this request from the baseline for its endpoint
  - behavioural  : how fast is this client going, how many endpoints is it touching

A brand-new backend with completely different URLs produces the same feature
distribution for the same *kind* of traffic, which is exactly what makes the
calibration step (rather than a full retrain) sufficient.
"""
import math
import re
from collections import Counter
from typing import Dict, Optional

import numpy as np

from . import normalize as nz

# Order is part of the model contract. Appending is safe; reordering or removing
# requires a retrain. train.py asserts the saved order matches at load time.
FEATURE_NAMES = [
    # body shape
    "body_log_size", "body_entropy", "body_special_ratio", "body_digit_ratio",
    "body_upper_ratio", "body_nonascii_ratio", "body_size_z", "has_body", "ct_json",
    # path shape
    "path_len", "path_depth", "path_max_seg", "path_entropy",
    "path_special_ratio", "path_digit_ratio", "path_numeric_seg_ratio",
    "path_nonascii_ratio", "path_decode_delta", "path_dot_count", "path_known",
    # query shape
    "q_param_count", "q_max_val_len", "q_total_len", "q_special_ratio", "q_decode_delta",
    # ── client-shape headers: REMOVED, deliberately ──────────────────────────
    #
    # header_count, ua_len, ua_entropy, has_ua, has_referer and has_auth were
    # all dropped. Two independent arguments, either of which is sufficient:
    #
    # 1. SECURITY. Every one of them is set by the client. An attacker copies a
    #    browser User-Agent and adds a Referer for free, so any accuracy the
    #    model gains from them evaporates against an adversary who spends ten
    #    seconds on evasion. Detection must rest on what the request DOES
    #    (payload shape, path structure, rate), not on how it introduces itself.
    #
    # 2. FALSE POSITIVES. They were the dominant cause, and measurably so.
    #    header_count was contaminated by the traffic generator's own
    #    X-Ground-Truth/X-Forwarded-For headers (training sd 1.16, so a normal
    #    4-header client sat 2.75 sigma out). The UA group was worse: a client
    #    that sends no User-Agent flips has_ua, ua_len and ua_entropy together,
    #    and an autoencoder trained on normal-only traffic flags any systematic
    #    deviation whether or not it is security-relevant. A legitimate
    #    multi-client load measured 36.7% false positives with these features
    #    present.
    #
    # This is the ponytail principle applied to a feature set: the features
    # that were doing the least security work were doing the most damage.
    # ── behaviour ────────────────────────────────────────────────────────────
    #
    # win_log_count, burst_log_count and rate_z were REMOVED. Rate MAGNITUDE is
    # Layer 1's job, and giving it to the unsupervised layers as well made the
    # two layers enforce contradictory policies.
    #
    # Layer 1 enforces an explicit, operator-configured limit (GUARD_RATE_LIMIT,
    # default 240/min/client) and hands L4 a continuous `rate` score derived
    # from it. When the autoencoder ALSO saw raw rate magnitudes, it learned the
    # rate distribution that happened to be in the training corpus (~9 req/min)
    # and then rejected anything faster - so an operator who configured 240
    # silently got an effective limit near 20, and legitimate fast clients were
    # blocked at 38% while the held-out test FPR still read 1.3%.
    #
    # `win_distinct_paths` is kept: how MANY different endpoints a client
    # touches is a breadth/behaviour signal (scanning, enumeration), not a
    # volume signal, and it is what makes exfil and scan detectable.
    #
    # Net effect: L1 decides how fast is too fast, using the configured policy.
    # L2/L3 decide whether the request LOOKS wrong. L4 combines them.
    "win_distinct_paths",
    # method (low cardinality; the same 6 buckets exist on every HTTP API)
    "m_get", "m_post", "m_put", "m_delete", "m_patch", "m_other", "is_write",
    # layer-1 evidence (FLAG-severity only; BLOCK hits never reach the model)
    "n_flags",
]

N_FEATURES = len(FEATURE_NAMES)

_SPECIAL = re.compile(r"[^A-Za-z0-9 _\-./]")
_DIGIT = re.compile(r"\d")
_UPPER = re.compile(r"[A-Z]")
_NUMERIC_SEG = re.compile(r"^\d+$")


def shannon_entropy(s: str) -> float:
    """Bits per character. Random/encoded/compressed payloads score high,
    natural language and JSON score low-to-middling."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _ratio(pattern: re.Pattern, s: str) -> float:
    return len(pattern.findall(s)) / len(s) if s else 0.0


def _nonascii_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for ch in s if ord(ch) > 127) / len(s)


def _safe_z(value: float, mean: float, std: float) -> float:
    """Z-score clipped to +/-10 so one freak request cannot dominate the scaler."""
    if std is None or std <= 1e-9:
        return 0.0
    return float(np.clip((value - mean) / std, -10.0, 10.0))


class Baseline:
    """Per-deployment statistical baseline, produced by the calibration phase.

    Holds what "normal" looks like *for this particular backend*: how big bodies
    usually are on each endpoint, and how fast clients usually go. This is the
    mechanism that lets one trained model serve a backend it has never seen -
    the model consumes deviations from the baseline, not raw magnitudes.
    """

    def __init__(self, data: Optional[dict] = None):
        data = data or {}
        self.endpoints: Dict[str, dict] = data.get("endpoints", {})
        rate = data.get("rate", {})
        self.rate_mean = float(rate.get("mean", 0.0))
        self.rate_std = float(rate.get("std", 0.0))
        self.n_samples = int(data.get("n_samples", 0))
        self.ready = bool(self.endpoints) and self.n_samples > 0

    def body_stats(self, template: str):
        e = self.endpoints.get(template)
        if not e:
            return None
        return float(e.get("body_mean", 0.0)), float(e.get("body_std", 0.0))

    def knows(self, template: str) -> bool:
        # With no baseline at all we must not label every endpoint "novel",
        # so we report known and let the other features carry the decision.
        return (not self.ready) or (template in self.endpoints)

    def to_dict(self) -> dict:
        return {
            "endpoints": self.endpoints,
            "rate": {"mean": self.rate_mean, "std": self.rate_std},
            "n_samples": self.n_samples,
        }


EMPTY_BASELINE = Baseline()


def extract(ev: dict, baseline: Optional[Baseline] = None) -> Dict[str, float]:
    """Turn a raw request event into the model's feature dictionary.

    `ev` is the canonical event produced by the gateway and replayed from the
    event log during training, so training and inference see identical inputs.
    """
    bl = baseline or EMPTY_BASELINE

    raw_path = ev.get("path", "/") or "/"
    raw_query = ev.get("query", "") or ""
    body = ev.get("body", "") or ""
    body_size = float(ev.get("body_size", len(body)))
    method = (ev.get("method", "GET") or "GET").upper()
    template = ev.get("template") or nz.path_template(raw_path)

    canon_path = nz.canonical(raw_path + ("?" + raw_query if raw_query else ""))
    canon_body = nz.canonical(body)

    segs = [s for s in raw_path.split("/") if s]
    n_segs = len(segs)

    # ── body ─────────────────────────────────────────────────────────────────
    bstats = bl.body_stats(template)
    body_z = _safe_z(body_size, bstats[0], bstats[1]) if bstats else 0.0

    f = {
        "body_log_size": math.log1p(max(0.0, body_size)),
        "body_entropy": shannon_entropy(body[:4096]),
        "body_special_ratio": _ratio(_SPECIAL, body[:4096]),
        "body_digit_ratio": _ratio(_DIGIT, body[:4096]),
        "body_upper_ratio": _ratio(_UPPER, body[:4096]),
        "body_nonascii_ratio": _nonascii_ratio(body[:4096]),
        "body_size_z": body_z,
        "has_body": 1.0 if body_size > 0 else 0.0,
        "ct_json": 1.0 if "json" in (ev.get("content_type", "") or "").lower() else 0.0,

        # ── path ─────────────────────────────────────────────────────────────
        "path_len": float(len(raw_path)),
        "path_depth": float(min(n_segs, 20)),
        "path_max_seg": float(max((len(s) for s in segs), default=0)),
        "path_entropy": shannon_entropy(raw_path),
        "path_special_ratio": _ratio(_SPECIAL, raw_path),
        "path_digit_ratio": _ratio(_DIGIT, raw_path),
        "path_numeric_seg_ratio": (
            sum(1 for s in segs if _NUMERIC_SEG.match(s)) / n_segs if n_segs else 0.0
        ),
        "path_nonascii_ratio": _nonascii_ratio(raw_path),
        "path_decode_delta": nz.decode_delta(raw_path),
        "path_dot_count": float(raw_path.count(".")),
        "path_known": 1.0 if bl.knows(template) else 0.0,
    }

    # ── query ────────────────────────────────────────────────────────────────
    params = [p for p in raw_query.split("&") if p] if raw_query else []
    values = [p.split("=", 1)[1] if "=" in p else "" for p in params]
    f.update({
        "q_param_count": float(len(params)),
        "q_max_val_len": float(max((len(v) for v in values), default=0)),
        "q_total_len": float(len(raw_query)),
        "q_special_ratio": _ratio(_SPECIAL, raw_query),
        "q_decode_delta": nz.decode_delta(raw_query),
    })

    # Client-supplied header features are intentionally not extracted -
    # see the note in FEATURE_NAMES above.

    # ── behaviour ────────────────────────────────────────────────────────────
    # Rate magnitude is deliberately absent - see the note in FEATURE_NAMES.
    # Only breadth (how many distinct endpoints) reaches the model.
    f["win_distinct_paths"] = math.log1p(float(ev.get("window_distinct", 0)))

    # ── method ───────────────────────────────────────────────────────────────
    f.update({
        "m_get": 1.0 if method == "GET" else 0.0,
        "m_post": 1.0 if method == "POST" else 0.0,
        "m_put": 1.0 if method == "PUT" else 0.0,
        "m_delete": 1.0 if method == "DELETE" else 0.0,
        "m_patch": 1.0 if method == "PATCH" else 0.0,
        "m_other": 1.0 if method not in ("GET", "POST", "PUT", "DELETE", "PATCH") else 0.0,
        "is_write": 1.0 if method in ("POST", "PUT", "DELETE", "PATCH") else 0.0,
        "n_flags": float(ev.get("n_flags", 0)),
    })

    # keep the canonical strings out of the vector but available to the caller
    f["_canon_path"] = canon_path
    f["_canon_body"] = canon_body
    return f


def to_vector(f: Dict[str, float]) -> np.ndarray:
    """Feature dict -> fixed-order float32 vector."""
    return np.fromiter((float(f.get(n, 0.0)) for n in FEATURE_NAMES),
                       dtype=np.float32, count=N_FEATURES)


def to_matrix(rows) -> np.ndarray:
    """Sequence of feature dicts -> (n, N_FEATURES) matrix."""
    out = np.zeros((len(rows), N_FEATURES), dtype=np.float32)
    for i, r in enumerate(rows):
        out[i] = to_vector(r)
    return out
