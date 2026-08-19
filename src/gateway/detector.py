"""The 4-layer detection pipeline.

    L1  static rules + rate limiting   -> deterministic, can short-circuit
    L2  Isolation Forest               -> unsupervised, normal-only
    L3  Autoencoder                    -> unsupervised, normal-only
    L4  Logistic Regression            -> meta-learner, MAKES THE DECISION

Two properties are enforced here on purpose:

1. L4 IS the classifier. The previous build selected whichever of seven score
   sources scored best on validation, picked a gradient-boosting model, and
   left the meta-learner computing an unused number. Here the base detectors
   only ever produce *features for L4*; nothing else can decide.

2. A BLOCK-severity L1 hit short-circuits before any model runs. Sending a
   confirmed `UNION SELECT` to a statistical model to ask its opinion adds
   latency and a chance of being wrong about something already certain. FLAG
   hits do NOT short-circuit - they become evidence the model weighs.
"""
import json
import os
import pickle
from dataclasses import dataclass, field
from typing import List, Optional

import joblib
import numpy as np

from common import config, features, rules
from common import normalize as nz
from common.features import Baseline

ALLOW = "allow"
BLOCK = "block"


@dataclass
class Decision:
    action: str = ALLOW
    layer: str = ""                       # which layer decided
    reason: str = ""
    probability: float = 0.0              # L4 output
    scores: dict = field(default_factory=dict)
    rule_hits: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    degraded: bool = False


class Detector:
    def __init__(self):
        self.scaler = None
        self.iforest = None
        self.autoencoder = None
        self.meta_lr = None
        self.meta = None                  # decision.json
        self.baseline = Baseline()
        self.loaded = False
        self.threshold = config.ML_THRESHOLD

    # ── model lifecycle ──────────────────────────────────────────────────────
    def load(self, models_dir: Optional[str] = None) -> bool:
        d = models_dir or config.MODELS_DIR
        try:
            with open(os.path.join(d, "decision.json"), "r") as f:
                self.meta = json.load(f)

            saved = self.meta.get("feature_names", [])
            if saved != features.FEATURE_NAMES:
                # A silent feature-order mismatch produces a model that is
                # confidently wrong on every request. Refuse instead.
                raise ValueError(
                    f"feature contract mismatch: model was trained on "
                    f"{len(saved)} features, this build has "
                    f"{len(features.FEATURE_NAMES)}. Retrain required."
                )

            self.scaler = joblib.load(os.path.join(d, "scaler.pkl"))
            self.iforest = joblib.load(os.path.join(d, "isolation_forest.pkl"))
            self.meta_lr = joblib.load(os.path.join(d, "meta_lr.pkl"))
            with open(os.path.join(d, "autoencoder.pkl"), "rb") as f:
                self.autoencoder = pickle.load(f)

            self.threshold = float(self.meta.get("threshold", config.ML_THRESHOLD))
            self.load_baseline(d)
            self.loaded = True
            return True
        except Exception as e:
            print(f"[detector] model load failed: {e}")
            self.loaded = False
            return False

    def load_baseline(self, models_dir: Optional[str] = None) -> bool:
        path = os.path.join(models_dir or config.MODELS_DIR, "calibration.json")
        try:
            with open(path, "r") as f:
                self.baseline = Baseline(json.load(f))
            return self.baseline.ready
        except FileNotFoundError:
            self.baseline = Baseline()
            return False
        except Exception as e:
            print(f"[detector] baseline load failed: {e}")
            self.baseline = Baseline()
            return False

    # ── score normalisation ──────────────────────────────────────────────────
    def _norm(self, value: float, lo_key: str, hi_key: str) -> float:
        lo = float(self.meta.get(lo_key, 0.0))
        hi = float(self.meta.get(hi_key, 1.0))
        return float(np.clip((value - lo) / (hi - lo + 1e-9), 0.0, 1.0))

    @staticmethod
    def _rate_score(ev: dict) -> float:
        """L1's continuous contribution to the stack.

        The static layer is a base detector too, so it must hand L4 a graded
        score - not just the binary "did it trip the limit" it already used to
        short-circuit. Ratio of observed rate to the configured limit.
        """
        w = float(ev.get("window_count", 0)) / max(1, config.RATE_LIMIT)
        b = float(ev.get("burst_count", 0)) / max(1, config.RATE_BURST_LIMIT)
        return float(np.clip(max(w, b), 0.0, 1.0))

    # ── main entry point ─────────────────────────────────────────────────────
    def inspect(self, ev: dict) -> Decision:
        """Run the pipeline over one canonical request event."""
        # ── L1a: signatures ──────────────────────────────────────────────────
        canon_path = nz.canonical(ev.get("path", "") +
                                  (("?" + ev["query"]) if ev.get("query") else ""))
        canon_body = nz.canonical(ev.get("body", ""))
        hits = rules.evaluate(canon_path, canon_body)
        hit_ids = [h.id for h in hits]
        cats = sorted({h.category for h in hits})

        if any(h.severity == rules.BLOCK for h in hits):
            blocking = next(h for h in hits if h.severity == rules.BLOCK)
            return Decision(action=BLOCK, layer="L1-rules",
                            reason=f"{blocking.id}: {blocking.why}",
                            probability=1.0,
                            scores={"rule": 1.0},
                            rule_hits=hit_ids, categories=cats)

        # ── L1b: rate limiting ───────────────────────────────────────────────
        if ev.get("rate_limited"):
            return Decision(action=BLOCK, layer="L1-rate",
                            reason=ev.get("rate_reason", "rate limit exceeded"),
                            probability=1.0,
                            scores={"rate": 1.0},
                            rule_hits=hit_ids, categories=cats + ["rate"])

        # FLAG hits are evidence, not verdicts - hand the count to the model.
        ev = dict(ev)
        ev["n_flags"] = len(hits)

        # ── L2/L3/L4 ─────────────────────────────────────────────────────────
        if not self.loaded:
            # Models absent. L1 still ran, so we are not defenceless, but we
            # cannot claim anomaly coverage - say so rather than reporting
            # a confident "normal".
            return Decision(action=ALLOW, layer="L1-only",
                            reason="anomaly models not loaded",
                            rule_hits=hit_ids, categories=cats, degraded=True)

        try:
            f = features.extract(ev, self.baseline)
            X = features.to_vector(f).reshape(1, -1)
            Xs = self.scaler.transform(X)

            if_raw = float(-self.iforest.decision_function(Xs)[0])
            ae_raw = float(self.autoencoder.score(Xs)[0])
            rate_raw = self._rate_score(ev)

            if_n = self._norm(if_raw, "if_lo", "if_hi")
            ae_n = self._norm(ae_raw, "ae_lo", "ae_hi")

            # L4 - the only thing that decides.
            p = float(self.meta_lr.predict_proba([[rate_raw, if_n, ae_n]])[0, 1])

            action = BLOCK if p >= self.threshold else ALLOW
            return Decision(
                action=action,
                layer="L4-meta" if action == BLOCK else "",
                reason=(f"ensemble anomaly probability {p:.3f} >= "
                        f"threshold {self.threshold:.3f}") if action == BLOCK else "",
                probability=p,
                scores={"rate": round(rate_raw, 4),
                        "isolation_forest": round(if_n, 4),
                        "autoencoder": round(ae_n, 4),
                        "meta_lr": round(p, 4)},
                rule_hits=hit_ids, categories=cats,
            )

        except Exception as e:
            # Feature extraction and inference run on attacker-controlled input.
            # Failing open here is an exploitable bypass: send whatever crashes
            # the extractor and you are waved through. Fail closed by default.
            print(f"[detector] inference error: {e}")
            if config.FAIL_CLOSED:
                return Decision(action=BLOCK, layer="L-error",
                                reason=f"inference failure, failing closed: {type(e).__name__}",
                                probability=1.0, rule_hits=hit_ids,
                                categories=cats, degraded=True)
            return Decision(action=ALLOW, layer="L-error",
                            reason=f"inference failure, failing open: {type(e).__name__}",
                            rule_hits=hit_ids, categories=cats, degraded=True)
