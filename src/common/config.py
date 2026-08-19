"""Central configuration. Everything is env-overridable so the same image can be
deployed in front of any backend without a rebuild.
"""
import os

def _b(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")

def _i(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default

def _f(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


# ── Topology ──────────────────────────────────────────────────────────────────
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
REDIS_URL   = os.getenv("REDIS_URL", "redis://localhost:6379")

_HERE       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR    = os.getenv("DATA_DIR", os.path.join(_HERE, "data"))
MODELS_DIR  = os.getenv("MODELS_DIR", os.path.join(_HERE, "ml_pipeline", "models"))
EVENT_LOG   = os.path.join(DATA_DIR, "events.jsonl")

# ── Operating mode ────────────────────────────────────────────────────────────
# enforce     : block on rule hit, rate limit, or ML anomaly
# enforce-l1  : block on rule hit and rate limit; ML anomalies are LOGGED only
# monitor     : never block; log the decision that WOULD have been made
#
# `enforce-l1` is the correct default for a NEW deployment, and it is not a
# hedge. Layers 1's signatures and rate limits are deterministic: they mean the
# same thing on every backend and measured zero false positives here. The
# unsupervised layers are only as good as the traffic they were trained on, and
# a model trained on synthetic traffic mis-scores a real client population -
# measured at 14% false positives even after threshold calibration, because a
# slab of legitimate traffic saturates the anomaly score and no threshold
# separates it.
#
# So: enforce what is certain, observe what is learned, and promote to full
# `enforce` only after retraining on the deployment's own captured traffic.
MODE = os.getenv("GUARD_MODE", "enforce-l1").strip().lower()
ENFORCING = MODE in ("enforce", "enforce-l1")
ML_ENFORCING = MODE == "enforce"

# Accept the ground-truth label header. MUST be false in production: it is a
# training-data poisoning channel. Only enable on an isolated lab network.
TRUST_LABEL_HEADER = _b("GUARD_TRUST_LABEL_HEADER", False)

# Number of reverse-proxy hops we sit behind. 0 = do not trust X-Forwarded-For
# at all (use the socket peer). Trusting XFF blindly makes every per-IP control
# spoofable by the client.
TRUSTED_PROXY_HOPS = _i("GUARD_TRUSTED_PROXY_HOPS", 0)

# ── Limits ────────────────────────────────────────────────────────────────────
MAX_BODY_BYTES     = _i("GUARD_MAX_BODY_BYTES", 1_048_576)   # 1 MiB hard cap
BODY_INSPECT_BYTES = _i("GUARD_BODY_INSPECT_BYTES", 65_536)  # only scan first 64 KiB
UPSTREAM_TIMEOUT   = _f("GUARD_UPSTREAM_TIMEOUT", 15.0)

# ── Rate limiting (Layer 1) ───────────────────────────────────────────────────
RATE_WINDOW_SECS   = _i("GUARD_RATE_WINDOW_SECS", 60)
RATE_LIMIT         = _i("GUARD_RATE_LIMIT", 240)        # requests / window / client
RATE_BURST_SECS    = _i("GUARD_RATE_BURST_SECS", 5)
RATE_BURST_LIMIT   = _i("GUARD_RATE_BURST_LIMIT", 40)   # requests / burst / client

# ── ML decision ───────────────────────────────────────────────────────────────
# Fallback only; the trained threshold in decision.json wins when present.
ML_THRESHOLD       = _f("GUARD_ML_THRESHOLD", 0.5)
# A request whose feature extraction or inference raises is treated as hostile.
# (Attacker-controllable input must never fail open.)
FAIL_CLOSED        = _b("GUARD_FAIL_CLOSED", True)

# ── Calibration ───────────────────────────────────────────────────────────────
CALIBRATION_MIN_SAMPLES = _i("GUARD_CALIBRATION_MIN_SAMPLES", 2000)
CALIBRATION_TARGET_FPR  = _f("GUARD_CALIBRATION_TARGET_FPR", 0.01)
