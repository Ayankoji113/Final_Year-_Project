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

# ── Admin authentication ──────────────────────────────────────────────────────
# /__guard/* sits on the only published port with no authentication. That was
# tolerable while `reload` merely re-read model files. It stops being tolerable
# the moment a runtime kill switch and a brake reset live on the same surface:
# a safety latch anyone on the network can clear is worse than no latch, because
# an operator believes they are protected.
#
# Empty preserves today's behaviour exactly. Set it before raising
# GUARD_ML_ENFORCE_PERCENT above zero.
ADMIN_TOKEN = os.getenv("GUARD_ADMIN_TOKEN", "")

# ── ML enforcement rollout ────────────────────────────────────────────────────
# Detection and enforcement are separate decisions. Detection is what the model
# records and the console shows; enforcement is what returns 403. Collapsing
# them into one boolean is why turning ML blocking on has been all-or-nothing
# with no reverse gear.
#
# -1 is the "not configured" sentinel throughout, because 0.0 is meaningful.
# With everything unset, all three existing GUARD_MODE values behave exactly as
# they do today: monitor and enforce-l1 resolve to 0% rollout, enforce to 100%.

# What counts as a DETECTION. Precedence: this > decision.json > ML_THRESHOLD.
ML_DETECTION_THRESHOLD   = _f("GUARD_ML_DETECTION_THRESHOLD", -1.0)

# How sure before a 403. -1 means "same as detection", i.e. historical
# behaviour. Clamped at use so it can never sit below the detection threshold.
ML_ENFORCEMENT_THRESHOLD = _f("GUARD_ML_ENFORCEMENT_THRESHOLD", -1.0)

# FOR WHOM, as a percentage of clients, 0-100. This is the single authoritative
# "never enforce" control. One knob carries that meaning on purpose: giving both
# the threshold and the percentage a never-default creates the failure where an
# operator sets the percentage, sees nothing happen, assumes the canary is
# broken, and loosens both at once.
ML_ENFORCE_PERCENT       = _f("GUARD_ML_ENFORCE_PERCENT", -1.0)

# Which endpoint templates ML may block, comma-separated. Empty means "all that
# pass the other gates". Per-endpoint rollout is the practical route here: the
# false-positive rate is per-endpoint, not global, and several endpoints measure
# 0% while others measure 100%.
ML_ENFORCE_ENDPOINTS = tuple(
    t.strip() for t in os.getenv("GUARD_ML_ENFORCE_ENDPOINTS", "").split(",") if t.strip())

# Salts the client -> canary bucket map. Empty means membership is computable by
# anyone who can read this file, so a client could choose a source address
# outside the enforced cohort. Set a random per-deployment value.
ML_ENFORCE_SALT = os.getenv("GUARD_ML_ENFORCE_SALT", "")

# L4 consumes Redis-backed rate features. With Redis down they read zero, so the
# probability is computed from knowingly degraded input. Detect on it; do not
# 403 on it. Setting this false restores literal pre-existing behaviour.
ML_REQUIRE_RATE_STATE = _b("GUARD_ML_REQUIRE_RATE_STATE", True)

# ── Automatic brake ───────────────────────────────────────────────────────────
# Measures the would-block rate across everything that reached the model, not
# the enforced rate across the canary. That way the ceiling means the same thing
# at 1% rollout as at 100%, and the metric is observable at 0% rollout - so an
# operator can watch it for a week before anyone receives a 403.
ML_BRAKE_ENABLED     = _b("GUARD_ML_BRAKE_ENABLED", True)
ML_BRAKE_WINDOW_SECS = _i("GUARD_ML_BRAKE_WINDOW_SECS", 300)
ML_BRAKE_MIN_SAMPLES = _i("GUARD_ML_BRAKE_MIN_SAMPLES", 200)
# Anti-abuse: one attacker is one distinct client and must never be able to trip
# the brake alone, however much traffic they send.
ML_BRAKE_MIN_CLIENTS = _i("GUARD_ML_BRAKE_MIN_CLIENTS", 5)
ML_BRAKE_MAX_RATE    = _f("GUARD_ML_BRAKE_MAX_RATE", 0.05)   # 5x the FPR budget


def _rollout_percent() -> float:
    """Resolve the canary percentage, inheriting from GUARD_MODE when unset."""
    if ML_ENFORCE_PERCENT < 0:
        return 100.0 if ML_ENFORCING else 0.0
    return min(100.0, max(0.0, ML_ENFORCE_PERCENT))


ML_ROLLOUT_PERCENT = _rollout_percent()
ML_ROLLOUT_BPS = int(round(ML_ROLLOUT_PERCENT * 100))   # basis points, 0..10000
