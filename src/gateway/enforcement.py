"""ML enforcement policy: thresholds, canary, and the automatic brake.

THE STRUCTURAL GUARANTEE
------------------------
Nothing in this module is consulted on the Layer-1 path. `main.py` decides L1
enforcement with its own literal expression, and calls in here only for an ML
verdict. A bug anywhere in this file can therefore produce at most "ML stopped
blocking" - never "signatures stopped blocking", and never over-blocking.

That property is why the gate is a separate module rather than a few more
clauses in the proxy handler. It is also why `evaluate()` is wrapped at the call
site so any exception resolves to "do not enforce".

WHY DETECTION AND ENFORCEMENT ARE SEPARATE
------------------------------------------
Detection is a property of the model. Enforcement is a property of the
deployment. Before this module they were the same boolean, which made turning
ML blocking on an all-or-nothing act with no reverse gear and no way to express
"5% of clients, at probability >= 0.97, with a brake".

Measured context for the defaults: on independent traffic the shipped model
produced a 61% mean false-positive rate, so enforcement has to be something an
operator ramps into while watching, not a switch.
"""
import hashlib
import time
from collections import deque
from typing import Optional, Tuple

from common import config

# Gate outcomes. These are logged verbatim as `enforce_gate`, so an operator can
# tell apart "below threshold", "not in the canary" and "brake engaged" without
# inferring anything.
ENFORCE = "enforce"
GATE_MODE = "mode"                  # rollout is 0 - every ML detection today
GATE_DEGRADED = "degraded"          # Redis down, rate features are zeroed
GATE_BRAKE = "brake"
GATE_THRESHOLD = "below-threshold"
GATE_ENDPOINT = "endpoint-not-enabled"
GATE_CANARY = "not-in-canary"
GATE_ERROR = "error"


class _Brake:
    """Rolling would-block rate with a manual-reset latch.

    In-process, not Redis, for three reasons: a Redis outage must not break the
    brake, it must not add a round trip to a path already costing ~14 ms, and
    in-process state fails toward NOT enforcing.

    It measures the would-block rate over everything that reached the model
    rather than the enforced rate over the canary. That keeps the ceiling
    meaning the same thing at 1% rollout as at 100%, and makes the metric
    observable at 0% rollout - which is how an operator learns whether the brake
    would trip before anyone receives a 403.
    """

    BUCKETS = 10

    def __init__(self):
        self._width = max(1, config.ML_BRAKE_WINDOW_SECS // self.BUCKETS)
        self._buckets = deque(
            [{"epoch": -1, "n": 0, "would": 0, "clients": set()}
             for _ in range(self.BUCKETS)], maxlen=self.BUCKETS)
        self.engaged = False
        self.tripped_at: Optional[float] = None
        self.tripped_rate = 0.0
        self.tripped_samples = 0
        self.tripped_clients = 0
        self._cached: Optional[Tuple[float, float, int, int]] = None

    def _slot(self, now: float):
        epoch = int(now // self._width)
        b = self._buckets[epoch % self.BUCKETS]
        if b["epoch"] != epoch:
            b["epoch"] = epoch
            b["n"] = 0
            b["would"] = 0
            b["clients"] = set()
        return b, epoch

    def observe(self, client_hash: str, would_block: bool) -> None:
        """Record one request that reached the models. Two integer adds."""
        now = time.monotonic()
        b, epoch = self._slot(now)
        b["n"] += 1
        if would_block:
            b["would"] += 1
            # Capped: an attacker must not be able to grow this without bound.
            if len(b["clients"]) < 256:
                b["clients"].add(client_hash)

    def _window(self, now: float):
        """Summarise the live window. Cached for one second so the brake's own
        cost stays bounded regardless of traffic - otherwise it would be a CPU
        amplification target."""
        if self._cached and now - self._cached[0] < 1.0:
            return self._cached[1], self._cached[2], self._cached[3]
        epoch = int(now // self._width)
        n = would = 0
        clients = set()
        for b in self._buckets:
            if b["epoch"] < 0 or epoch - b["epoch"] >= self.BUCKETS:
                continue
            n += b["n"]
            would += b["would"]
            clients |= b["clients"]
        rate = would / n if n else 0.0
        self._cached = (now, rate, n, len(clients))
        return rate, n, len(clients)

    def check(self) -> bool:
        """True when enforcement must be suppressed."""
        if not config.ML_BRAKE_ENABLED:
            return False
        if self.engaged:
            return True
        # Never latch at 0% rollout, or an operator arrives at their first
        # canary already braked.
        if config.ML_ROLLOUT_BPS <= 0:
            return False
        now = time.monotonic()
        rate, n, nclients = self._window(now)
        if (n >= config.ML_BRAKE_MIN_SAMPLES
                and nclients >= config.ML_BRAKE_MIN_CLIENTS
                and rate > config.ML_BRAKE_MAX_RATE):
            self.engaged = True
            self.tripped_at = time.time()
            self.tripped_rate = rate
            self.tripped_samples = n
            self.tripped_clients = nclients
            print(f"[gateway] *** ML BRAKE ENGAGED: would-block rate {rate:.1%} "
                  f"over {n} requests from {nclients} clients exceeds "
                  f"{config.ML_BRAKE_MAX_RATE:.1%}. ML enforcement is now OFF. "
                  f"L1 signatures and rate limits still enforce. Clear with "
                  f"POST /__guard/reload?ml_brake=reset ***")
            return True
        return False

    def engage(self, manual: bool = True) -> None:
        if not self.engaged:
            self.engaged = True
            self.tripped_at = time.time()
            rate, n, c = self._window(time.monotonic())
            self.tripped_rate, self.tripped_samples, self.tripped_clients = rate, n, c

    def reset(self) -> None:
        """Clear the latch AND the measurement window.

        Clearing the latch alone would be futile: the window that tripped the
        brake is still in memory, so the very next check re-engages and the
        operator concludes the reset is broken. A reset means "I have dealt with
        the cause, start measuring again from now".
        """
        self.engaged = False
        self.tripped_at = None
        self.tripped_rate = 0.0
        self.tripped_samples = 0
        self.tripped_clients = 0
        for b in self._buckets:
            b["epoch"] = -1
            b["n"] = 0
            b["would"] = 0
            b["clients"] = set()
        self._cached = None

    def snapshot(self) -> dict:
        rate, n, c = self._window(time.monotonic())
        return {
            "enabled": config.ML_BRAKE_ENABLED,
            "engaged": self.engaged,
            "tripped_at": self.tripped_at,
            "tripped_rate": round(self.tripped_rate, 4),
            "tripped_samples": self.tripped_samples,
            "tripped_clients": self.tripped_clients,
            "window_secs": config.ML_BRAKE_WINDOW_SECS,
            "live_would_block_rate": round(rate, 4),
            "live_samples": n,
            "live_clients": c,
            "max_rate": config.ML_BRAKE_MAX_RATE,
        }


class MLGate:
    """Decides whether an ML verdict is enforced, and says why."""

    def __init__(self, detector):
        self._detector = detector
        self.brake = _Brake()

    # -- thresholds ---------------------------------------------------------

    def detection_threshold(self) -> float:
        if config.ML_DETECTION_THRESHOLD >= 0:
            return config.ML_DETECTION_THRESHOLD
        return float(self._detector.threshold)

    def enforcement_threshold(self) -> float:
        """Never below the detection threshold.

        Enforcing looser than detecting would 403 requests that were never
        logged as detections, and the console would render an enforced block
        with an empty layer.
        """
        d = self.detection_threshold()
        if config.ML_ENFORCEMENT_THRESHOLD < 0:
            return d
        return max(d, config.ML_ENFORCEMENT_THRESHOLD)

    # -- canary -------------------------------------------------------------

    @staticmethod
    def bucket(client_id: str) -> int:
        """Stable 0..9999 bucket for a client.

        Fixed rather than random per request so a client never flaps between
        blocked and allowed, and monotonic under ramp: a client inside the 5%
        cohort is still inside the 25% cohort.
        """
        h = hashlib.sha256(
            (config.ML_ENFORCE_SALT + "|" + client_id).encode("utf-8", "ignore"))
        return int.from_bytes(h.digest()[:4], "big") % 10_000

    def in_canary(self, client_id: str) -> bool:
        return self.bucket(client_id) < config.ML_ROLLOUT_BPS

    # -- the decision -------------------------------------------------------

    def observe(self, client_hash: str, probability: float) -> None:
        """Record any request that reached the models, blocked or not."""
        self.brake.observe(client_hash, probability >= self.enforcement_threshold())

    def evaluate(self, probability: float, template: str, client_id: str,
                 rate_degraded: bool) -> Tuple[str, Optional[bool]]:
        """Return (gate, canary_membership).

        Ordered cheapest and most global first, so the reason reported is the
        most actionable one and the hash is only paid once everything else has
        passed.
        """
        if config.ML_ROLLOUT_BPS <= 0:
            return GATE_MODE, None
        if rate_degraded and config.ML_REQUIRE_RATE_STATE:
            return GATE_DEGRADED, None
        if self.brake.check():
            return GATE_BRAKE, None
        if probability < self.enforcement_threshold():
            return GATE_THRESHOLD, None
        if config.ML_ENFORCE_ENDPOINTS and template not in config.ML_ENFORCE_ENDPOINTS:
            return GATE_ENDPOINT, None
        member = self.in_canary(client_id)
        if not member:
            return GATE_CANARY, False
        return ENFORCE, True

    # -- reporting ----------------------------------------------------------

    def enforcing(self) -> bool:
        """Whether ML verdicts can block anything at all right now."""
        return config.ML_ROLLOUT_BPS > 0 and not self.brake.engaged

    def snapshot(self) -> dict:
        return {
            "rollout_percent": config.ML_ROLLOUT_PERCENT,
            "threshold_detect": round(self.detection_threshold(), 6),
            "threshold_enforce": round(self.enforcement_threshold(), 6),
            "enforce_endpoints": list(config.ML_ENFORCE_ENDPOINTS),
            "require_rate_state": config.ML_REQUIRE_RATE_STATE,
            "salted": bool(config.ML_ENFORCE_SALT),
            "enforcing": self.enforcing(),
            "brake": self.brake.snapshot(),
        }
