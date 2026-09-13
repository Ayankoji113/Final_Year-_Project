"""Enforcement gate: canary, thresholds, brake, and backward compatibility.

Pure unit tests. The gate is a separate module precisely so it can be tested
without a running gateway, a model, or Redis.

The test that matters most is the last one: for every combination of the new
settings, a Layer-1 verdict must be enforced exactly as it is today. The new
machinery must only ever be able to subtract ML blocking.
"""
import importlib

import pytest

from common import config
from gateway import enforcement


class FakeDetector:
    threshold = 0.25


@pytest.fixture
def gate(monkeypatch):
    monkeypatch.setattr(config, "ML_ROLLOUT_BPS", 10_000)      # 100%
    monkeypatch.setattr(config, "ML_ROLLOUT_PERCENT", 100.0)
    monkeypatch.setattr(config, "ML_ENFORCE_ENDPOINTS", ())
    monkeypatch.setattr(config, "ML_DETECTION_THRESHOLD", -1.0)
    monkeypatch.setattr(config, "ML_ENFORCEMENT_THRESHOLD", -1.0)
    monkeypatch.setattr(config, "ML_REQUIRE_RATE_STATE", True)
    monkeypatch.setattr(config, "ML_BRAKE_ENABLED", True)
    monkeypatch.setattr(config, "ML_ENFORCE_SALT", "test-salt")
    return enforcement.MLGate(FakeDetector())


# ── thresholds ───────────────────────────────────────────────────────────────

def test_detection_threshold_defaults_to_the_trained_value(gate):
    assert gate.detection_threshold() == pytest.approx(0.25)


def test_env_detection_threshold_overrides_the_trained_one(gate, monkeypatch):
    monkeypatch.setattr(config, "ML_DETECTION_THRESHOLD", 0.4)
    assert gate.detection_threshold() == pytest.approx(0.4)


def test_enforcement_threshold_can_never_sit_below_detection(gate, monkeypatch):
    """Enforcing looser than detecting would 403 requests that were never
    logged as detections, and the console would render a block with no layer."""
    monkeypatch.setattr(config, "ML_DETECTION_THRESHOLD", 0.6)
    monkeypatch.setattr(config, "ML_ENFORCEMENT_THRESHOLD", 0.1)
    assert gate.enforcement_threshold() == pytest.approx(0.6)


# ── canary ───────────────────────────────────────────────────────────────────

def test_bucket_is_stable_for_a_client(gate):
    assert gate.bucket("10.0.0.7") == gate.bucket("10.0.0.7")


def test_ramping_only_ever_adds_clients(gate, monkeypatch):
    """A client inside the 5% cohort must still be inside the 25% cohort.

    Without this, ramping would move clients in and out of enforcement and the
    same user would flap between blocked and allowed.
    """
    clients = [f"10.0.{i // 256}.{i % 256}" for i in range(600)]
    monkeypatch.setattr(config, "ML_ROLLOUT_BPS", 500)
    small = {c for c in clients if gate.in_canary(c)}
    monkeypatch.setattr(config, "ML_ROLLOUT_BPS", 2500)
    large = {c for c in clients if gate.in_canary(c)}
    assert small <= large


def test_canary_percentage_is_roughly_honoured(gate, monkeypatch):
    clients = [f"198.51.{i // 256}.{i % 256}" for i in range(3000)]
    monkeypatch.setattr(config, "ML_ROLLOUT_BPS", 2500)     # 25%
    frac = sum(gate.in_canary(c) for c in clients) / len(clients)
    assert 0.20 < frac < 0.30


# ── gate ordering ────────────────────────────────────────────────────────────

def test_zero_rollout_blocks_nothing(gate, monkeypatch):
    monkeypatch.setattr(config, "ML_ROLLOUT_BPS", 0)
    assert gate.evaluate(0.99, "/api/x", "1.2.3.4", False)[0] == enforcement.GATE_MODE


def test_degraded_rate_state_suppresses_enforcement(gate):
    """With Redis down the rate features read zero, so the probability comes
    from knowingly degraded input. Detect on it; do not 403 on it."""
    assert gate.evaluate(0.99, "/api/x", "1.2.3.4", True)[0] == enforcement.GATE_DEGRADED


def test_below_threshold_is_reported_as_such(gate):
    assert gate.evaluate(0.10, "/api/x", "1.2.3.4", False)[0] == enforcement.GATE_THRESHOLD


def test_endpoint_allowlist_is_honoured(gate, monkeypatch):
    monkeypatch.setattr(config, "ML_ENFORCE_ENDPOINTS", ("/api/allowed",))
    assert gate.evaluate(0.99, "/api/other", "1.2.3.4", False)[0] == enforcement.GATE_ENDPOINT
    assert gate.evaluate(0.99, "/api/allowed", "1.2.3.4", False)[0] == enforcement.ENFORCE


def test_full_rollout_enforces(gate):
    g, member = gate.evaluate(0.99, "/api/x", "1.2.3.4", False)
    assert g == enforcement.ENFORCE and member is True


# ── brake ────────────────────────────────────────────────────────────────────

def test_brake_never_engages_at_zero_rollout(gate, monkeypatch):
    """Otherwise an operator arrives at their first canary already braked."""
    monkeypatch.setattr(config, "ML_ROLLOUT_BPS", 0)
    monkeypatch.setattr(config, "ML_BRAKE_MIN_SAMPLES", 10)
    monkeypatch.setattr(config, "ML_BRAKE_MIN_CLIENTS", 2)
    for i in range(100):
        gate.brake.observe(f"c{i % 5}", True)
    assert gate.brake.check() is False


def test_brake_engages_above_the_ceiling(gate, monkeypatch):
    monkeypatch.setattr(config, "ML_BRAKE_MIN_SAMPLES", 20)
    monkeypatch.setattr(config, "ML_BRAKE_MIN_CLIENTS", 3)
    monkeypatch.setattr(config, "ML_BRAKE_MAX_RATE", 0.05)
    for i in range(100):
        gate.brake.observe(f"c{i % 10}", True)
    assert gate.brake.check() is True
    assert gate.brake.engaged is True


def test_one_client_alone_cannot_trip_the_brake(gate, monkeypatch):
    """The anti-abuse term. An attacker is one distinct client and must not be
    able to switch the ML layer off however much traffic they send."""
    monkeypatch.setattr(config, "ML_BRAKE_MIN_SAMPLES", 20)
    monkeypatch.setattr(config, "ML_BRAKE_MIN_CLIENTS", 5)
    monkeypatch.setattr(config, "ML_BRAKE_MAX_RATE", 0.05)
    for _ in range(500):
        gate.brake.observe("attacker", True)
    assert gate.brake.check() is False


def test_brake_does_not_engage_below_the_sample_floor(gate, monkeypatch):
    monkeypatch.setattr(config, "ML_BRAKE_MIN_SAMPLES", 1000)
    monkeypatch.setattr(config, "ML_BRAKE_MIN_CLIENTS", 2)
    for i in range(50):
        gate.brake.observe(f"c{i % 9}", True)
    assert gate.brake.check() is False


def test_brake_latches_and_needs_an_explicit_reset(gate, monkeypatch):
    """No hysteresis to tune and no oscillation to have, because there is no
    automatic re-arm."""
    monkeypatch.setattr(config, "ML_BRAKE_MIN_SAMPLES", 10)
    monkeypatch.setattr(config, "ML_BRAKE_MIN_CLIENTS", 2)
    monkeypatch.setattr(config, "ML_BRAKE_MAX_RATE", 0.05)
    for i in range(60):
        gate.brake.observe(f"c{i % 6}", True)
    assert gate.brake.check() is True
    for i in range(600):                       # window now overwhelmingly clean
        gate.brake.observe(f"c{i % 6}", False)
    assert gate.brake.check() is True          # still latched
    gate.brake.reset()
    assert gate.brake.check() is False


def test_engaged_brake_suppresses_enforcement(gate):
    gate.brake.engage()
    assert gate.evaluate(0.99, "/api/x", "1.2.3.4", False)[0] == enforcement.GATE_BRAKE
    assert gate.enforcing() is False


# ── backward compatibility ───────────────────────────────────────────────────

@pytest.mark.parametrize("mode,enforcing,expected_bps", [
    ("monitor", False, 0),
    ("enforce-l1", True, 0),
    ("enforce", True, 10_000),
])
def test_unset_settings_reproduce_each_guard_mode(monkeypatch, mode, enforcing,
                                                  expected_bps):
    """With nothing configured, the three existing modes must behave exactly as
    they did before this machinery existed."""
    monkeypatch.setenv("GUARD_MODE", mode)
    monkeypatch.delenv("GUARD_ML_ENFORCE_PERCENT", raising=False)
    fresh = importlib.reload(config)
    try:
        assert fresh.ENFORCING is enforcing
        assert fresh.ML_ROLLOUT_BPS == expected_bps
    finally:
        monkeypatch.delenv("GUARD_MODE", raising=False)
        importlib.reload(config)
