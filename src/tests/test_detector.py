"""Detection-pipeline tests.

These pin the architectural guarantees that the previous build violated:
Layer 1 short-circuits, the meta-learner is the only thing that decides, and
inference failure on attacker-controlled input fails CLOSED.
"""
import os

import pytest

from common import config, rules
from gateway import detector as det
from gateway.detector import ALLOW, BLOCK, Detector

MODELS = config.MODELS_DIR
HAVE_MODELS = os.path.exists(os.path.join(MODELS, "decision.json"))
needs_models = pytest.mark.skipif(not HAVE_MODELS,
                                  reason="run ml_pipeline/train.py first")


def ev(**kw):
    base = {"method": "GET", "path": "/api/products", "query": "", "body": "",
            "body_size": 0, "template": "/api/products", "content_type": "",
            "user_agent": "curl/8.4.0", "header_count": 5, "window_count": 2,
            "burst_count": 1, "window_distinct": 1, "rate_limited": False}
    base.update(kw)
    return base


@pytest.fixture(scope="module")
def d():
    x = Detector()
    if HAVE_MODELS:
        assert x.load(MODELS), "models present but failed to load"
    return x


# ── Layer 1 ──────────────────────────────────────────────────────────────────

def test_l1_block_short_circuits_before_any_model(d):
    """A confirmed signature must not be forwarded to a statistical model for
    a second opinion - it costs latency and can only make the answer worse."""
    r = d.inspect(ev(path="/api/x", query="q=' UNION SELECT a FROM b --"))
    assert r.action == BLOCK
    assert r.layer == "L1-rules"
    assert "sqli.union" in r.rule_hits


def test_l1_rate_limit_blocks(d):
    r = d.inspect(ev(rate_limited=True, rate_reason="burst limit exceeded"))
    assert r.action == BLOCK
    assert r.layer == "L1-rate"


def test_flag_severity_does_not_short_circuit(d):
    """FLAG rules are evidence for the model, not a verdict of their own."""
    r = d.inspect(ev(path="/wp-admin"))
    assert r.layer != "L1-rules"


def test_l1_works_without_models():
    """Signature defence must survive an untrained/degraded deployment."""
    bare = Detector()
    r = bare.inspect(ev(path="/api/../../../etc/passwd"))
    assert r.action == BLOCK and r.layer == "L1-rules"


def test_no_models_reports_degraded_not_normal():
    bare = Detector()
    r = bare.inspect(ev())
    assert r.action == ALLOW
    assert r.degraded is True, "must not claim a confident 'normal' with no models"


# ── decision authority ───────────────────────────────────────────────────────

@needs_models
def test_meta_learner_is_the_decision_maker(d):
    """The regression that mattered: the previous build chose whichever of
    seven score sources scored best and shipped a gradient-boosting model,
    leaving the specified meta-learner computing an unused number."""
    r = d.inspect(ev())
    assert set(r.scores) == {"rate", "isolation_forest", "autoencoder", "meta_lr"}
    # scores are rounded to 4dp for the log; the point is that the reported
    # probability IS the meta-learner output, not some other source's score.
    assert r.probability == pytest.approx(r.scores["meta_lr"], abs=1e-4)


@needs_models
def test_meta_lr_consumes_exactly_three_base_scores(d):
    # `n_features_in_` rather than `coef_.shape`: the meta-learner is now
    # selectable (logistic regression or gradient boosting, see TRAIN_META), and
    # only the linear one has coefficients. The invariant under test is the
    # arity of the stack - three base detectors in, one decision out - which
    # holds for either model and is what a mismatch would break.
    assert d.meta_lr.n_features_in_ == 3
    assert d.meta["meta_inputs"] == ["rate", "isolation_forest", "autoencoder"]


@needs_models
def test_threshold_comes_from_training_not_a_constant(d):
    assert 0.0 < d.threshold < 1.0
    assert d.threshold == pytest.approx(d.meta["threshold"])


@needs_models
def test_feature_contract_mismatch_is_refused(d, tmp_path, monkeypatch):
    """A silent feature-order change yields a model that is confidently wrong
    on every request, so loading must fail loudly instead."""
    import json
    import shutil
    for f in os.listdir(MODELS):
        if f.endswith(".pkl"):
            shutil.copy2(os.path.join(MODELS, f), tmp_path / f)
    meta = json.load(open(os.path.join(MODELS, "decision.json")))
    meta["feature_names"] = meta["feature_names"][:-3]      # simulate drift
    (tmp_path / "decision.json").write_text(json.dumps(meta))
    assert Detector().load(str(tmp_path)) is False


# ── fail-closed ──────────────────────────────────────────────────────────────

@needs_models
def test_inference_failure_fails_closed(d, monkeypatch):
    """Attacker-controlled input that crashes extraction must not be waved
    through - that is a trivially exploitable bypass."""
    monkeypatch.setattr(config, "FAIL_CLOSED", True)
    monkeypatch.setattr(det.features, "extract",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    r = d.inspect(ev())
    assert r.action == BLOCK
    assert r.layer == "L-error"
    assert r.degraded is True


@needs_models
def test_fail_open_is_opt_in_only(d, monkeypatch):
    monkeypatch.setattr(config, "FAIL_CLOSED", False)
    monkeypatch.setattr(det.features, "extract",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert d.inspect(ev()).action == ALLOW


# ── robustness ───────────────────────────────────────────────────────────────

@needs_models
@pytest.mark.parametrize("path,body", [
    ("/" + "\x00" * 20, ""), ("/" + "%" * 300, ""), ("/", "\U0001f4a9" * 500),
    ("/" + "a" * 4000, "{" * 2000), ("/", "\\x00\\xff" * 200),
])
def test_hostile_input_never_raises(d, path, body):
    r = d.inspect(ev(path=path, body=body, body_size=len(body)))
    assert r.action in (ALLOW, BLOCK)
    assert 0.0 <= r.probability <= 1.0


@needs_models
def test_probability_is_bounded(d):
    for p in ("/api/products", "/api/users/1", "/health", "/api/orders"):
        r = d.inspect(ev(path=p, template=p))
        assert 0.0 <= r.probability <= 1.0


def test_all_block_rules_are_reachable():
    """Every BLOCK rule should have at least one triggering example in the
    regression corpus, otherwise it is untested dead weight."""
    from tests.test_rules import MUST_BLOCK
    from common import normalize as nz
    fired = set()
    for _, path, body in MUST_BLOCK:
        for h in rules.evaluate(nz.canonical(path), nz.canonical(body)):
            fired.add(h.id)
    block_rules = {r.id for r in rules.RULES if r.severity == rules.BLOCK}
    untested = block_rules - fired
    assert not untested, f"BLOCK rules with no test case: {sorted(untested)}"
