"""Feature contract tests.

The properties asserted here are the ones that, when violated, produced the
previous build's failures: endpoint memorisation, feature-order drift between
training and serving, and NaNs from odd input.
"""
import math

import numpy as np
import pytest

from common import features
from common import normalize as nz
from common.features import Baseline


def ev(**kw):
    base = {"method": "GET", "path": "/api/products", "query": "", "body": "",
            "body_size": 0, "content_type": "", "user_agent": "curl/8.4.0",
            "header_count": 4, "window_count": 3, "burst_count": 1,
            "window_distinct": 2, "n_flags": 0}
    base.update(kw)
    return base


def test_vector_shape_and_dtype():
    v = features.to_vector(features.extract(ev()))
    assert v.shape == (features.N_FEATURES,)
    assert v.dtype == np.float32


def test_all_features_finite_on_hostile_input():
    """Attacker-controlled input must never produce NaN/inf, because the
    scaler and the model will happily propagate it into a wrong decision."""
    nasty = [
        ev(path="/" + "\x00" * 50, body="\x00\x01\x02"),
        ev(path="/" + "%" * 200),
        ev(path="/" + "‮​" * 40, body="\U0001f4a9" * 100),
        ev(path="/", query="a" * 5000, body="{" * 3000),
        ev(path="/", body="\\u0000" * 100, body_size=10 ** 9),
        ev(method="", path="", query="", body=""),
        ev(path="/%%%%%%", query="=&=&=&"),
    ]
    for e in nasty:
        v = features.to_vector(features.extract(e))
        assert np.isfinite(v).all(), f"non-finite feature vector for {e['path'][:30]!r}"


def test_extraction_is_deterministic():
    e = ev(path="/api/users/42", query="a=1", body='{"x":1}', body_size=7)
    a = features.to_vector(features.extract(e))
    b = features.to_vector(features.extract(e))
    assert np.array_equal(a, b)


def test_no_endpoint_identity_in_feature_names():
    """The regression that mattered most: no feature may encode WHICH endpoint
    this is. Any path-valued or one-hot-path feature reintroduces the lookup
    table that made the previous model untransferable."""
    for name in features.FEATURE_NAMES:
        assert not name.startswith("http_path")
        assert "/" not in name
        assert not name.startswith("cat__")


def test_same_shape_traffic_on_different_backends_looks_the_same():
    """Backend-agnosticism, stated as a testable property: two structurally
    identical requests against completely different URL vocabularies must
    produce near-identical feature vectors."""
    a = features.to_vector(features.extract(
        ev(path="/api/products/42", query="page=2", body='{"a":1}', body_size=7)))
    b = features.to_vector(features.extract(
        ev(path="/shop/artikel/42", query="page=2", body='{"a":1}', body_size=7)))
    idx = {n: i for i, n in enumerate(features.FEATURE_NAMES)}
    # path_len/entropy legitimately differ (different string lengths); the
    # behavioural and body features must not.
    for n in ("body_log_size", "body_entropy", "path_depth", "path_numeric_seg_ratio",
              "q_param_count", "win_distinct_paths", "m_get", "is_write"):
        assert a[idx[n]] == pytest.approx(b[idx[n]]), f"{n} is backend-specific"


def test_entropy_ranks_random_above_structured():
    low = features.shannon_entropy("aaaaaaaaaaaaaaaaaaaa")
    mid = features.shannon_entropy('{"name":"alice","age":30}')
    high = features.shannon_entropy("f8Kd93jXm2QpZv7Lw0Rt5YbNcHs1AeUi")
    assert low < mid < high


def test_body_size_z_uses_the_endpoint_baseline():
    bl = Baseline({"endpoints": {"/api/upload": {"body_mean": 1000.0,
                                                 "body_std": 100.0, "count": 50}},
                   "rate": {"mean": 5.0, "std": 2.0}, "n_samples": 500})
    normal = features.extract(ev(path="/api/upload", body_size=1050,
                                 template="/api/upload"), bl)
    huge = features.extract(ev(path="/api/upload", body_size=90000,
                               template="/api/upload"), bl)
    assert abs(normal["body_size_z"]) < 1.0
    assert huge["body_size_z"] >= 9.0          # clipped at 10, so "way out"


def test_z_scores_are_clipped():
    """One freak request must not be able to dominate the scaler.

    Only body_size_z remains: rate_z was removed along with the other rate
    magnitude features, because rate policy belongs to Layer 1 (see the note in
    features.FEATURE_NAMES).
    """
    bl = Baseline({"endpoints": {"/x": {"body_mean": 1.0, "body_std": 1.0, "count": 9}},
                   "rate": {"mean": 1.0, "std": 1.0}, "n_samples": 99})
    f = features.extract(ev(path="/x", template="/x", body_size=10 ** 9,
                            window_count=10 ** 6), bl)
    assert -10.0 <= f["body_size_z"] <= 10.0
    assert "rate_z" not in features.FEATURE_NAMES


def test_rate_magnitude_is_not_a_model_feature():
    """Regression guard for the L1/L4 policy conflict.

    When the unsupervised layers also saw raw rate magnitude they learned the
    corpus's rate distribution (~9 req/min) and overrode the operator's
    configured limit (240 req/min), blocking legitimate fast clients.
    """
    for banned in ("win_log_count", "burst_log_count", "rate_z"):
        assert banned not in features.FEATURE_NAMES


def test_client_supplied_headers_are_not_model_features():
    """Attacker-controlled signals must not drive the decision - they are free
    to spoof, so any accuracy gained from them is illusory."""
    for banned in ("header_count", "ua_len", "ua_entropy", "has_ua",
                   "has_referer", "has_auth"):
        assert banned not in features.FEATURE_NAMES


def test_unknown_endpoint_flagged_only_when_baseline_exists():
    ready = Baseline({"endpoints": {"/api/known": {"body_mean": 0, "body_std": 0,
                                                   "count": 10}},
                      "rate": {"mean": 1, "std": 1}, "n_samples": 100})
    assert features.extract(ev(template="/api/known"), ready)["path_known"] == 1.0
    assert features.extract(ev(template="/api/other"), ready)["path_known"] == 0.0
    # with no baseline we must not declare every endpoint novel
    assert features.extract(ev(template="/anything"), Baseline())["path_known"] == 1.0


def test_path_template_collapses_identifiers():
    assert nz.path_template("/api/users/1837") == "/api/users/{id}"
    assert nz.path_template("/api/o/9f8b7c6d-1234-4abc-8def-0123456789ab") == "/api/o/{uuid}"
    assert nz.path_template("/api/users/1837?x=1") == "/api/users/{id}"
    assert nz.path_template("/") == "/"


def test_feature_names_unique_and_ordered():
    assert len(features.FEATURE_NAMES) == len(set(features.FEATURE_NAMES))
    assert features.N_FEATURES == len(features.FEATURE_NAMES)
