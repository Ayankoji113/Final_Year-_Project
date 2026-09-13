"""Corpus shape coverage — the regression guard for the false-positive bug.

WHY THIS FILE EXISTS
--------------------
The unsupervised layers learn "normal" from whatever the generator shows them.
When the generator emitted exactly one shape per endpoint, everything else
became an anomaly: `GET /api/products` with no query string scored 0.9948
against a 0.25 threshold, while the paginated form it always generated scored
0.0003. Omitting an optional parameter ranked as more hostile than most real
attacks, and the measured false-positive rate on independent traffic was 67%.

Nothing in the existing suite could catch that. `test_features.py` tests the
extraction maths on hand-built dicts, `test_rules.py` tests signatures against a
string corpus, `test_detector.py` tests decision logic. None of them look at
what the generator actually produces.

These tests assert distributional properties of `normal_requests()` and the
session profiles. They need no network and no gateway: those functions are pure
and return `(method, path, body)` tuples.

The precedent is `test_detector.py::test_all_block_rules_are_reachable`, which
cross-checks the rule table against the regression corpus for the same reason —
a control nothing exercises is a control nobody can trust.
"""
import collections
import random
import urllib.parse

import pytest

from traffic_simulator import generate as g

# Sampling has to be large enough that a 15% branch is not missing by luck.
SESSIONS = 1500
SEED = 20260912


def _shapes():
    """Collect, per (method, endpoint template), the distinct query-parameter
    key-sets and body field key-sets the generator can emit."""
    random.seed(SEED)
    query = collections.defaultdict(collections.Counter)
    body = collections.defaultdict(collections.Counter)
    methods = collections.Counter()

    def template(path):
        base = path.split("?", 1)[0]
        segs = []
        for s in base.split("/"):
            if not s:
                continue
            segs.append("{id}" if s.isdigit() else s)
        return "/" + "/".join(segs)

    for _ in range(SESSIONS):
        for fn, _w in g.NORMAL_PROFILES:
            reqs, _pace = fn()
            for method, path, b in reqs:
                key = (method, template(path))
                qkeys = frozenset(
                    k for k, _v in urllib.parse.parse_qsl(path.split("?", 1)[1])
                ) if "?" in path else frozenset()
                query[key][qkeys] += 1
                methods[method] += 1
                if b:
                    body[key][frozenset(b)] += 1
    return query, body, methods


SHAPES = None


def _cached():
    global SHAPES
    if SHAPES is None:
        SHAPES = _shapes()
    return SHAPES


# Endpoints that take optional query parameters and are called often enough for
# the distribution to be meaningful. A path-only endpoint with no optional
# parameters is not a bug, so the list is explicit rather than inferred.
QUERY_ENDPOINTS = [
    ("GET", "/api/products"),
    ("GET", "/api/orders"),
    ("GET", "/api/comments"),
    ("GET", "/health"),
]


@pytest.mark.parametrize("method,endpoint", QUERY_ENDPOINTS)
def test_endpoint_is_called_in_several_query_shapes(method, endpoint):
    """No endpoint may appear in only one shape.

    This is the exact defect that produced the 67% false-positive rate.
    """
    query, _b, _m = _cached()
    shapes = query.get((method, endpoint))
    assert shapes, f"{method} {endpoint} never generated"
    assert len(shapes) >= 3, (
        f"{method} {endpoint} only ever appears in {len(shapes)} query shape(s): "
        f"{[sorted(s) for s in shapes]}. An endpoint the corpus shows in one "
        f"shape is an endpoint the model rejects in every other shape."
    )


@pytest.mark.parametrize("method,endpoint", QUERY_ENDPOINTS)
def test_endpoint_is_sometimes_called_bare(method, endpoint):
    """The most ordinary call an endpoint receives must be well represented.

    Relying on independent per-parameter omission is not enough: four optional
    parameters at 35% produce the bare shape 1.5% of the time, measured at 12
    occurrences in 3,260 requests, which left it effectively unseen.
    """
    query, _b, _m = _cached()
    shapes = query[(method, endpoint)]
    total = sum(shapes.values())
    bare = shapes.get(frozenset(), 0)
    assert bare / total >= 0.05, (
        f"{method} {endpoint} is called with no query string only "
        f"{bare}/{total} = {bare / total:.1%} of the time. The bare form needs "
        f"to be ordinary in the corpus, not a rounding error."
    )


@pytest.mark.parametrize("method,endpoint", [
    ("POST", "/api/comments"),
    ("POST", "/api/orders"),
    ("POST", "/api/users/register"),
])
def test_bodies_vary_which_optional_fields_are_present(method, endpoint):
    """Bodies that always carry every field make body_size_z, has_body and
    ct_json a fingerprint of the endpoint rather than a description of the
    request — the same failure as the query string, in a different feature."""
    _q, body, _m = _cached()
    shapes = body.get((method, endpoint))
    assert shapes, f"{method} {endpoint} never generated a body"
    assert len(shapes) >= 2, (
        f"{method} {endpoint} always sends the same field set "
        f"{[sorted(s) for s in shapes]}."
    )


def test_no_single_shape_dominates_an_endpoint():
    """A corpus can satisfy 'several shapes' and still be 97% one of them."""
    query, _b, _m = _cached()
    offenders = []
    for (method, endpoint) in QUERY_ENDPOINTS:
        shapes = query[(method, endpoint)]
        total = sum(shapes.values())
        top = max(shapes.values())
        if top / total > 0.85:
            offenders.append(f"{method} {endpoint} {top / total:.0%}")
    assert not offenders, (
        "one shape dominates these endpoints, so the others are effectively "
        f"unseen: {offenders}"
    )


def test_unusual_http_methods_are_exercised():
    """m_patch and m_other were constant zero across the whole corpus, so any
    PATCH, OPTIONS or HEAD request in production was unseen input."""
    _q, _b, methods = _cached()
    for m in ("PATCH", "OPTIONS", "HEAD"):
        assert methods.get(m, 0) > 0, (
            f"{m} is never generated, so m_patch/m_other stay constant and real "
            f"traffic using it reads as anomalous"
        )


def test_text_bodies_are_not_uniformly_lowercase():
    """body_upper_ratio had standard deviation 0.0000 across the corpus, which
    makes a single capital letter an unbounded-sigma event."""
    random.seed(SEED)
    samples = [g.rtext() for _ in range(400)]
    with_caps = sum(1 for t in samples if any(c.isupper() for c in t))
    assert with_caps / len(samples) >= 0.5, (
        f"only {with_caps}/{len(samples)} generated texts contain a capital "
        f"letter; real bodies are not uniformly lowercase"
    )


def test_generated_normal_traffic_never_trips_a_block_rule():
    """The generator deliberately emits some traffic that trips FLAG-severity
    signatures, so n_flags is not constant zero. It must never emit normal
    traffic that trips a BLOCK rule: that would put mislabelled attacks into the
    normal training pool, which is worse than the gap it closes."""
    from common import normalize as nz
    from common import rules

    random.seed(SEED)
    blocked = []
    for _ in range(300):
        for fn, _w in g.NORMAL_PROFILES:
            for method, path, body in fn()[0]:
                hits = rules.evaluate(nz.canonical(path),
                                      nz.canonical(str(body) if body else ""))
                if any(h.severity == rules.BLOCK for h in hits):
                    blocked.append((method, path, [h.id for h in hits]))
    assert not blocked, (
        f"{len(blocked)} normal requests trip a BLOCK rule, e.g. {blocked[:3]}"
    )
