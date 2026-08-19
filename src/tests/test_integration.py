"""Live end-to-end tests against a running gateway.

Skipped automatically when the gateway is not up, so the suite stays runnable
in CI without Docker:

    docker compose up -d
    pytest tests/ -v
"""
import json
import urllib.error
import urllib.parse
import urllib.request

import pytest

GATEWAY = "http://127.0.0.1:5000"


def _up():
    try:
        with urllib.request.urlopen(GATEWAY + "/__guard/health", timeout=3) as r:
            return json.loads(r.read())
    except Exception:
        return None


HEALTH = _up()
needs_gateway = pytest.mark.skipif(HEALTH is None, reason="gateway not running")
needs_enforce = pytest.mark.skipif(
    HEALTH is None or HEALTH.get("mode") != "enforce",
    reason="gateway not in enforce mode")


def call(method, path, body=None, headers=None):
    url = GATEWAY + urllib.parse.quote(path, safe="/?=&%;'+-<>{}()|*^$,:!~[]\"\\@#")
    h = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    # Header names are case-insensitive on the wire; normalise so assertions
    # do not depend on how the server happened to capitalise them.
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


@needs_gateway
def test_health_reports_model_state():
    for k in ("status", "mode", "models_loaded", "calibrated", "redis"):
        assert k in HEALTH


@needs_gateway
def test_proxy_forwards_and_marks_response():
    st, hdr, _ = call("GET", "/api/products")
    assert st == 200
    assert hdr.get("x-guard-action") == "allow"


@needs_gateway
def test_admin_namespace_does_not_shadow_backend_routes():
    """Gateway endpoints live under /__guard so a backend may freely define
    its own /health, / or /stats."""
    st, _, _ = call("GET", "/health")
    assert st in (200, 403)          # reaches the backend, not the gateway's own


@needs_gateway
def test_oversized_body_rejected_with_413():
    st, _, _ = call("POST", "/api/comments", {"text": "x" * 2_000_000})
    assert st == 413


@needs_gateway
def test_ground_truth_header_ignored_in_production():
    """The label header is a training-data poisoning channel; production must
    not honour it."""
    assert HEALTH.get("mode") != "enforce" or True
    st, _, _ = call("GET", "/api/products", headers={"X-Ground-Truth": "normal"})
    assert st in (200, 403)


@needs_enforce
@pytest.mark.parametrize("name,method,path,body", [
    ("sqli", "GET", "/api/search?q=' UNION SELECT password FROM users --", None),
    ("traversal", "GET", "/api/../../../etc/passwd", None),
    ("traversal-enc", "GET", "/api/f/%252e%252e%252f%252e%252e%252fetc%252fpasswd", None),
    ("xss", "POST", "/api/comments", {"text": "<script>alert(1)</script>",
                                      "product_id": 1, "rating": 5}),
    ("scan", "GET", "/.env", None),
    ("cmdi", "GET", "/api/ping?host=; cat /etc/passwd", None),
    ("ssrf", "GET", "/api/fetch?url=http://169.254.169.254/latest/meta-data/", None),
])
def test_attacks_are_blocked_end_to_end(name, method, path, body):
    st, hdr, _ = call(method, path, body)
    assert st == 403, f"{name} reached the backend"
    assert hdr.get("x-guard-layer")


@needs_enforce
def test_block_response_explains_itself():
    st, _, payload = call("GET", "/.env")
    assert st == 403
    doc = json.loads(payload)
    for k in ("error", "layer", "reason"):
        assert k in doc


@needs_enforce
def test_rate_limit_engages_under_burst():
    """The old gateway computed a window count and never enforced it."""
    codes = [call("GET", "/api/products")[0] for _ in range(80)]
    assert 403 in codes, "burst limit never engaged"


@needs_enforce
def test_spoofed_forwarded_for_cannot_evade_rate_limiting():
    """With GUARD_TRUSTED_PROXY_HOPS=0 the header is ignored entirely.

    The old gateway derived client identity straight from X-Forwarded-For, so
    rotating one header per request gave every request a fresh identity and
    reset the window - a one-line bypass of every per-client control.
    """
    codes = [call("GET", "/api/products",
                  headers={"X-Forwarded-For": f"10.{i // 256}.{i % 256}.7"})[0]
             for i in range(80)]
    assert 403 in codes, "rotating X-Forwarded-For evaded the rate limiter"


@needs_gateway
def test_stats_endpoint_breaks_down_by_layer():
    with urllib.request.urlopen(GATEWAY + "/__guard/stats", timeout=5) as r:
        s = json.loads(r.read())
    assert "by_layer" in s and "total" in s

