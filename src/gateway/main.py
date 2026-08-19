"""MicroAPI Guard - security gateway.

Sits in front of ANY HTTP backend as a reverse proxy. It knows nothing about the
backend's routes, framework or language; every decision is made from the request
itself plus per-client behavioural state in Redis.

Request lifecycle:
    read (capped) -> identify client -> rate state -> detect -> block | forward
                  -> log a numeric feature vector (never a raw body)
"""
import asyncio
import hashlib
import json
import os
import sys
import time
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Response
from starlette.concurrency import run_in_threadpool

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config, features           # noqa: E402
from common import normalize as nz            # noqa: E402
from gateway.detector import BLOCK, Detector  # noqa: E402
from gateway.ratelimit import RateLimiter     # noqa: E402

# Headers that must not be relayed: they describe THIS hop's connection.
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host",
}
# Additionally stripped from the RESPONSE: our own server generates these, and
# relaying the upstream copy emits the header twice.
RESPONSE_STRIP = HOP_BY_HOP | {"date", "server"}
# Never written to the event log in any form.
SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}

ADMIN_PREFIX = "/__guard"   # namespaced so it cannot shadow a backend route

detector = Detector()
state = {"redis": None, "http": None, "limiter": None, "queue": None,
         "writer": None, "started": 0.0}
stats = {"total": 0, "allowed": 0, "blocked": 0, "by_layer": {}}


# ── client identity ───────────────────────────────────────────────────────────

def client_id(request: Request) -> str:
    """Resolve the client address.

    X-Forwarded-For is client-controlled unless a proxy you trust wrote it, so
    trusting it blindly makes every per-IP control spoofable by adding one
    header. We only read it when the operator declares how many trusted hops we
    sit behind, and we take the entry that hop actually appended.
    """
    peer = request.client.host if request.client else "unknown"
    hops = config.TRUSTED_PROXY_HOPS
    if hops <= 0:
        return peer
    xff = request.headers.get("x-forwarded-for")
    if not xff:
        return peer
    chain = [p.strip() for p in xff.split(",") if p.strip()]
    if not chain:
        return peer
    idx = len(chain) - hops
    return chain[idx] if 0 <= idx < len(chain) else chain[0]


def hash_client(cid: str) -> str:
    """Pseudonymise the client address before it reaches disk."""
    return hashlib.sha256(cid.encode("utf-8", "ignore")).hexdigest()[:16]


# ── lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(config.DATA_DIR, exist_ok=True)

    try:
        state["redis"] = aioredis.from_url(config.REDIS_URL, decode_responses=True)
        await state["redis"].ping()
        print(f"[gateway] redis connected: {config.REDIS_URL}")
    except Exception as e:
        print(f"[gateway] redis unavailable ({e}) - rate limiting DEGRADED")
        state["redis"] = None

    state["limiter"] = RateLimiter(state["redis"])
    # One pooled client for the process. Building an AsyncClient per request
    # throws away connection reuse and adds a full TCP handshake to every call.
    state["http"] = httpx.AsyncClient(
        timeout=config.UPSTREAM_TIMEOUT,
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        follow_redirects=False,
    )
    state["queue"] = asyncio.Queue(maxsize=10_000)
    state["writer"] = asyncio.create_task(_log_writer())
    state["started"] = time.time()

    ok = detector.load()
    if not ok and config.ENFORCING:
        # Starting an enforcing gateway with no anomaly models would advertise
        # protection it cannot deliver. Misconfiguration must be loud.
        raise RuntimeError(
            f"GUARD_MODE=enforce but models could not be loaded from "
            f"{config.MODELS_DIR}. Train them, mount them, or start with "
            f"GUARD_MODE=monitor."
        )

    print(f"[gateway] mode={config.MODE} models={'loaded' if ok else 'ABSENT'} "
          f"baseline={'ready' if detector.baseline.ready else 'uncalibrated'}")
    print(f"[gateway] upstream={config.BACKEND_URL}")
    yield

    if state["writer"]:
        state["writer"].cancel()
    if state["http"]:
        await state["http"].aclose()
    if state["redis"]:
        await state["redis"].aclose()


app = FastAPI(title="MicroAPI Guard", version="3.0.0", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


# ── event log ─────────────────────────────────────────────────────────────────

async def _log_writer():
    """Batched append-only writer. Runs off the request path so disk latency
    never shows up in the client's response time."""
    buf = []
    while True:
        try:
            rec = await asyncio.wait_for(state["queue"].get(), timeout=1.0)
            buf.append(rec)
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            break
        except Exception:
            continue

        if buf and (len(buf) >= 50 or state["queue"].empty()):
            try:
                with open(config.EVENT_LOG, "a", encoding="utf-8") as fh:
                    for r in buf:
                        fh.write(json.dumps(r, separators=(",", ":")) + "\n")
            except Exception as e:
                print(f"[gateway] log write failed: {e}")
            buf.clear()


def enqueue(rec: dict):
    q = state["queue"]
    if q is None:
        return
    try:
        q.put_nowait(rec)
    except asyncio.QueueFull:
        pass   # shed logging before shedding traffic


# ── admin endpoints ───────────────────────────────────────────────────────────

@app.get(ADMIN_PREFIX + "/health")
async def health():
    redis_ok = False
    if state["redis"]:
        try:
            redis_ok = bool(await state["redis"].ping())
        except Exception:
            redis_ok = False
    return {
        "status": "healthy",
        "mode": config.MODE,
        # Makes the L1/L4 enforcement split explicit: under enforce-l1 the
        # deterministic layers block while the statistical layer only observes.
        "enforcing_rules": config.ENFORCING,
        "enforcing_ml": config.ML_ENFORCING,
        "models_loaded": detector.loaded,
        "calibrated": detector.baseline.ready,
        "calibration_samples": detector.baseline.n_samples,
        "redis": redis_ok,
        "threshold": detector.threshold,
        "uptime_s": round(time.time() - state["started"], 1),
    }


@app.get(ADMIN_PREFIX + "/stats")
async def get_stats():
    return {**stats, "trained_at": (detector.meta or {}).get("trained_at")}


@app.post(ADMIN_PREFIX + "/reload")
async def reload_models():
    """Hot-reload models and baseline after retraining or recalibration."""
    ok = detector.load()
    return {"reloaded": ok, "calibrated": detector.baseline.ready}


# ── proxy ─────────────────────────────────────────────────────────────────────

async def read_body_capped(request: Request):
    """Read the body but refuse to buffer more than the cap.

    `await request.body()` is unbounded: a single large POST can pin the whole
    body in memory, and the old generator already sent 200 KB bodies.
    """
    total, chunks = 0, []
    async for chunk in request.stream():
        total += len(chunk)
        if total > config.MAX_BODY_BYTES:
            return None, total
        chunks.append(chunk)
    return b"".join(chunks), total


@app.api_route("/{full_path:path}",
               methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy(request: Request, full_path: str):
    t0 = time.perf_counter()
    cid = client_id(request)
    path = request.url.path
    query = request.url.query or ""
    template = nz.path_template(path)

    body, size = await read_body_capped(request)
    if body is None:
        return _json(413, {"error": "Request body too large",
                           "limit_bytes": config.MAX_BODY_BYTES})

    rate = await state["limiter"].check(cid, template)

    ev = {
        "method": request.method,
        "path": path,
        "query": query,
        "body": body[:config.BODY_INSPECT_BYTES].decode("utf-8", "ignore"),
        "body_size": size,
        "template": template,
        "content_type": request.headers.get("content-type", ""),
        "user_agent": request.headers.get("user-agent", ""),
        "header_count": len(request.headers),
        "has_referer": bool(request.headers.get("referer")),
        "has_auth": bool(request.headers.get("authorization")),
        "window_count": rate.window_count,
        "burst_count": rate.burst_count,
        "window_distinct": rate.distinct_paths,
        "rate_limited": rate.limited,
        "rate_reason": rate.reason,
    }

    # Tree ensembles and the AE are synchronous CPU work. Running them inline
    # would block the event loop for every other in-flight request.
    decision = await run_in_threadpool(detector.inspect, ev)

    # L1 verdicts (signatures, rate limits) are deterministic and enforced in
    # both enforce modes. L4 verdicts are statistical and only enforced once the
    # operator has promoted the deployment to full `enforce` - see config.MODE.
    ml_verdict = decision.layer in ("L4-meta", "L-error")
    enforced = decision.action == BLOCK and config.ENFORCING and (
        config.ML_ENFORCING or not ml_verdict)
    stats["total"] += 1
    if enforced:
        stats["blocked"] += 1
        stats["by_layer"][decision.layer] = stats["by_layer"].get(decision.layer, 0) + 1
    else:
        stats["allowed"] += 1

    label = None
    if config.TRUST_LABEL_HEADER:
        # Lab-only. In production this header is ignored, because whoever can
        # set it can hand-label the corpus the next model trains on.
        label = request.headers.get("x-ground-truth")

    def log(status, latency_ms, detect_ms):
        enqueue({
            "ts": round(time.time(), 3),
            "client": hash_client(cid),
            "method": request.method,
            "template": template,
            "path_len": len(path),
            "body_size": size,
            "status": status,
            # Raw rate counters are logged as METADATA, not as model features.
            # Layer 1 owns rate policy; the trainer needs these to reconstruct
            # L1's continuous score, but they must not reach L2/L3.
            "window_count": rate.window_count,
            "burst_count": rate.burst_count,
            "latency_ms": round(latency_ms, 3),
            "detect_ms": round(detect_ms, 3),
            "action": decision.action,
            "enforced": enforced,
            "layer": decision.layer,
            "reason": decision.reason[:200],
            "probability": round(decision.probability, 4),
            "scores": decision.scores,
            "rule_hits": decision.rule_hits,
            "categories": decision.categories,
            "degraded": decision.degraded or rate.degraded,
            # The numeric feature vector IS the training data. Raw bodies are
            # never written, so login passwords cannot leak through the log.
            "features": _feature_snapshot(ev),
            "label": label,
        })

    detect_ms = (time.perf_counter() - t0) * 1000

    if enforced:
        log(403, detect_ms, detect_ms)
        return _json(403, {
            "error": "Request blocked by MicroAPI Guard",
            "layer": decision.layer,
            "reason": decision.reason,
            "categories": decision.categories,
        }, extra={"X-Guard-Action": "block", "X-Guard-Layer": decision.layer})

    # ── forward ──────────────────────────────────────────────────────────────
    fwd = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}
    fwd.pop("x-ground-truth", None)
    fwd["x-forwarded-for"] = cid
    fwd["x-forwarded-proto"] = request.url.scheme
    fwd["x-guard-request-id"] = hashlib.sha256(
        f"{t0}{cid}{path}".encode()).hexdigest()[:16]

    url = config.BACKEND_URL.rstrip("/") + path
    try:
        upstream = await state["http"].request(
            request.method, url, headers=fwd, content=body,
            params=dict(request.query_params) or None,
        )
    except httpx.TimeoutException:
        log(504, (time.perf_counter() - t0) * 1000, detect_ms)
        return _json(504, {"error": "Backend timed out"})
    except httpx.RequestError:
        log(502, (time.perf_counter() - t0) * 1000, detect_ms)
        return _json(502, {"error": "Backend unavailable"})

    latency_ms = (time.perf_counter() - t0) * 1000
    log(upstream.status_code, latency_ms, detect_ms)

    out = {k: v for k, v in upstream.headers.items() if k.lower() not in RESPONSE_STRIP}
    out["X-Guard-Action"] = "allow"
    if decision.action == BLOCK and not enforced:
        # monitor mode, or an ML verdict under enforce-l1
        out["X-Guard-Would-Block"] = decision.layer
    return Response(content=upstream.content, status_code=upstream.status_code,
                    headers=out)


def _feature_snapshot(ev: dict) -> dict:
    try:
        f = features.extract(ev, detector.baseline)
        return {k: round(float(v), 5) for k, v in f.items() if not k.startswith("_")}
    except Exception:
        return {}


def _json(status: int, payload: dict, extra: dict = None) -> Response:
    return Response(content=json.dumps(payload), status_code=status,
                    media_type="application/json", headers=extra or {})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
