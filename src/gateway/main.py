"""
MicroAPI Guard - API Security Gateway
Reverse Proxy + Redis Sliding Window + Feature Extraction + ML Inference + JSONL Logging
Phase 4: Real-time ML Attack Detection (HTTP 403 Blocking)
"""

import os
import sys
import time
import json
import pickle
import asyncio
import datetime
from datetime import datetime as dt

import httpx
import numpy as np
import pandas as pd
import joblib
import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Response

# ======================== CONFIG ========================

BACKEND_URL          = os.getenv("BACKEND_URL", "http://localhost:8000")
REDIS_URL            = os.getenv("REDIS_URL", "redis://localhost:6379")
JSONL_DIR            = os.getenv("JSONL_DIR", os.path.join(os.path.dirname(__file__), "..", "data"))
JSONL_FILE           = os.path.join(JSONL_DIR, "api_traffic_features.jsonl")
MODELS_DIR           = os.getenv("MODELS_DIR", "/app/models")
SLIDING_WINDOW_SECS  = 60
# True = block attacks (production), False = log only (calibration/training)
ENFORCEMENT_MODE     = os.getenv("ML_ENFORCEMENT_MODE", "true").lower() == "true"

# ======================== NUMPY AUTOENCODER (must match train.py exactly) ========================

class NumpyAutoencoder:
    """Pure-NumPy autoencoder — identical class needed to unpickle autoencoder.pkl"""
    def __init__(self, input_dim, hidden=64, bottleneck=16, lr=0.003, epochs=80, batch=256):
        self.lr, self.epochs, self.batch = lr, epochs, batch
        def xavier(a, b):
            return np.random.randn(a, b) * np.sqrt(2.0 / (a + b))
        self.W1, self.b1 = xavier(input_dim, hidden),    np.zeros(hidden)
        self.W2, self.b2 = xavier(hidden,    bottleneck), np.zeros(bottleneck)
        self.W3, self.b3 = xavier(bottleneck, hidden),   np.zeros(hidden)
        self.W4, self.b4 = xavier(hidden,    input_dim),  np.zeros(input_dim)

    @staticmethod
    def relu(x):   return np.maximum(0.0, x)
    @staticmethod
    def relu_d(x): return (x > 0).astype(float)

    def _fwd(self, X):
        h1 = self.relu(X  @ self.W1 + self.b1)
        h2 = self.relu(h1 @ self.W2 + self.b2)
        h3 = self.relu(h2 @ self.W3 + self.b3)
        return h3 @ self.W4 + self.b4, h3, h2, h1

    def fit(self, X): pass  # Already trained

    def score(self, X):
        out, _, _, _ = self._fwd(X)
        return ((X - out) ** 2).mean(axis=1)

import sys
sys.modules['__main__'].NumpyAutoencoder = NumpyAutoencoder

# ======================== ML INFERENCE ENGINE ========================

# Globals — loaded at startup
_preprocessor    = None
_iforest         = None
_autoencoder     = None
_meta_lr         = None
_hgb             = None
_et              = None
_rf              = None
_threshold_meta  = None   # {'best_source': 'hist_gradient_boost', 'best_threshold': 0.715}

# Feature column names (must match train.py exactly)
NUMERICAL_COLS   = ['request_body_size', 'sliding_window_count']
CATEGORICAL_COLS = ['http_method', 'http_path']
ENG_NUMERICAL    = NUMERICAL_COLS + [
    'log_body_size', 'log_window',
    'is_large_body', 'is_high_rate',
    'path_has_admin', 'path_has_sqli', 'path_has_traverse',
    'path_depth', 'is_post_large',
]

def _engineer(row: dict) -> pd.DataFrame:
    """Apply same feature engineering as train.py"""
    df = pd.DataFrame([{
        'request_body_size':    float(row.get('request_body_size', 0)),
        'sliding_window_count': float(row.get('sliding_window_count', 0)),
        'http_method':          str(row.get('http_method', 'GET')),
        'http_path':            str(row.get('http_path', '/')),
    }])

    df['log_body_size']     = np.log1p(df['request_body_size'])
    df['log_window']        = np.log1p(df['sliding_window_count'])
    df['is_large_body']     = (df['request_body_size'] > 1000).astype(float)
    df['is_high_rate']      = (df['sliding_window_count'] > 15).astype(float)
    path = df['http_path'].astype(str).str.lower()
    df['path_has_admin']    = path.str.contains('admin|root|config', regex=True).astype(float)
    df['path_has_sqli']     = path.str.contains(r"'|--|union|select|drop", regex=True).astype(float)
    df['path_has_traverse'] = path.str.contains(r'\.\./|etc/passwd|\.env|\.git', regex=True).astype(float)
    df['path_depth']        = df['http_path'].astype(str).str.count('/').clip(0, 10).astype(float)
    df['is_post_large']     = ((df['http_method'].astype(str).str.upper() == 'POST') &
                               (df['request_body_size'] > 500)).astype(float)
    return df


def _load_models():
    """Load all trained models from MODELS_DIR at startup."""
    global _preprocessor, _iforest, _autoencoder, _meta_lr
    global _hgb, _et, _rf, _threshold_meta

    if not os.path.exists(MODELS_DIR):
        print(f"[ML] WARNING: Models dir not found: {MODELS_DIR}")
        print(f"[ML] Running in LOGGING-ONLY mode (no blocking)")
        return False

    try:
        _preprocessor   = joblib.load(os.path.join(MODELS_DIR, 'preprocessor.pkl'))
        _iforest        = joblib.load(os.path.join(MODELS_DIR, 'isolation_forest.pkl'))
        _hgb            = joblib.load(os.path.join(MODELS_DIR, 'hgb.pkl'))
        _et             = joblib.load(os.path.join(MODELS_DIR, 'extra_trees.pkl'))
        _rf             = joblib.load(os.path.join(MODELS_DIR, 'rf_direct.pkl'))
        _meta_lr        = joblib.load(os.path.join(MODELS_DIR, 'meta_learner.pkl'))

        with open(os.path.join(MODELS_DIR, 'autoencoder.pkl'), 'rb') as f:
            _autoencoder = pickle.load(f)

        with open(os.path.join(MODELS_DIR, 'threshold_meta.pkl'), 'rb') as f:
            _threshold_meta = pickle.load(f)

        print(f"[ML] All models loaded from {MODELS_DIR}")
        print(f"[ML] Best source: {_threshold_meta['best_source']}")
        print(f"[ML] Threshold:   {_threshold_meta['best_threshold']:.3f}")
        print(f"[ML] Enforcement: {'BLOCKING' if ENFORCEMENT_MODE else 'LOG ONLY'}")
        return True

    except Exception as e:
        print(f"[ML] ERROR loading models: {e}")
        return False


def _minmax_score(arr, lo=0.0, hi=1.0):
    return float(np.clip((arr - lo) / (hi - lo + 1e-9), 0, 1))


def predict(raw_features: dict) -> dict:
    """
    Run ML inference on a single request.
    Returns: {'label': 'attack'/'normal', 'score': float, 'scores': dict}
    """
    if _preprocessor is None:
        return {'label': 'normal', 'score': 0.0, 'scores': {}, 'blocked': False}

    try:
        # 1. Feature engineering
        df_eng = _engineer(raw_features)

        # 2. Preprocess (StandardScaler + OneHotEncoder)
        X = _preprocessor.transform(df_eng)

        # 3. Individual model scores
        if_score  = float(-_iforest.decision_function(X)[0])
        ae_score  = float(_autoencoder.score(X)[0])

        # Normalize unsupervised scores to [0,1]
        if_norm   = _minmax_score(if_score, -0.1, 0.3)
        ae_norm   = _minmax_score(ae_score,  0.0, 2.0)

        # Meta-LR on anomaly scores
        meta_score = float(_meta_lr.predict_proba(
            np.array([[if_norm, ae_norm]])
        )[0, 1])

        # Supervised models
        hgb_score = float(_hgb.predict_proba(X)[0, 1])
        et_score  = float(_et.predict_proba(X)[0, 1])
        rf_score  = float(_rf.predict_proba(X)[0, 1])

        # Weighted fusion (same weights as training)
        fusion_score = (0.40 * hgb_score +
                        0.20 * et_score  +
                        0.20 * rf_score  +
                        0.10 * if_norm   +
                        0.05 * ae_norm   +
                        0.05 * meta_score)

        # Select best source (from training)
        best_src   = _threshold_meta['best_source']
        threshold  = _threshold_meta['best_threshold']

        score_map = {
            'isolation_forest':      if_norm,
            'autoencoder':           ae_norm,
            'meta_lr':               meta_score,
            'hist_gradient_boost':   hgb_score,
            'extra_trees':           et_score,
            'random_forest':         rf_score,
            'fusion':                fusion_score,
        }
        final_score = score_map.get(best_src, hgb_score)
        is_attack   = final_score >= threshold

        return {
            'label':   'attack' if is_attack else 'normal',
            'score':   round(final_score, 4),
            'scores':  {k: round(v, 4) for k, v in score_map.items()},
            'blocked': is_attack and ENFORCEMENT_MODE,
        }

    except Exception as e:
        print(f"[ML] Inference error: {e}")
        return {'label': 'normal', 'score': 0.0, 'scores': {}, 'blocked': False}


# ======================== APP INIT ========================

app = FastAPI(title="MicroAPI Guard - API Gateway", version="2.0.0")

redis_client: aioredis.Redis = None
log_queue: asyncio.Queue     = None
log_task                     = None
ml_loaded                    = False


# ======================== STARTUP / SHUTDOWN ========================

@app.on_event("startup")
async def startup():
    global redis_client, log_queue, log_task, ml_loaded

    # Redis
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await redis_client.ping()
        print(f"[GATEWAY] Redis connected at {REDIS_URL}")
    except Exception as e:
        print(f"[GATEWAY] Redis unavailable: {e} — sliding window disabled")
        redis_client = None

    # Data dir
    os.makedirs(JSONL_DIR, exist_ok=True)

    # JSONL writer
    log_queue = asyncio.Queue()
    log_task  = asyncio.create_task(jsonl_writer())

    # ML Models
    ml_loaded = _load_models()

    print(f"[GATEWAY] Started → backend: {BACKEND_URL}")
    print(f"[GATEWAY] ML inference: {'ACTIVE' if ml_loaded else 'DISABLED'}")
    print(f"[GATEWAY] Mode: {'ENFORCEMENT (blocking)' if ENFORCEMENT_MODE and ml_loaded else 'LOG ONLY'}")


@app.on_event("shutdown")
async def shutdown():
    if log_task:
        log_task.cancel()
    if redis_client:
        await redis_client.close()


# ======================== JSONL ASYNC WRITER ========================

async def jsonl_writer():
    while True:
        try:
            record = await log_queue.get()
            with open(JSONL_FILE, "a") as f:
                f.write(json.dumps(record) + "\n")
            log_queue.task_done()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[LOGGER] Write error: {e}")


# ======================== REDIS SLIDING WINDOW ========================

async def get_sliding_window_count(client_ip: str) -> int:
    if not redis_client:
        return 0
    now = time.time()
    key = f"sw:{client_ip}"
    try:
        pipe = redis_client.pipeline()
        pipe.zadd(key, {str(now): now})
        pipe.zremrangebyscore(key, 0, now - SLIDING_WINDOW_SECS)
        pipe.zcard(key)
        pipe.expire(key, SLIDING_WINDOW_SECS * 2)
        results = await pipe.execute()
        return results[2]
    except Exception as e:
        print(f"[REDIS] Error: {e}")
        return 0


# ======================== HEALTH + STATUS ========================

@app.get("/health")
async def health():
    return {
        "status":      "healthy",
        "service":     "gateway-microservices",
        "timestamp":   dt.now().isoformat(),
        "ml_loaded":   ml_loaded,
        "ml_mode":     "enforcement" if ENFORCEMENT_MODE else "logging",
        "ml_model":    _threshold_meta.get('best_source') if _threshold_meta else None,
        "ml_threshold":_threshold_meta.get('best_threshold') if _threshold_meta else None,
    }


@app.get("/")
async def root():
    return {
        "service": "MicroAPI Guard - API Gateway v2.0",
        "backend": BACKEND_URL,
        "redis":   REDIS_URL,
        "ml":      "active" if ml_loaded else "disabled",
        "mode":    "enforcement" if ENFORCEMENT_MODE and ml_loaded else "log-only",
        "timestamp": dt.now().isoformat(),
    }


# ======================== MAIN PROXY ROUTE ========================

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def gateway_proxy(request: Request, path: str):

    start_time   = time.time()
    client_ip    = request.client.host if request.client else "unknown"
    ground_truth = request.headers.get("x-ground-truth", "unknown")
    request_body = await request.body()

    # Step 1: Redis sliding window
    sliding_window_count = await get_sliding_window_count(client_ip)

    # ── Step 2: ML INFERENCE (before forwarding) ─────────────────────
    full_path = request.url.path
    if request.url.query:
        full_path += f"?{request.url.query}"

    raw_features = {
        'request_body_size':    len(request_body),
        'sliding_window_count': sliding_window_count,
        'http_method':          request.method,
        'http_path':            full_path,
    }

    ml_result = predict(raw_features)

    # ── Step 3: BLOCK if attack detected ─────────────────────────────
    if ml_result['blocked']:
        duration_ms = (time.time() - start_time) * 1000
        print(
            f"[GATEWAY] 🚫 BLOCKED  {request.method:6s} /{path:30s} "
            f"score={ml_result['score']:.3f} | "
            f"{duration_ms:.1f}ms | window={sliding_window_count}"
        )
        # Log blocked request
        log_record = {
            "timestamp":            time.time(),
            "client_ip":            client_ip,
            "http_method":          request.method,
            "http_path":            full_path,
            "request_body_size":    len(request_body),
            "response_status":      403,
            "request_duration_ms":  round(duration_ms, 2),
            "sliding_window_count": sliding_window_count,
            "label":                ground_truth,
            "ml_label":             "attack",
            "ml_score":             ml_result['score'],
            "ml_scores":            ml_result['scores'],
            "blocked":              True,
        }
        await log_queue.put(log_record)

        return Response(
            content=json.dumps({
                "error":   "Request blocked by MicroAPI Guard",
                "reason":  "Anomaly detected by ML security engine",
                "score":   ml_result['score'],
                "request": f"{request.method} {full_path}",
            }),
            status_code=403,
            media_type="application/json",
        )

    # ── Step 4: Forward to backend (normal traffic) ───────────────────
    target_url = f"{BACKEND_URL}/{path}"
    headers    = dict(request.headers)
    headers.pop("host", None)
    headers.pop("x-ground-truth", None)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=request_body,
                params=dict(request.query_params),
            )
    except httpx.ConnectError:
        duration_ms = (time.time() - start_time) * 1000
        return Response(
            content=json.dumps({"error": "Backend service unavailable"}),
            status_code=503,
            media_type="application/json",
        )

    duration_ms = (time.time() - start_time) * 1000

    # ── Step 5: Log to JSONL ──────────────────────────────────────────
    log_record = {
        "timestamp":            time.time(),
        "client_ip":            client_ip,
        "http_method":          request.method,
        "http_path":            full_path,
        "request_body_size":    len(request_body),
        "response_status":      response.status_code,
        "request_duration_ms":  round(duration_ms, 2),
        "sliding_window_count": sliding_window_count,
        "label":                ground_truth,
        "ml_label":             ml_result['label'],
        "ml_score":             ml_result['score'],
        "ml_scores":            ml_result['scores'],
        "blocked":              False,
    }
    await log_queue.put(log_record)

    # ── Step 6: Console log ───────────────────────────────────────────
    icon = "✅" if response.status_code < 400 else "⚠️"
    ml_icon = "🔵" if ml_result['label'] == 'normal' else "🟡"
    print(
        f"[GATEWAY] {icon}{ml_icon} {request.method:6s} /{path:25s} "
        f"→ {response.status_code} | {duration_ms:6.1f}ms | "
        f"score={ml_result['score']:.3f} | window={sliding_window_count}"
    )

    # ── Step 7: Return response ───────────────────────────────────────
    excluded = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    resp_headers = {k: v for k, v in response.headers.items()
                    if k.lower() not in excluded}

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=resp_headers,
        media_type=response.headers.get("content-type"),
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
