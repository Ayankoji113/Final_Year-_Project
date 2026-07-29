"""
MicroAPI Guard - API Security Gateway
Reverse Proxy + Redis Sliding Window + Feature Extraction + JSONL Logging
"""

import os
import time
import json
import asyncio
from datetime import datetime

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Response

# ======================== CONFIG ========================

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
JSONL_DIR = os.getenv("JSONL_DIR", os.path.join(os.path.dirname(__file__), "..", "data"))
JSONL_FILE = os.path.join(JSONL_DIR, "api_traffic_features.jsonl")
SLIDING_WINDOW_SECONDS = 60  # 60 second window

# ======================== APP INIT ========================

app = FastAPI(title="MicroAPI Guard - API Gateway", version="1.0.0")

# Redis connection (lazy init)
redis_client: aioredis.Redis = None

# Async queue for non-blocking JSONL writes
log_queue: asyncio.Queue = None
log_task = None


# ======================== STARTUP / SHUTDOWN ========================

@app.on_event("startup")
async def startup():
    global redis_client, log_queue, log_task

    # Connect to Redis
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await redis_client.ping()
        print(f"[GATEWAY] Redis connected at {REDIS_URL}")
    except Exception as e:
        print(f"[GATEWAY] Redis connection failed: {e}")
        print(f"[GATEWAY] Running without Redis - sliding window disabled")
        redis_client = None

    # Ensure data directory exists
    os.makedirs(JSONL_DIR, exist_ok=True)

    # Start async JSONL writer
    log_queue = asyncio.Queue()
    log_task = asyncio.create_task(jsonl_writer())

    print(f"[GATEWAY] Gateway started -> forwarding to {BACKEND_URL}")
    print(f"[GATEWAY] JSONL logging to {JSONL_FILE}")


@app.on_event("shutdown")
async def shutdown():
    global log_task
    if log_task:
        log_task.cancel()
    if redis_client:
        await redis_client.close()
    print("[GATEWAY] Shutdown complete")


# ======================== JSONL ASYNC WRITER (Task 6) ========================

async def jsonl_writer():
    """Background task: reads from queue and writes to JSONL file."""
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


# ======================== REDIS SLIDING WINDOW (Task 4) ========================

async def get_sliding_window_count(client_ip: str) -> int:
    """
    Count how many requests this client sent in the last 60 seconds.
    Uses Redis Sorted Sets: ZADD + ZREMRANGEBYSCORE + ZCARD
    """
    if not redis_client:
        return 0

    now = time.time()
    window_start = now - SLIDING_WINDOW_SECONDS
    key = f"sw:{client_ip}"

    try:
        pipe = redis_client.pipeline()
        # Add current request timestamp
        pipe.zadd(key, {str(now): now})
        # Remove entries older than window
        pipe.zremrangebyscore(key, 0, window_start)
        # Count entries in window
        pipe.zcard(key)
        # Set expiry so keys don't stay forever
        pipe.expire(key, SLIDING_WINDOW_SECONDS * 2)

        results = await pipe.execute()
        count = results[2]  # ZCARD result
        return count
    except Exception as e:
        print(f"[REDIS] Error: {e}")
        return 0


# ======================== FEATURE EXTRACTION (Task 5) ========================

def extract_features(
    request: Request,
    request_body: bytes,
    response_status: int,
    duration_ms: float,
    sliding_window_count: int,
    client_ip: str,
    ground_truth: str = "unknown"
) -> dict:
    """Extract features from each request for ML pipeline."""

    features = {
        "timestamp": time.time(),
        "client_ip": client_ip,
        "http_method": request.method,
        "http_path": request.url.path,
        "request_body_size": len(request_body),
        "response_status": response_status,
        "request_duration_ms": round(duration_ms, 2),
        "sliding_window_count": sliding_window_count,
        "label": ground_truth,
    }

    return features


# ======================== GATEWAY REVERSE PROXY (Task 3) ========================

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def gateway_proxy(request: Request, path: str):
    """
    Core gateway logic:
    1. Receive request from client
    2. Query Redis for sliding window count
    3. Forward request to backend
    4. Extract features
    5. Log to JSONL
    6. Return response to client
    """

    start_time = time.time()

    # Get client IP
    client_ip = request.client.host if request.client else "unknown"

    # Read ground truth label (sent by Locust during dataset generation)
    ground_truth = request.headers.get("x-ground-truth", "unknown")

    # Read request body
    request_body = await request.body()

    # Step 1: Get sliding window count from Redis
    sliding_window_count = await get_sliding_window_count(client_ip)

    # Step 2: Forward request to backend
    target_url = f"{BACKEND_URL}/{path}"

    # Build headers (remove host header to avoid conflicts)
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("x-ground-truth", None)  # Strip label header before forwarding

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
        print(f"[GATEWAY] ❌ Backend unreachable: {target_url}")
        return Response(
            content=json.dumps({"error": "Backend service unavailable"}),
            status_code=503,
            media_type="application/json"
        )

    # Step 3: Calculate duration
    duration_ms = (time.time() - start_time) * 1000

    # Step 4: Extract features
    features = extract_features(
        request=request,
        request_body=request_body,
        response_status=response.status_code,
        duration_ms=duration_ms,
        sliding_window_count=sliding_window_count,
        client_ip=client_ip,
        ground_truth=ground_truth
    )

    # Step 5: Log to JSONL (non-blocking)
    await log_queue.put(features)

    # Step 6: Print to console
    status_icon = "✅" if response.status_code < 400 else "⚠️"
    print(
        f"[GATEWAY] {status_icon} {request.method:6s} /{path:30s} "
        f"→ {response.status_code} | "
        f"{duration_ms:7.1f}ms | "
        f"body={len(request_body):5d}B | "
        f"window={sliding_window_count}"
    )

    # Step 7: Return backend response to client
    # Filter out hop-by-hop headers
    excluded_headers = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    response_headers = {
        k: v for k, v in response.headers.items()
        if k.lower() not in excluded_headers
    }

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=response_headers,
        media_type=response.headers.get("content-type")
    )


# ======================== GATEWAY HEALTH ========================

@app.get("/")
async def gateway_root():
    return {
        "service": "MicroAPI Guard - API Gateway",
        "version": "1.0.0",
        "backend": BACKEND_URL,
        "redis": REDIS_URL,
        "status": "running",
        "timestamp": datetime.now().isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
