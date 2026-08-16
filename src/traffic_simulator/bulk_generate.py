"""
MicroAPI Guard - Bulk Data Generator (No Locust / No Cython)
=============================================================
Directly hits the gateway with realistic normal + attack traffic.
Uses only stdlib (urllib) so zero DLL issues with AppLocker.
"""
import urllib.request
import urllib.error
import json
import random
import time
import threading
import sys
import os
from collections import Counter

# ── CONFIG ────────────────────────────────────────────────────────────────────
GATEWAY_URL   = "http://localhost:5000"
TARGET_RECORDS = 50000          # how many NEW records to generate
NUM_THREADS   = 20              # parallel senders
ATTACK_RATIO  = 0.28            # 28% attack traffic

JSONL_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'data', 'api_traffic_features.jsonl')
)

# ── ENDPOINTS ─────────────────────────────────────────────────────────────────
NORMAL_ENDPOINTS = [
    ("GET",  "/api/users",          None),
    ("GET",  "/api/users/1",        None),
    ("GET",  "/api/products",       None),
    ("GET",  "/api/products/42",    None),
    ("GET",  "/api/orders",         None),
    ("GET",  "/api/orders/7",       None),
    ("GET",  "/health",             None),
    ("POST", "/api/users",          {"name":"Alice","email":"alice@example.com"}),
    ("POST", "/api/orders",         {"product_id":5,"qty":2,"user_id":1}),
    ("PUT",  "/api/users/1",        {"name":"Alice Updated"}),
    ("DELETE","/api/orders/3",      None),
    ("GET",  "/api/search?q=phone", None),
]

ATTACK_ENDPOINTS = [
    # SQL injection
    ("GET",  "/api/users?id=1' OR '1'='1", None),
    ("POST", "/api/login",          {"user":"admin'--","pass":"x"}),
    ("GET",  "/api/search?q='; DROP TABLE users;--", None),
    # Path traversal
    ("GET",  "/api/../../../etc/passwd", None),
    ("GET",  "/api/users/../../admin",   None),
    # Large payloads
    ("POST", "/api/upload",         {"data": "A" * 8000}),
    ("POST", "/api/users",          {"name": "x" * 5000, "email":"bad@bad.com"}),
    # Scanner patterns
    ("GET",  "/admin",              None),
    ("GET",  "/wp-admin",           None),
    ("GET",  "/.env",               None),
    ("GET",  "/config.php",         None),
    ("GET",  "/api/admin/users",    None),
    # Rate limit abuse (same endpoint spammed)
    ("GET",  "/api/users/1",        None),
    ("GET",  "/api/users/1",        None),
]


# ── STATS ─────────────────────────────────────────────────────────────────────
_lock   = threading.Lock()
_sent   = 0
_errors = 0


def current_record_count():
    if not os.path.exists(JSONL_FILE):
        return 0
    with open(JSONL_FILE, 'r', errors='ignore') as f:
        return sum(1 for l in f if l.strip())


def send_request(method, path, body, is_attack):
    global _sent, _errors
    url = GATEWAY_URL + path
    headers = {
        "Content-Type":   "application/json",
        "X-Ground-Truth": "attack" if is_attack else "normal",
        "User-Agent":     "BulkGenerator/1.0",
    }
    data = json.dumps(body).encode() if body else None
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
        with _lock:
            _sent += 1
    except Exception:
        with _lock:
            _errors += 1


def worker(n_requests):
    """Each thread sends n_requests requests."""
    rng = random.Random()
    for _ in range(n_requests):
        is_attack = rng.random() < ATTACK_RATIO
        if is_attack:
            method, path, body = rng.choice(ATTACK_ENDPOINTS)
        else:
            method, path, body = rng.choice(NORMAL_ENDPOINTS)
        send_request(method, path, body, is_attack)
        time.sleep(rng.uniform(0.01, 0.05))   # small jitter


def run(target_new_records):
    start_count = current_record_count()
    print(f"\n  Starting records : {start_count:,}")
    print(f"  Target new       : {target_new_records:,}")
    print(f"  Final target     : {start_count + target_new_records:,}")
    print(f"  Threads          : {NUM_THREADS}")
    print(f"  Attack ratio     : {ATTACK_RATIO:.0%}\n")

    per_thread = target_new_records // NUM_THREADS + 100  # slight overshoot
    threads = [threading.Thread(target=worker, args=(per_thread,), daemon=True)
               for _ in range(NUM_THREADS)]

    t0 = time.time()
    for th in threads:
        th.start()

    # Progress bar
    while any(th.is_alive() for th in threads):
        elapsed   = time.time() - t0
        cur_count = current_record_count()
        new_so_far = max(0, cur_count - start_count)
        pct        = min(100, new_so_far * 100 // target_new_records)
        bar        = '#' * (pct // 2) + '.' * (50 - pct // 2)
        rps        = new_so_far / elapsed if elapsed > 0 else 0
        eta        = (target_new_records - new_so_far) / rps if rps > 0 else 999
        sys.stdout.write(
            f"\r  [{bar}] {pct:3d}%  {new_so_far:,}/{target_new_records:,} records"
            f"  {rps:.0f} rec/s  ETA {eta:.0f}s  "
        )
        sys.stdout.flush()

        if new_so_far >= target_new_records:
            break
        time.sleep(2)

    for th in threads:
        th.join(timeout=5)

    elapsed = time.time() - t0
    end_count = current_record_count()
    new_added = end_count - start_count

    print(f"\n\n{'='*60}")
    print(f"  BULK GENERATION COMPLETE")
    print(f"{'='*60}")
    print(f"  Time elapsed     : {elapsed:.0f}s")
    print(f"  Requests sent    : {_sent:,}  (errors: {_errors})")
    print(f"  Records before   : {start_count:,}")
    print(f"  Records after    : {end_count:,}")
    print(f"  New records added: {new_added:,}")
    print(f"  File             : {JSONL_FILE}")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    # How many NEW records to add (default: enough to reach 50k)
    start = current_record_count()
    need  = max(0, 50000 - start)
    if need == 0:
        print(f"Already have {start:,} records >= 50,000. Done!")
        sys.exit(0)

    print('='*60)
    print('  MicroAPI Guard - Bulk Data Generator (AppLocker-Safe)')
    print('='*60)
    run(need)
