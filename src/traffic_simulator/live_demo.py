"""Continuous demo traffic for the security console.

Sends a realistic mix of legitimate requests and attacks through the gateway,
indefinitely, so the dashboard has something live to show.

PACING
------
Stays well under the Layer-1 limits on purpose. GUARD_RATE_LIMIT is 240 per
60 s (4 rps) and the burst allowance is 40 per 5 s. Running at ~2 rps leaves
headroom, so the console shows signature blocks and ML verdicts rather than a
wall of rate-limit blocks - which is what happens the moment you exceed 4 rps
and is much less interesting to look at.

Attacks are drawn from the project's own corpus. Nothing here is fabricated:
every verdict on the dashboard is the real gateway deciding in real time.

    python traffic_simulator/live_demo.py            # run until Ctrl-C
    python traffic_simulator/live_demo.py --rps 1.5 --attack-ratio 0.25
"""
import argparse
import json
import random
import signal
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

GATEWAY = "http://127.0.0.1:5000"
_running = True

NAMES = ["amara", "bjorn", "chidi", "dilnoza", "eitan", "fatima", "gustavo",
         "hyeon", "isabela", "jarek", "kwame", "leilani", "mateus", "nadia"]
LOOKUPS = ["wireless mouse", "usb-c hub", "standing desk", "mechanical keyboard",
           "laptop stand", "4k monitor", "webcam", "o'neill", "50% off", "café chair"]
SECTIONS = ["Electronics", "Accessories", "Home", "Office"]


def tok(n):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


def qs(**kw):
    items = [(k, v) for k, v in kw.items() if v is not None]
    random.shuffle(items)
    return ("?" + urllib.parse.urlencode(items)) if items else ""


def maybe(v, p=0.5):
    return v if random.random() < p else None


def benign():
    """One legitimate request. Shapes vary the way real clients vary."""
    k = random.random()
    if k < 0.26:
        return "GET", f"/api/products/{random.randint(1, 5)}", None
    if k < 0.40:
        return "GET", "/api/products" + qs(page=maybe(random.randint(1, 9), .6),
                                           limit=maybe(random.choice([10, 20, 50]), .5),
                                           category=maybe(random.choice(SECTIONS), .3)), None
    if k < 0.52:
        return "GET", "/api/orders" + qs(limit=maybe(20, .4)), None
    if k < 0.62:
        return "POST", "/api/users/login", {
            "username": random.choice(NAMES), "password": tok(random.randint(6, 18))}
    if k < 0.72:
        return "GET", "/api/search" + qs(q=random.choice(LOOKUPS),
                                         page=maybe(random.randint(1, 4), .4)), None
    if k < 0.82:
        b = {"text": "works well. " * random.randint(1, 12)}
        if random.random() < .6:
            b["product_id"] = random.randint(1, 5)
        if random.random() < .5:
            b["rating"] = random.randint(1, 5)
        return "POST", "/api/comments", b
    if k < 0.90:
        return "GET", f"/api/users/{random.randint(1, 3)}", None
    if k < 0.96:
        return "GET", "/health", None
    return "POST", "/api/orders", {"product_id": random.randint(1, 5),
                                   "quantity": random.randint(1, 6)}


# Drawn from the project's own attack corpus. The split matters for the
# dashboard: SIGNED families are blocked by Layer 1 and show as real 403s,
# UNSIGNED ones have no signature and show as ML "would block" verdicts under
# enforce-l1 - which is exactly the distinction the console exists to display.
SIGNED = [
    ("sqli", "GET", lambda: "/api/products" + qs(id="1 UNION SELECT * FROM users--"), None),
    ("sqli", "GET", lambda: "/api/users" + qs(id="1' OR '1'='1"), None),
    ("sqli", "GET", lambda: "/api/search" + qs(q="1'; DROP TABLE orders;--"), None),
    ("traversal", "GET", lambda: "/api/" + "../" * random.randint(3, 6) + "etc/passwd", None),
    ("traversal", "GET", lambda: "/api/files/" + "%2e%2e%2f" * 4 + "etc/shadow", None),
    ("xss", "GET", lambda: "/api/search" + qs(q="<script>alert(1)</script>"), None),
    ("xss", "POST", lambda: "/api/comments",
     lambda: {"text": "<img src=x onerror=alert(document.cookie)>", "product_id": 1}),
    ("cmdi", "GET", lambda: "/api/export" + qs(f="x;cat /etc/passwd"), None),
    ("ssrf", "GET", lambda: "/api/fetch" + qs(url="http://169.254.169.254/latest/meta-data/"), None),
    ("scan", "GET", lambda: random.choice(["/.env", "/.git/config", "/.aws/credentials"]), None),
    ("scan", "GET", lambda: random.choice(["/wp-admin", "/phpmyadmin", "/adminer"]), None),
]
UNSIGNED = [
    ("nosql", "POST", lambda: "/api/users/login",
     lambda: {"username": {"$ne": None}, "password": {"$ne": None}}),
    ("massassign", "POST", lambda: "/api/users/register",
     lambda: {"username": tok(6), "password": tok(10), "name": "x",
              "email": "a@b.test", "role": "admin", "is_staff": True}),
    ("idor", "GET", lambda: f"/api/users/{random.randint(10000, 99999)}", None),
    ("logic", "POST", lambda: "/api/orders",
     lambda: {"product_id": 1, "quantity": -random.randint(10 ** 4, 10 ** 7)}),
    ("enum", "GET", lambda: "/api/products" + qs(limit=10 ** random.randint(6, 9)), None),
]


def attack():
    fam, method, path_fn, body_fn = random.choice(
        SIGNED if random.random() < 0.65 else UNSIGNED)
    return fam, method, path_fn(), (body_fn() if callable(body_fn) else None)


def send(method, path, body):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(GATEWAY + path, data=data, method=method)
    if data:
        req.add_header("content-type", "application/json")
    req.add_header("user-agent", "microapi-live-demo/1.0")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def stop(_sig, _frm):
    global _running
    _running = False


def main():
    ap = argparse.ArgumentParser(description="Continuous demo traffic")
    ap.add_argument("--rps", type=float, default=2.0,
                    help="requests per second; keep under 4 or Layer 1 rate-limits you")
    ap.add_argument("--attack-ratio", type=float, default=0.22)
    ap.add_argument("--seconds", type=int, default=0, help="0 = run until Ctrl-C")
    args = ap.parse_args()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    if args.rps > 3.5:
        print(f"WARNING: {args.rps} rps is close to GUARD_RATE_LIMIT (4 rps). "
              f"The dashboard will fill with rate-limit blocks.")

    gap = 1.0 / max(0.1, args.rps)
    t0 = time.time()
    n = codes = 0
    tally = {}
    print(f"sending ~{args.rps} rps, {args.attack_ratio:.0%} attacks, to {GATEWAY}")
    print("Ctrl-C to stop\n")
    while _running:
        if args.seconds and time.time() - t0 > args.seconds:
            break
        if random.random() < args.attack_ratio:
            fam, m, p, b = attack()
        else:
            fam, (m, p, b) = "normal", benign()
        st = send(m, p, b)
        n += 1
        tally[st] = tally.get(st, 0) + 1
        if n % 50 == 0:
            el = time.time() - t0
            print(f"  {n:>6} sent  {n / el:.1f} rps  {el:.0f}s   "
                  f"status: {dict(sorted(tally.items()))}", flush=True)
        time.sleep(gap)
    print(f"\nstopped after {n} requests in {time.time() - t0:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
