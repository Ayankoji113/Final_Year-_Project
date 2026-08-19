"""Emit representative NORMAL traffic for the calibration phase.

This is step 2 of the documented deployment procedure: run the gateway in
monitor mode in front of the real backend, let real (or representative) normal
traffic flow, then run ml_pipeline/calibrate.py.

Why this step is not optional
-----------------------------
The shipped model is trained on synthetic traffic. A real deployment's client
population differs in ways that are individually small and collectively large:
header sets, user agents, pacing, whether clients sit behind NAT, how many
endpoints a session touches. Those differences move the autoencoder's
reconstruction error, so a threshold chosen on the synthetic validation split
does not transfer as-is.

Calibration measures the score distribution of THIS deployment's normal traffic
and places the threshold at the operator's false-positive budget. It changes no
model weights - see the header of calibrate.py.

Unlike generate.py this sends NO attacks and NO ground-truth labels. It is a
sample of what normal looks like here, nothing more.
"""
import argparse
import json
import random
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

GATEWAY = "http://127.0.0.1:5000"

TERMS = ["laptop", "phone", "headphones", "backpack", "mouse", "keyboard",
         "monitor", "cable", "charger", "webcam", "desk", "chair", "speaker",
         "admin", "100%", "home appliances", "select a product", "o'brien"]
FIRST = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "priya",
         "omar", "rosa", "sam", "tina", "will", "nina", "karl", "lena"]
LAST = ["smith", "jones", "khan", "patel", "garcia", "obrien", "sato", "rossi"]


def rword(n=8):
    return "".join(random.choices(string.ascii_lowercase, k=n))


def rtext():
    n = max(1, int(random.lognormvariate(1.0, 1.1) * 12))
    return " ".join(random.choice(TERMS + FIRST) for _ in range(min(n, 400)))


def requests_batch():
    """A plausible slice of legitimate activity."""
    q = urllib.parse.quote(random.choice(TERMS))
    f, l = random.choice(FIRST), random.choice(LAST)
    out = [
        ("GET", f"/api/products?page={random.randint(1,20)}"
                f"&limit={random.choice([10,20,25,50])}", None),
        ("GET", f"/api/products/{random.randint(1,500)}", None),
        ("GET", f"/api/search?q={q}&page={random.randint(1,5)}", None),
        ("GET", f"/api/users/{random.randint(1,3)}", None),
        ("GET", "/api/orders", None),
        ("GET", "/health", None),
        ("GET", f"/api/comments?page={random.randint(1,10)}&limit=20", None),
        ("POST", "/api/users/login",
         {"username": random.choice(["admin", "john", "jane"]),
          "password": random.choice(["pass123", "john456", "jane789"])}),
        ("POST", "/api/users/register",
         {"username": f"{f}_{rword(6)}", "password": rword(12),
          "name": f"{f.capitalize()} {l.capitalize()}",
          "email": f"{f}.{l}{random.randint(1,999)}@example.com"}),
        ("POST", "/api/comments",
         {"text": rtext(), "product_id": random.randint(1, 500),
          "rating": random.randint(1, 5)}),
        ("POST", "/api/orders",
         {"product_id": random.randint(1, 5), "quantity": random.randint(1, 5)}),
        ("PUT", f"/api/users/{random.randint(1,3)}",
         {"name": f"{f.capitalize()} Updated"}),
        ("GET", f"/api/products?category={urllib.parse.quote(random.choice(['Electronics','Home','Office']))}", None),
        ("GET", f"/api/files/report.{random.randint(2019,2025)}.pdf", None),
        ("GET", f"/api/v{random.randint(1,3)}/products/{random.randint(1,500)}", None),
    ]
    random.shuffle(out)
    return out[:random.randint(6, len(out))]


def send(method, path, body, client_ip=None):
    url = GATEWAY + urllib.parse.quote(path, safe="/?=&%;'+-<>{}()|*^$,:!~[]\"\\@#")
    headers = {}
    if client_ip:
        # Only honoured when the gateway runs with GUARD_TRUSTED_PROXY_HOPS>=1.
        # Used to represent a realistic multi-client population: a real API is
        # served to many clients, and per-client rate features are meaningless
        # if every request appears to come from the same address.
        headers["X-Forwarded-For"] = client_ip
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
            return r.status
    except urllib.error.HTTPError as e:
        try:
            e.read()
        except Exception:
            pass
        return e.code
    except Exception:
        return -1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", type=int, default=3000)
    ap.add_argument("--pace", type=float, default=0.02,
                    help="seconds between requests")
    ap.add_argument("--clients", type=int, default=120,
                    help="distinct client identities to spread traffic across "
                         "(requires GUARD_TRUSTED_PROXY_HOPS>=1 on the gateway)")
    ap.add_argument("--allow-enforce", action="store_true",
                    help="permit running against an enforcing gateway; used to "
                         "MEASURE the false-positive rate rather than calibrate")
    args = ap.parse_args()

    try:
        with urllib.request.urlopen(GATEWAY + "/__guard/health", timeout=5) as r:
            h = json.loads(r.read())
    except Exception as e:
        print(f"  gateway unreachable: {e}")
        return 1
    mode = h.get("mode")
    if mode != "monitor" and not args.allow_enforce:
        print(f"  ERROR: gateway is in '{mode}' mode.")
        print("  Calibration traffic must be collected in MONITOR mode, or the")
        print("  current threshold will block some of it and the sample will")
        print("  describe what survived rather than what is normal.")
        print("  (Pass --allow-enforce to measure the false-positive rate.)")
        return 1

    # A single client cannot exceed the gateway's own rate limit and still be
    # called "normal" -- that traffic is abusive by policy. Spread across
    # distinct clients so per-client rates stay in a realistic range.
    per_client = args.requests / max(1, args.clients)
    print(f"  {args.requests:,} requests across {args.clients} clients "
          f"(~{per_client:.0f} each) at {args.pace}s pacing")
    if args.clients <= 1:
        print("  WARNING: all traffic from one client. Unless you are "
              "deliberately testing")
        print("           a single-client deployment, this will saturate the "
              "rate features.")

    ips = [f"{random.randint(11,223)}.{random.randint(0,255)}."
           f"{random.randint(0,255)}.{random.randint(1,254)}"
           for _ in range(max(1, args.clients))]

    sent, codes = 0, {}
    t0 = time.time()
    while sent < args.requests:
        ip = random.choice(ips)
        for method, path, body in requests_batch():
            if sent >= args.requests:
                break
            c = send(method, path, body, client_ip=ip)
            codes[c] = codes.get(c, 0) + 1
            sent += 1
            if sent % 250 == 0:
                sys.stdout.write(f"\r  {sent:,}/{args.requests:,}   ")
                sys.stdout.flush()
            time.sleep(args.pace)
        time.sleep(random.uniform(0.05, 0.3))    # gap between sessions

    blocked = codes.get(403, 0)
    print(f"\n\n  sent {sent:,} in {time.time()-t0:.0f}s")
    print(f"  status codes: {dict(sorted(codes.items()))}")
    print(f"\n  FALSE POSITIVE RATE: {blocked}/{sent} = {100*blocked/max(1,sent):.2f}%")
    print("  (every request here is legitimate, so any 403 is a false positive)")
    if mode == "monitor":
        print("\n  next: python ml_pipeline/calibrate.py --target-fpr 0.01")
    return 0


if __name__ == "__main__":
    sys.exit(main())
