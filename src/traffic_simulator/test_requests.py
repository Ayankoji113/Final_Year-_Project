"""
MicroAPI Guard — Security Gateway Traffic Simulation
======================================================
Generates an automated, randomized mix of benign and malicious
API traffic to evaluate the ML-based security gateway's 
inference accuracy and performance under load.
Results stream to the console and save to data/test_results.log

Usage:
  python test_100_requests.py              # asks for count
  python test_100_requests.py 50           # 50 requests
  python test_100_requests.py 200          # 200 requests
"""
import urllib.request
import urllib.error
import urllib.parse
import json
import random
import time
import sys
import io
import os

# Fix Windows encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:5000")
LOG_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'data', 'test_results.log')
)

# ── NORMAL ENDPOINTS ────────────────────────────────────────────────
NORMAL_ENDPOINTS = [
    ("GET",  "/api/users",              None, "List Users"),
    ("GET",  "/api/users/profile",      None, "Get Profile"),
    ("GET",  "/api/products",           None, "List Products"),
    ("GET",  "/api/products/1",         None, "Get Product"),
    ("GET",  "/api/products/2",         None, "Get Product"),
    ("GET",  "/api/products/3",         None, "Get Product"),
    ("GET",  "/api/products/4",         None, "Get Product"),
    ("GET",  "/api/products/5",         None, "Get Product"),
    ("GET",  "/api/orders",             None, "List Orders"),
    ("GET",  "/health",                 None, "Healthcheck"),
    ("POST", "/api/users/login",        {"username": "user", "password": "pwd"}, "Login"),
    ("POST", "/api/orders",             {"product_id": 1, "qty": 1}, "Create Order"),
    # Edge Cases: Suspicious but normal
    ("GET",  "/api/search?q=admin",     None, "Normal Search"),
    ("GET",  "/api/search?q=100%",      None, "Normal Search"),
    ("GET",  "/api/products?category=home%20appliances", None, "Normal Search URL Encoded"),
    ("POST", "/api/comments",           {"text": "A" * 1500, "user": 1}, "Long Normal Payload"),
]

# ── ATTACK ENDPOINTS ────────────────────────────────────────────────
ATTACK_ENDPOINTS = [
    # SQL Injection
    ("GET",  "/api/users?id=1' OR '1'='1",               None,  "SQL Injection"),
    ("GET",  "/api/search?q='; DROP TABLE users;--",     None,  "SQL Injection"),
    ("POST", "/api/users/login", {"username":"admin'--","password":"x"},  "SQL Injection"),
    ("GET",  "/api/products?id=1 UNION SELECT * FROM users--", None, "SQL Injection"),
    # Edge Case: Stealthy / Obfuscated SQLi
    ("GET",  "/api/users?id=1%27%20OR%20%271%27%3D%271", None, "Stealthy SQLi"),
    ("GET",  "/api/products?id=2-1",                     None, "Stealthy SQLi"),
    
    # Path Traversal
    ("GET",  "/api/../../../etc/passwd",                  None,  "Path Traversal"),
    ("GET",  "/api/../../etc/shadow",                     None,  "Path Traversal"),
    ("GET",  "/api/users/../../admin",                    None,  "Path Traversal"),
    ("GET",  "/../../../windows/system32/config/sam",     None,  "Path Traversal"),
    ("GET",  "/api/../../../var/log/syslog",              None,  "Path Traversal"),
    # Edge Case: Encoded Path Traversal
    ("GET",  "/api/users/%2e%2e/%2e%2e/etc/passwd",       None, "Encoded Path Traversal"),

    # Admin / Config Probes
    ("GET",  "/admin",                                    None,  "Admin Probe"),
    ("GET",  "/admin/config/database",                    None,  "Admin Probe"),
    ("GET",  "/admin/users",                              None,  "Admin Probe"),
    ("GET",  "/root/config",                              None,  "Admin Probe"),
    ("GET",  "/admin/dashboard",                          None,  "Admin Probe"),
    # Sensitive File Exposure
    ("GET",  "/.env",                                     None,  "Dotfile Exposure"),
    ("GET",  "/.git/config",                              None,  "Dotfile Exposure"),
    ("GET",  "/.git/HEAD",                                None,  "Dotfile Exposure"),
    ("GET",  "/.htaccess",                                None,  "Dotfile Exposure"),
    # Scanner Patterns
    ("GET",  "/config.php",                               None,  "Scanner Pattern"),
    ("GET",  "/wp-admin",                                 None,  "Scanner Pattern"),
    ("GET",  "/wp-login.php",                             None,  "Scanner Pattern"),
    ("GET",  "/phpmyadmin",                               None,  "Scanner Pattern"),
    ("GET",  "/xmlrpc.php",                               None,  "Scanner Pattern"),
    # Large Payload Attacks
    ("POST", "/api/products",  {"name":"x"*5000, "price":1, "category":"test", "stock":1}, "Large Payload"),
    ("POST", "/api/upload",    {"data": "A" * 8000},       "Large Payload"),
    ("POST", "/api/users",     {"name":"B"*6000, "email":"bad@bad.com"}, "Large Payload"),
    # Edge Case: Borderline large payload
    ("POST", "/api/upload",    {"data": "X" * 3000},       "Borderline Large Payload"),
]


def generate_unique_ip(index):
    """Generate a unique random-looking IP for each request."""
    random.seed(index + int(time.time()) % 10000)
    return f"{random.randint(10,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def send_request(method, path, body, ip, ground_truth):
    """Send a single request and return result dict."""
    safe_path = urllib.parse.quote(path, safe="/?=&;'+-<>{}()|*^")
    url = GATEWAY_URL + safe_path
    headers = {
        "Content-Type":    "application/json",
        "X-Forwarded-For": ip,
        "X-Ground-Truth":  ground_truth,
        "User-Agent":      f"TestBot/1.0 (IP:{ip})",
    }
    data = json.dumps(body).encode() if body else None

    t0 = time.time()
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
            return {"status": resp.status, "duration_ms": round((time.time()-t0)*1000, 1), "blocked": False}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "duration_ms": round((time.time()-t0)*1000, 1), "blocked": e.code == 403}
    except Exception:
        return {"status": 0, "duration_ms": round((time.time()-t0)*1000, 1), "blocked": False, "error": True}


def main():
    # ── GET REQUEST COUNT FROM USER ─────────────────────────────────
    if len(sys.argv) > 1:
        try:
            total = int(sys.argv[1])
        except ValueError:
            print("Usage: python test_100_requests.py [number_of_requests]")
            sys.exit(1)
    else:
        try:
            total = int(input("\n  Enter number of requests to send (e.g. 50, 100, 200): "))
        except (ValueError, EOFError):
            total = 100

    if total < 1:
        print("  Must be at least 1 request.")
        sys.exit(1)

    # 70% normal, 30% attack
    n_attack = max(1, int(total * 0.30))
    n_normal = total - n_attack

    # Open log file
    log_f = open(LOG_FILE, 'w', encoding='utf-8')

    def log(msg=""):
        print(msg)
        sys.stdout.flush()
        log_f.write(msg + "\n")
        log_f.flush()

    log("=" * 75)
    log(f"  MicroAPI Guard — Security Gateway Traffic Simulation")
    log(f"  Total Requests: {total} (Benign: {n_normal}, Malicious: {n_attack})")
    log(f"  Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log("=" * 75)

    # ── BUILD RANDOM REQUEST LIST ───────────────────────────────────
    requests = []
    for i in range(n_normal):
        endpoint = random.choice(NORMAL_ENDPOINTS)
        method, path, body = endpoint[0], endpoint[1], endpoint[2]
        requests.append({"method": method, "path": path, "body": body,
                          "type": "normal", "attack_cat": "-"})
    for i in range(n_attack):
        method, path, body, cat = random.choice(ATTACK_ENDPOINTS)
        requests.append({"method": method, "path": path, "body": body,
                          "type": "attack", "attack_cat": cat})

    # Shuffle randomly (no fixed seed = different every time)
    random.shuffle(requests)
    for i, r in enumerate(requests):
        r["index"] = i + 1

    # ── SEND REQUESTS ───────────────────────────────────────────────
    results = []
    normal_pass = normal_blocked = attack_blocked = attack_passed = errors = 0
    unique_ips = set()

    log(f"\n  Sending {total} requests ...\n")
    log(f"  {'#':>4}  {'IP':<18} {'Method':<7} {'Path':<35} {'Type':<8} {'Status':>6}  {'ms':>7}  Result")
    log(f"  {'-'*4}  {'-'*18} {'-'*7} {'-'*35} {'-'*8} {'-'*6}  {'-'*7}  {'-'*12}")

    t_start = time.time()

    for r in requests:
        ip = generate_unique_ip(r["index"])
        unique_ips.add(ip)
        result = send_request(r["method"], r["path"], r["body"], ip, r["type"])
        result["request"] = r
        results.append(result)

        if result.get("error"):
            errors += 1; verdict = "ERROR"
        elif r["type"] == "normal":
            if result["blocked"]: normal_blocked += 1; verdict = "FALSE POS"
            else: normal_pass += 1; verdict = "OK"
        else:
            if result["blocked"]: attack_blocked += 1; verdict = "BLOCKED"
            else: attack_passed += 1; verdict = "MISSED"

        icon = {"OK": "[PASS]", "BLOCKED": "[BLOCK]", "FALSE POS": "[FP]",
                "MISSED": "[MISS]", "ERROR": "[ERR]"}.get(verdict, "?")
        path_display = r["path"][:35]
        log(f"  {r['index']:>4}  {ip:<18} {r['method']:<7} {path_display:<35} {r['type']:<8} {result['status']:>6}  {result['duration_ms']:>6.1f}ms  {icon} {verdict}")
        time.sleep(0.03)

    t_elapsed = time.time() - t_start
    tp = attack_blocked
    fp = normal_blocked
    fn = attack_passed
    tn = normal_pass
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy  = (tp + tn) / total if total > 0 else 0
    avg_duration = sum(r["duration_ms"] for r in results) / len(results) if results else 0

    log(f"\n{'=' * 70}")
    log(f"  TEST RESULTS SUMMARY")
    log(f"{'=' * 70}")
    log(f"  Total Requests     : {total}")
    log(f"  Unique IPs Used    : {len(unique_ips)}")
    log(f"  Total Time         : {t_elapsed:.1f}s")
    log(f"  Avg Response Time  : {avg_duration:.1f}ms")
    log(f"  Errors             : {errors}")
    log()
    log(f"  +---------------------------------------------+")
    log(f"  |          CONFUSION MATRIX                   |")
    log(f"  |                                             |")
    log(f"  |              Predicted                      |")
    log(f"  |            Normal   Attack                  |")
    log(f"  |  Actual  +--------+--------+                |")
    log(f"  |  Normal  | TN={tn:<4}| FP={fp:<4}|  ({n_normal} normal)  |")
    log(f"  |  Attack  | FN={fn:<4}| TP={tp:<4}|  ({n_attack} attack)  |")
    log(f"  |          +--------+--------+                |")
    log(f"  +---------------------------------------------+")
    log()
    log(f"  Accuracy           : {accuracy:.1%}  ({tp+tn}/{total})")
    log(f"  Precision          : {precision:.1%}")
    log(f"  Recall             : {recall:.1%}")
    log(f"  F1 Score           : {f1:.3f}")
    log()
    log(f"  Normal Traffic     : {normal_pass}/{n_normal} passed   |  {normal_blocked}/{n_normal} false positives")
    log(f"  Attack Traffic     : {attack_blocked}/{n_attack} blocked  |  {attack_passed}/{n_attack} missed")
    log(f"{'=' * 70}")

    # ── ATTACK CATEGORY BREAKDOWN ───────────────────────────────────
    cat_stats = {}
    for r in results:
        if r["request"]["type"] == "attack":
            cat = r["request"]["attack_cat"]
            if cat not in cat_stats:
                cat_stats[cat] = {"total": 0, "blocked": 0}
            cat_stats[cat]["total"] += 1
            if r["blocked"]:
                cat_stats[cat]["blocked"] += 1

    log(f"\n  ATTACK DETECTION BY CATEGORY:")
    log(f"  {'Category':<20} {'Blocked':>8} {'Total':>8} {'Rate':>8}")
    log(f"  {'-'*20} {'-'*8} {'-'*8} {'-'*8}")
    for cat in sorted(cat_stats.keys()):
        s = cat_stats[cat]
        rate = s["blocked"] / s["total"] * 100 if s["total"] > 0 else 0
        log(f"  {cat:<20} {s['blocked']:>8} {s['total']:>8} {rate:>7.0f}%")
    log(f"{'=' * 70}")

    log_f.close()
    print(f"\n  Log saved to: {LOG_FILE}\n")


if __name__ == "__main__":
    main()
