"""Layer 1 - deterministic security signatures.

Design rules for this file:

1. A pattern only earns severity BLOCK if a legitimate API client would
   essentially never emit it. Everything weaker is FLAG: it becomes evidence
   for the ML layer instead of an immediate 403.
2. Patterns match STRUCTURE, not single characters. The previous version keyed
   on a bare apostrophe and on `--`, which fires on any surname like O'Brien or
   any hyphenated text. That is how WAFs earn their reputation for blocking
   real users.
3. Everything is matched against the normalized/decoded form (see normalize.py)
   so percent-, double-percent-, entity- and unicode-encoded variants collapse
   onto the same signature.

The regression suite in tests/test_rules.py asserts both directions: known
attacks must hit, and a corpus of awkward-but-legitimate requests
(`?q=admin`, `?q=100%`, `O'Brien`, `category=home appliances`) must not.
"""
import re
from dataclasses import dataclass
from typing import List, Optional

BLOCK = "block"
FLAG = "flag"

PATH = "path"      # match against path + query string
BODY = "body"      # match against request body
ANY = "any"        # match against either


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    target: str
    pattern: re.Pattern
    why: str


def _r(id, category, severity, target, pattern, why, flags=re.I):
    return Rule(id, category, severity, target, re.compile(pattern, flags), why)


RULES: List[Rule] = [
    # ── SQL injection ─────────────────────────────────────────────────────────
    _r("sqli.union", "sqli", BLOCK, ANY,
       r"\bunion\b[\s/*]+(?:all[\s/*]+)?\bselect\b",
       "UNION SELECT is never emitted by a legitimate API client"),
    _r("sqli.tautology", "sqli", BLOCK, ANY,
       r"['\"\s(]\s*(?:or|and)\s+['\"]?[\w]+['\"]?\s*=\s*['\"]?[\w]+['\"]?\s*(?:--|#|/\*|$|\))",
       "boolean tautology terminated by a comment or paren (' OR '1'='1' --)"),
    _r("sqli.stacked_ddl", "sqli", BLOCK, ANY,
       r";\s*(?:drop|truncate|alter|create)\s+(?:table|database|schema)\b",
       "stacked DDL statement"),
    _r("sqli.stacked_dml", "sqli", BLOCK, ANY,
       r";\s*(?:update|insert\s+into|delete\s+from)\s+\w+",
       "stacked DML statement"),
    _r("sqli.xp_cmdshell", "sqli", BLOCK, ANY,
       r"\b(?:xp_cmdshell|sp_executesql|utl_http|dbms_lock)\b",
       "database command-execution primitive"),
    _r("sqli.timing", "sqli", BLOCK, ANY,
       r"\b(?:sleep|pg_sleep|benchmark|waitfor\s+delay)\s*\(",
       "time-based blind SQLi probe"),
    _r("sqli.schema", "sqli", BLOCK, ANY,
       r"\b(?:information_schema|sysobjects|pg_catalog|mysql\.user)\b",
       "database metadata enumeration"),
    _r("sqli.comment_terminator", "sqli", FLAG, ANY,
       r"'\s*(?:--|#|/\*)",
       "quote immediately followed by a comment token"),

    # ── Cross-site scripting ──────────────────────────────────────────────────
    _r("xss.script_tag", "xss", BLOCK, ANY,
       r"<\s*script[\s/>]",
       "inline <script> tag"),
    _r("xss.event_handler", "xss", BLOCK, ANY,
       r"<[^>]{0,64}\bon(?:error|load|click|mouseover|focus|animationstart)\s*=",
       "HTML tag carrying a JS event handler"),
    _r("xss.js_uri", "xss", BLOCK, ANY,
       r"(?:javascript|vbscript|data)\s*:\s*(?:[^,\s]*script|alert|eval|document)",
       "script-bearing URI scheme"),
    _r("xss.dom_exfil", "xss", BLOCK, ANY,
       r"document\s*\.\s*(?:cookie|location|write)\b",
       "DOM property used for exfiltration"),
    _r("xss.svg_iframe", "xss", BLOCK, ANY,
       r"<\s*(?:svg|iframe|object|embed|body)\b[^>]{0,64}\bon\w+\s*=",
       "vector tag with event handler"),

    # ── Path traversal / local file inclusion ─────────────────────────────────
    _r("traversal.dotdot", "traversal", BLOCK, PATH,
       r"(?:^|[/\\])\.{2,}[/\\]",
       "parent-directory escape (covers ../, ..\\, ....//)"),
    _r("traversal.semicolon", "traversal", BLOCK, PATH,
       r"\.\.\s*;\s*[/\\]",
       "..;/ path-parameter traversal bypass"),
    _r("traversal.unix_secrets", "traversal", BLOCK, ANY,
       r"/(?:etc/(?:passwd|shadow|hosts|group)|proc/self/(?:environ|cmdline))\b",
       "read of a well-known sensitive UNIX file"),
    _r("traversal.win_secrets", "traversal", BLOCK, ANY,
       r"(?:boot\.ini|windows[/\\]system32[/\\]config[/\\]sam|win\.ini)\b",
       "read of a well-known sensitive Windows file"),

    # ── Command injection ─────────────────────────────────────────────────────
    _r("cmdi.chained", "cmdi", BLOCK, ANY,
       r"[;|&`]\s*(?:cat|ls|dir|whoami|id|uname|curl|wget|nc|ncat|bash|sh|python|perl|powershell|cmd)\b",
       "shell metacharacter chained into a command"),
    _r("cmdi.substitution", "cmdi", BLOCK, ANY,
       r"\$\(\s*\w+|`\s*\w+\s*`",
       "shell command substitution"),
    _r("cmdi.reverse_shell", "cmdi", BLOCK, ANY,
       r"(?:/dev/tcp/|bash\s+-i|nc\s+-e|mkfifo)\b",
       "reverse-shell primitive"),

    # ── Server-side template / expression injection ───────────────────────────
    _r("ssti.expr", "ssti", FLAG, ANY,
       r"\{\{[^}]{1,64}\}\}|\$\{[^}]{1,64}\}|<%=[^%]{1,64}%>",
       "template expression delimiters in user input"),

    # ── Sensitive path probing / scanner fingerprints ─────────────────────────
    # The alternatives must NOT carry their own trailing slash: consuming it
    # and then also requiring a boundary means `/.git/config` never matches,
    # while `/.git` alone does. Keep the boundary in one place.
    _r("scan.vcs_secrets", "scan", BLOCK, PATH,
       r"/(?:\.env|\.git|\.svn|\.hg|\.aws|\.ssh|id_rsa|\.htpasswd)(?:$|[/?])",
       "request for a version-control or credential artifact"),
    _r("scan.admin_panels", "scan", FLAG, PATH,
       r"/(?:wp-admin|wp-login|phpmyadmin|adminer|pma|cgi-bin|server-status)\b",
       "probe for a well-known admin panel"),
    _r("scan.config_files", "scan", FLAG, PATH,
       r"/(?:config\.(?:php|json|yml|yaml)|web\.config|\.htaccess|dump\.sql|backup\.zip)(?:$|[/?])",
       "probe for a config or backup artifact"),

    # ── Deserialization / SSRF ────────────────────────────────────────────────
    _r("deser.java", "deser", BLOCK, BODY,
       r"(?:rO0AB|aced0005|__reduce__|pickle\.loads|ObjectInputStream)",
       "serialized-object payload marker"),
    _r("ssrf.metadata", "ssrf", BLOCK, ANY,
       r"(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com)",
       "cloud instance-metadata endpoint (SSRF credential theft)"),
]


@dataclass
class RuleHit:
    id: str
    category: str
    severity: str
    why: str


def evaluate(canon_path: str, canon_body: str) -> List[RuleHit]:
    """Run every rule against the already-normalized path and body.

    Callers MUST pass normalize.canonical() output. Passing raw strings would
    let a single percent-encode walk past every signature here.
    """
    hits: List[RuleHit] = []
    for rule in RULES:
        subject = None
        if rule.target == PATH:
            subject = canon_path
        elif rule.target == BODY:
            subject = canon_body
        else:
            subject = canon_path + "\n" + canon_body
        if subject and rule.pattern.search(subject):
            hits.append(RuleHit(rule.id, rule.category, rule.severity, rule.why))
    return hits


def worst_severity(hits: List[RuleHit]) -> Optional[str]:
    if any(h.severity == BLOCK for h in hits):
        return BLOCK
    if hits:
        return FLAG
    return None
