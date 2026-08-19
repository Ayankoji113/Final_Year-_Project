"""Payload normalization.

Signature matching is only as good as the normalization in front of it. Attackers
defeat naive WAF regexes with percent-encoding, double-encoding, HTML entities,
Unicode confusables, null bytes and mixed case. We collapse all of that to one
canonical form BEFORE any rule runs.

Ordering matters: decode repeatedly first, then Unicode-fold, then strip nulls,
then case-fold. Folding before decoding would miss `%2E%2E%2F`.
"""
import html
import re
import unicodedata
from urllib.parse import unquote_plus

_NULLS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_WS = re.compile(r"\s+")

MAX_DECODE_ROUNDS = 4


def url_decode_loop(s: str, max_rounds: int = MAX_DECODE_ROUNDS) -> str:
    """Percent-decode until the string stops changing (defeats double/triple encoding)."""
    for _ in range(max_rounds):
        try:
            nxt = unquote_plus(s)
        except Exception:
            return s
        if nxt == s:
            return s
        s = nxt
    return s


def normalize(s: str, max_rounds: int = MAX_DECODE_ROUNDS) -> str:
    """Canonical form used for signature matching."""
    if not s:
        return ""
    s = url_decode_loop(s, max_rounds)
    s = html.unescape(s)
    # NFKC folds fullwidth/confusable characters onto their ASCII equivalents.
    s = unicodedata.normalize("NFKC", s)
    s = _NULLS.sub("", s)
    s = _WS.sub(" ", s)
    return s


def canonical(s: str) -> str:
    """Normalized + case-folded. This is what the rule engine matches against."""
    return normalize(s).lower()


def decode_delta(raw: str) -> float:
    """How much shorter the string got when decoded, as a ratio in [0, 1].

    Legitimate traffic carries a little encoding (spaces, unicode in names).
    Heavy or nested encoding is an obfuscation signal, so we hand this to the
    model as a feature rather than blocking on it.
    """
    if not raw:
        return 0.0
    dec = normalize(raw)
    if len(raw) == 0:
        return 0.0
    return max(0.0, min(1.0, (len(raw) - len(dec)) / len(raw)))


_NUMERIC_SEG = re.compile(r"^\d+$")
_UUID_SEG = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
_HEXLIKE_SEG = re.compile(r"^[0-9a-f]{16,}$", re.I)


def path_template(path: str) -> str:
    """Collapse a concrete path to an endpoint template.

    /api/users/1837  ->  /api/users/{id}

    IMPORTANT: the template is NEVER used as a model feature. Feeding endpoint
    identity to the model is what turned the previous version into a lookup
    table. It is used only to key per-endpoint statistical baselines during
    calibration, and for human-readable grouping in the dashboard.
    """
    path = (path or "/").split("?", 1)[0]
    out = []
    for seg in path.split("/"):
        if not seg:
            continue
        if _NUMERIC_SEG.match(seg):
            out.append("{id}")
        elif _UUID_SEG.match(seg):
            out.append("{uuid}")
        elif _HEXLIKE_SEG.match(seg):
            out.append("{hash}")
        else:
            out.append(seg)
    return "/" + "/".join(out) if out else "/"
