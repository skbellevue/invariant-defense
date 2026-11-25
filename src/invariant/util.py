"""Small shared helpers."""

from __future__ import annotations

import fnmatch
import hashlib
import math
import re
from collections import Counter
from collections.abc import Iterable


def shannon_entropy(data: bytes) -> float:
    """Bits per byte, 0..8. Encrypted or compressed data sits above ~7.5."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def fingerprint_secret(secret: str) -> str:
    """Stable, non-reversible identifier for a secret, safe to log and share."""
    return "sha256:" + hashlib.sha256(secret.encode()).hexdigest()[:24]


def redact(secret: str, keep: int = 4) -> str:
    if len(secret) <= keep * 3:
        return secret[:2] + "…"
    # keep a recognizable prefix (e.g. "sk-ant-", "hf_", "AIza") and the last chars
    prefix_len = min(10, max(3, secret.find("-", 3) + 1 if "-" in secret[:12] else 4))
    return f"{secret[:prefix_len]}…{secret[-keep:]}"


def norm_path(p: str | None) -> str:
    return (p or "").replace("\\", "/").lower()


def basename(p: str | None) -> str:
    return norm_path(p).rsplit("/", 1)[-1]


def glob_any(value: str | None, patterns: Iterable[str]) -> bool:
    if value is None:
        return False
    v = value.lower()
    return any(fnmatch.fnmatchcase(v, p.lower()) for p in patterns)


def domain_matches(host: str | None, suffixes: Iterable[str]) -> str | None:
    """Return the suffix that matches ``host`` (exact or sub-domain), else None."""
    if not host:
        return None
    h = host.lower().rstrip(".")
    for s in suffixes:
        s = s.lower().lstrip("*.").rstrip(".")
        if h == s or h.endswith("." + s):
            return s
    return None


_WS = re.compile(r"\s+")


def squash(s: str | None, limit: int = 240) -> str:
    s = _WS.sub(" ", s or "").strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"
