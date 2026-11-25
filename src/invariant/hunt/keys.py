"""Provider API-key patterns.

Formats follow public secret-scanning rule sets (gitleaks, GitLab secret
detection, provider documentation). Matches are always redacted and
fingerprinted before they leave this module; the raw key is never printed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from invariant.util import fingerprint_secret, redact


@dataclass(frozen=True)
class KeyRule:
    id: str
    provider: str
    regex: re.Pattern[bytes]
    confidence: str  # high | medium | low


def _r(p: str) -> re.Pattern[bytes]:
    return re.compile(p.encode())


KEY_RULES: list[KeyRule] = [
    KeyRule("anthropic-api-key", "anthropic", _r(r"sk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93}AA"), "high"),
    KeyRule(
        "anthropic-key-generic", "anthropic", _r(r"sk-ant-[a-z]{3}\d{2}-[A-Za-z0-9_\-]{80,120}"), "medium"
    ),
    KeyRule(
        "openai-project-key",
        "openai",
        _r(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}"),
        "high",
    ),
    KeyRule("openai-legacy-key", "openai", _r(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"), "high"),
    KeyRule("openai-project-key-loose", "openai", _r(r"sk-proj-[A-Za-z0-9_\-]{48,}"), "medium"),
    KeyRule("google-api-key", "google_gemini", _r(r"AIza[0-9A-Za-z_\-]{35}"), "medium"),
    KeyRule("huggingface-token", "huggingface_inference", _r(r"hf_[A-Za-z0-9]{34,40}"), "high"),
    KeyRule("openrouter-key", "openrouter", _r(r"sk-or-v1-[a-f0-9]{64}"), "high"),
    KeyRule("groq-key", "groq", _r(r"gsk_[A-Za-z0-9]{52}"), "high"),
    KeyRule("xai-key", "xai", _r(r"xai-[A-Za-z0-9]{80}"), "high"),
    KeyRule("replicate-token", "replicate", _r(r"r8_[A-Za-z0-9]{37}"), "high"),
    KeyRule("perplexity-key", "perplexity", _r(r"pplx-[A-Za-z0-9]{48}"), "high"),
    KeyRule(
        "contextual-llm-key",
        "various",
        _r(
            r"(?i)(?:deepseek|dashscope|moonshot|mistral|cohere|together|fireworks|cerebras)[\w\-]{0,24}['\"\s:=]{1,6}([A-Za-z0-9_\-]{32,64})"
        ),
        "low",
    ),
]


@dataclass
class KeyHit:
    rule: str
    provider: str
    confidence: str
    redacted: str
    fingerprint: str
    offset: int


def find_keys(data: bytes) -> list[KeyHit]:
    hits: list[KeyHit] = []
    seen: set[str] = set()
    for rule in KEY_RULES:
        for m in rule.regex.finditer(data):
            raw = (m.group(1) if m.groups() else m.group(0)).decode("ascii", "replace")
            fp = fingerprint_secret(raw)
            if fp in seen:
                continue
            seen.add(fp)
            hits.append(KeyHit(rule.id, rule.provider, rule.confidence, redact(raw), fp, m.start()))
    return hits
