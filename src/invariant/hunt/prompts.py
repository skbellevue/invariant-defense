"""Prompts-as-code: score files for the structures LLM-enabled malware must embed.

A sample that calls a model carries (a) an endpoint, (b) instructions written
for a model, and usually (c) a way to execute what comes back. Each family is
weak alone and strong in combination; the verdicts mirror the hunting approach
SentinelLABS described (keys + prompts, then triage).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

FAMILIES: dict[str, list[str]] = {
    "model_api": [
        r"generativelanguage\.googleapis\.com",
        r"api\.openai\.com",
        r"api\.anthropic\.com",
        r"router\.huggingface\.co|api-inference\.huggingface\.co",
        r"openrouter\.ai/api",
        r"api\.deepseek\.com|dashscope(?:-intl)?\.aliyuncs\.com|api\.mistral\.ai|api\.groq\.com",
        r"/v1/chat/completions|/v1/messages|:generatecontent|/api/generate|/api/chat",
        r"[\"']messages[\"']\s*:\s*\[\s*\{\s*[\"']role[\"']",
        r"x-api-key|x-goog-api-key|authorization:\s*bearer",
    ],
    "role_prompt": [
        r"you are an? (?:expert|senior|professional|skilled|helpful)",
        r"act as an? (?:expert|senior|professional)",
        r"you are an? \w+ (?:obfuscator|assistant|administrator|developer|hacker)",
    ],
    "code_only": [
        r"(?:output|return|respond with|reply with) only (?:the )?(?:raw )?(?:code|command|script|json)",
        r"(?:no|without (?:any )?) ?(?:explanations?|markdown|comments|commentary)",
        r"do not (?:include|add|write) (?:any )?(?:explanations?|markdown|comments|text)",
        r"one[- ]line (?:windows |powershell |bash )?commands?",
        r"make a list of commands",
    ],
    "evasion": [
        r"obfuscat\w*",
        r"evade (?:antivirus|av|edr|detection|static analysis)",
        r"bypass (?:antivirus|amsi|edr|defender|detection)",
        r"polymorphic|metamorphic",
        r"undetectable",
        r"rewrite (?:the |your |this )?(?:entire )?(?:source|code|script)",
    ],
    "harmful_intent": [
        r"encrypt (?:all |the )?(?:user )?files",
        r"ransom note",
        r"(?:gather|collect) (?:computer|system|hardware|network|domain) information",
        r"copy (?:all )?(?:office|pdf|txt|documents?)\b",
        r"(?:exfiltrat|steal)\w* (?:credentials|tokens|data|files)",
    ],
    "analyst_injection": [
        r"ignore (?:all |any )?(?:previous|prior|above) instructions",
        r"no malware detected",
        r"this (?:file|sample|binary|code) is (?:benign|safe|clean|not malicious)",
        r"you are now (?:a|an|in) ",
        r"(?:respond|answer) (?:only )?with [\"']?(?:benign|safe|clean)",
    ],
    "exec": [
        r"wscript\.shell|shell\.application|createobject\(",
        r"subprocess\.(?:run|popen|call|check_output)|os\.system|os\.popen",
        r"invoke-expression|\biex\b|start-process",
        r"child_process|execsync\(|spawnsync\(",
        r"os/exec|exec\.command\(",
        r"runtime\.getruntime\(\)\.exec",
        r"loadstring\(|dostring\(",
        r"\beval\(|\bexec\(",
    ],
}

_COMPILED = {k: [re.compile(p.encode(), re.I) for p in v] for k, v in FAMILIES.items()}


@dataclass
class PromptVerdict:
    families: dict[str, list[str]] = field(default_factory=dict)
    verdicts: list[tuple[str, str, str]] = field(default_factory=list)  # (id, severity, title)

    @property
    def worst(self) -> str:
        order = ["info", "low", "medium", "high", "critical"]
        return max((s for _, s, _ in self.verdicts), key=order.index, default="info")


def analyze(data: bytes, has_key: bool = False) -> PromptVerdict:
    v = PromptVerdict()
    for fam, rxs in _COMPILED.items():
        found = []
        for rx in rxs:
            m = rx.search(data)
            if m:
                found.append(m.group(0)[:60].decode("utf-8", "replace"))
        if found:
            v.families[fam] = found
    f = v.families
    instructions = "role_prompt" in f or "code_only" in f
    if "model_api" in f and "exec" in f and instructions:
        v.verdicts.append(
            (
                "HUNT-LLM-EXEC",
                "high",
                "Calls a model, carries model instructions and can execute the reply (just-in-time code)",
            )
        )
    if "model_api" in f and "evasion" in f:
        v.verdicts.append(
            (
                "HUNT-LLM-EVASION",
                "critical" if "exec" in f else "high",
                "Asks a model for obfuscation/evasion: self-rewriting malware pattern",
            )
        )
    if "model_api" in f and "harmful_intent" in f:
        v.verdicts.append(
            ("HUNT-LLM-HARMFUL", "high", "Model prompt expresses collection, theft or encryption intent")
        )
    if "analyst_injection" in f:
        v.verdicts.append(
            ("HUNT-ANALYST-INJECTION", "high", "Embedded prompt injection aimed at AI-based analysis tools")
        )
    if has_key and "model_api" in f:
        v.verdicts.append(
            ("HUNT-EMBEDDED-KEY", "high", "Provider API key embedded alongside model API usage")
        )
    elif has_key:
        v.verdicts.append(("HUNT-KEY", "medium", "Provider API key present in file"))
    if not v.verdicts and instructions and ("model_api" in f or "evasion" in f):
        v.verdicts.append(("HUNT-PROMPT", "low", "Model-style instructions present"))
    return v
