"""Static hunting for the model dependency: embedded keys, prompts and risky AI-assistant configs.

LLM-enabled malware generates its behavior at runtime, but it must carry what it
needs to reach the model: an API key, an endpoint, and a prompt. Those are stable
artifacts and therefore huntable, which is the one place where "signature-like"
detection still works against AI malware.
"""
