"""Audit AI-assistant configuration files that a repository can ship.

Coding assistants read project-level settings. A malicious repository can use
them to run commands on open (hooks, MCP servers) or to redirect the
assistant's API traffic, and its key, to an attacker (Check Point's 2026
research on Claude Code project files: CVE-2025-59536, CVE-2026-21852; both
fixed by Anthropic). The same class of risk applies to every assistant that
honors repo-level config, so this module audits several formats.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from invariant.util import domain_matches

CONFIG_GLOBS = [
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".gemini/settings.json",
    ".windsurf/mcp.json",
    "claude_desktop_config.json",
]

BASE_URL_VARS = re.compile(
    r"^(ANTHROPIC|OPENAI|AZURE_OPENAI|GOOGLE_GEMINI|GEMINI|MISTRAL|GROQ)_(BASE_URL|API_BASE|ENDPOINT)$", re.I
)
NETWORK_OR_DECODE = re.compile(
    r"\b(curl|wget|nc|ncat|socat|invoke-webrequest|iwr|irm|invoke-restmethod|base64|certutil)\b|https?://|\|\s*(ba|z)?sh\b",
    re.I,
)
LITERAL_KEY = re.compile(r"^(sk-|hf_|AIza|gsk_|xai-|r8_|pplx-)[A-Za-z0-9_\-]{16,}")
LOCAL = ("localhost", "127.0.0.1", "::1", "0.0.0.0")


@dataclass
class ConfigFinding:
    file: str
    severity: str
    rule: str
    message: str


def _load_jsonc(text: str) -> Any:
    # tolerate // comments and trailing commas often found in editor configs
    text = re.sub(r"(?m)^\s*//.*$", "", text)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return json.loads(text)


def _walk_hooks(obj: Any) -> list[str]:
    cmds: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "command" and isinstance(v, str):
                cmds.append(v)
            else:
                cmds.extend(_walk_hooks(v))
    elif isinstance(obj, list):
        for v in obj:
            cmds.extend(_walk_hooks(v))
    return cmds


def audit_config(path: str, provider_domains: list[str]) -> list[ConfigFinding]:
    p = Path(path)
    out: list[ConfigFinding] = []
    try:
        cfg = _load_jsonc(p.read_text(encoding="utf-8", errors="replace"))
    except (ValueError, OSError) as exc:
        return [ConfigFinding(path, "info", "AICFG-PARSE", f"could not parse: {exc}")]
    if not isinstance(cfg, dict):
        return out
    project_level = (
        ".claude" in p.parts or p.name in (".mcp.json",) or ".cursor" in p.parts or ".vscode" in p.parts
    )

    # hooks
    for cmd in _walk_hooks(cfg.get("hooks", {})):
        if NETWORK_OR_DECODE.search(cmd):
            out.append(
                ConfigFinding(
                    path, "critical", "AICFG-HOOK-NET", f"hook runs a network/decoder command: {cmd[:120]}"
                )
            )
        elif project_level:
            out.append(
                ConfigFinding(path, "medium", "AICFG-HOOK", f"repository-defined hook (review): {cmd[:120]}")
            )

    # environment overrides
    env = cfg.get("env", {}) or {}
    if isinstance(env, dict):
        for k, v in env.items():
            sv = str(v)
            if BASE_URL_VARS.match(k):
                host = urlparse(sv).hostname or sv
                if not (host in LOCAL or domain_matches(host, provider_domains)):
                    out.append(
                        ConfigFinding(
                            path,
                            "critical",
                            "AICFG-BASEURL",
                            f"{k} redirects model traffic (and the API key) to {host}",
                        )
                    )
            if LITERAL_KEY.match(sv):
                out.append(
                    ConfigFinding(path, "high", "AICFG-LITERAL-KEY", f"literal credential in env var {k}")
                )

    # permissions
    perms = cfg.get("permissions", {}) or {}
    if isinstance(perms, dict):
        if str(perms.get("defaultMode", "")).lower() in ("bypasspermissions",):
            out.append(
                ConfigFinding(
                    path, "high", "AICFG-BYPASS", "defaultMode bypassPermissions disables approvals"
                )
            )
        for rule in perms.get("allow", []) or []:
            if str(rule).strip() in ("Bash", "Bash(*)", "*", "Bash(:*)"):
                out.append(ConfigFinding(path, "high", "AICFG-ALLOW-ALL", f"blanket allow rule: {rule}"))
    if cfg.get("enableAllProjectMcpServers") is True:
        out.append(
            ConfigFinding(
                path,
                "high",
                "AICFG-MCP-AUTOAPPROVE",
                "enableAllProjectMcpServers auto-approves every MCP server the repo defines",
            )
        )

    # MCP servers
    servers = cfg.get("mcpServers") or cfg.get("servers") or {}
    if isinstance(servers, dict):
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            command = " ".join([str(spec.get("command", ""))] + [str(a) for a in spec.get("args", []) or []])
            if NETWORK_OR_DECODE.search(command) and not spec.get("url"):
                out.append(
                    ConfigFinding(
                        path,
                        "critical",
                        "AICFG-MCP-NET",
                        f"MCP server '{name}' launches a network/decoder command: {command[:120]}",
                    )
                )
            if re.search(r"\b(npx|uvx|pipx|bunx)\b", command):
                pkgs = [a for a in spec.get("args", []) or [] if not str(a).startswith("-")]
                if pkgs and not re.search(r"@\d|==\d", str(pkgs[0])):
                    out.append(
                        ConfigFinding(
                            path,
                            "medium",
                            "AICFG-MCP-UNPINNED",
                            f"MCP server '{name}' runs unpinned package {pkgs[0]}",
                        )
                    )
            url = spec.get("url")
            if url:
                host = urlparse(str(url)).hostname or ""
                if host not in LOCAL:
                    out.append(
                        ConfigFinding(
                            path,
                            "medium",
                            "AICFG-MCP-REMOTE",
                            f"MCP server '{name}' is remote: {host} (confirm it is sanctioned)",
                        )
                    )
            for k, v in (spec.get("env") or {}).items():
                if LITERAL_KEY.match(str(v)):
                    out.append(
                        ConfigFinding(
                            path,
                            "high",
                            "AICFG-LITERAL-KEY",
                            f"literal credential in MCP server '{name}' env {k}",
                        )
                    )
    return out


def find_configs(root: str) -> list[str]:
    base = Path(root)
    found: list[str] = []
    if base.is_file():
        return [str(base)] if any(str(base).replace("\\", "/").endswith(g) for g in CONFIG_GLOBS) else []
    for g in CONFIG_GLOBS:
        found.extend(str(p) for p in base.rglob(g) if ".git" not in p.parts and "node_modules" not in p.parts)
    return sorted(set(found))
