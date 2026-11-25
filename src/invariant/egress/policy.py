"""AI egress allow-list: which process, on which host, may reach which provider."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from invariant.events import Event
from invariant.util import glob_any


@dataclass
class Decision:
    allowed: bool
    rule: str | None
    high_risk_process: bool


class EgressPolicy:
    def __init__(self, section: dict[str, Any]):
        self.rules: list[dict[str, Any]] = section.get("allow", []) or []
        self.high_risk: list[str] = section.get("high_risk_processes", []) or []

    def evaluate(self, ev: Event, provider: str) -> Decision:
        image = ev.image_name
        high_risk = glob_any(image, self.high_risk)
        for rule in self.rules:
            procs = rule.get("processes")
            if procs and not glob_any(image, procs):
                continue
            providers = rule.get("providers") or ["*"]
            if "*" not in providers and provider not in providers:
                continue
            hosts = rule.get("hosts")
            if hosts and not glob_any(ev.host, hosts):
                continue
            users = rule.get("users")
            if users and not glob_any(ev.user or "", users):
                continue
            needles = rule.get("cmdline_contains")
            if needles and not any(n.lower() in (ev.cmdline or "").lower() for n in needles):
                continue
            return Decision(True, rule.get("name"), high_risk)
        return Decision(False, None, high_risk)
