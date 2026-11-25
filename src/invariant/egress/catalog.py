"""Match network destinations against the LLM endpoint catalog."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from invariant.events import Event
from invariant.util import domain_matches


@dataclass(frozen=True)
class Match:
    provider: str
    category: str
    reason: str  # domain | pattern | port | path
    confidence: str  # high | medium | low


class EndpointCatalog:
    def __init__(self, catalog: dict[str, Any]):
        self.providers: dict[str, dict[str, Any]] = catalog.get("providers", {}) or {}
        self._patterns = {
            name: [re.compile(p, re.I) for p in (spec.get("patterns") or [])]
            for name, spec in self.providers.items()
        }

    def match_host(self, host: str | None) -> Match | None:
        if not host:
            return None
        for name, spec in self.providers.items():
            if domain_matches(host, spec.get("domains") or []):
                return Match(name, spec.get("category", "unknown"), "domain", "high")
            for rx in self._patterns[name]:
                if rx.search(host.lower()):
                    return Match(name, spec.get("category", "unknown"), "pattern", "high")
        return None

    def match_port(self, port: int | None) -> Match | None:
        if port is None:
            return None
        for name, spec in self.providers.items():
            if port in (spec.get("ports") or []):
                return Match(name, spec.get("category", "self_hosted"), "port", "medium")
        return None

    def match_path(self, url: str | None) -> Match | None:
        if not url:
            return None
        path = urlparse(url).path if "://" in url else url
        for name, spec in self.providers.items():
            for p in spec.get("paths") or []:
                if path.rstrip("/").endswith(p.rstrip("/")):
                    return Match(name, spec.get("category", "self_hosted"), "path", "medium")
        return None

    def match_event(self, ev: Event) -> Match | None:
        if ev.kind not in ("network_connect", "dns_query", "http_request"):
            return None
        host_match = self.match_host(ev.dst_host)
        if host_match:
            return host_match
        if ev.kind == "http_request":
            m = self.match_path(ev.url)
            if m:
                return m
            if ev.url and "://" in ev.url:
                hm = self.match_host(urlparse(ev.url).hostname)
                if hm:
                    return hm
        if ev.kind == "network_connect":
            return self.match_port(ev.dst_port)
        return None

    def all_domains(self) -> list[str]:
        out: list[str] = []
        for spec in self.providers.values():
            out.extend(spec.get("domains") or [])
        return sorted(set(out))
