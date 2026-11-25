"""Opt-in, read-only fingerprinting of AI platforms YOU OWN.

Only unauthenticated GET requests to version/health endpoints are made; no
credentials are tried and no exploit payloads are sent. Use it to verify that
the inventory matches reality (version drift, an Ollama API that answers from
the network). The CLI refuses to run it without --i-own-these-targets.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

PROBES: dict[str, list[tuple[str, str]]] = {
    # product: [(path, json key holding the version or "" for reachability only)]
    "langflow": [("/api/v1/version", "version")],
    "ollama": [("/api/version", "version")],
    "nacos": [("/nacos/v1/console/server/state", "version")],
    "minio": [("/minio/health/live", "")],
    "n8n": [("/healthz", "")],
    "flowise": [("/api/v1/ping", "")],
}


@dataclass
class ProbeResult:
    asset: str
    url: str
    reachable: bool
    status: int | None = None
    version: str | None = None
    error: str | None = None


def probe(asset: dict[str, Any], timeout: float = 5.0, verify_tls: bool = True) -> list[ProbeResult]:
    base = str(asset.get("url", "")).rstrip("/")
    product = str(asset.get("product", "")).lower()
    out: list[ProbeResult] = []
    if not base or product not in PROBES:
        return out
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    for path, key in PROBES[product]:
        url = base + path
        req = urllib.request.Request(url, headers={"User-Agent": "invariant-defense-probe/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
                body = resp.read(65536)
                ver = None
                if key:
                    try:
                        ver = str(json.loads(body).get(key))
                    except (ValueError, AttributeError):
                        ver = None
                out.append(ProbeResult(asset.get("name", "?"), url, True, resp.status, ver))
        except urllib.error.HTTPError as exc:
            out.append(ProbeResult(asset.get("name", "?"), url, True, exc.code, error=str(exc)))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            out.append(ProbeResult(asset.get("name", "?"), url, False, error=str(exc)))
    return out
