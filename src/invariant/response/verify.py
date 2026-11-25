"""Verify, don't trust.

Two checks:

* :func:`verify_claims` — an AI agent's self-narration ("exfiltrated data to X",
  "backdoor created") is a lead, not a fact. JADEPUFFER's comments claimed an
  exfiltration the investigators found no evidence of. We check each claim
  against telemetry.
* :func:`verify_containment` — after isolation, did the host actually go quiet?
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from invariant.events import Event

OUTBOUND = ("network_connect", "http_request", "dns_query")


def verify_claims(events: Iterable[Event]) -> list[dict[str, Any]]:
    evs = sorted(events, key=lambda e: e.ts)
    results: list[dict[str, Any]] = []
    for c in (e for e in evs if e.kind == "agent_claim"):
        claim = str(c.fields.get("claim", ""))
        target = str(c.fields.get("target", "") or "").lower()
        ctype = str(c.fields.get("type", "")).lower()
        support: list[Event] = []
        if ctype in ("exfiltration", "upload", "c2") and target:
            support = [
                e
                for e in evs
                if e.kind in OUTBOUND
                and e.host == c.host
                and target in f"{e.dst_host or ''} {e.dst_ip or ''} {e.url or ''}".lower()
            ]
            # exfiltration needs volume, not just a connection
            if ctype == "exfiltration":
                support = [e for e in support if int(e.fields.get("bytes_out", 0) or 0) > 1024]
        elif ctype in ("account", "backdoor") and target:
            support = [
                e
                for e in evs
                if e.kind == "account_change" and str(e.fields.get("target_user", "")).lower() == target
            ]
        elif ctype in ("encryption", "impact"):
            support = [
                e
                for e in evs
                if e.kind in ("sql", "file_rename", "file_write")
                and e.host == c.host
                and (target in str(e.fields.get("table", "")).lower() or target in (e.path or "").lower())
            ]
        results.append(
            {
                "host": c.host,
                "claim": claim,
                "type": ctype,
                "target": target,
                "verified": bool(support),
                "supporting_events": len(support),
                "verdict": "SUPPORTED by telemetry"
                if support
                else "UNVERIFIED: no telemetry supports this claim",
            }
        )
    return results


def verify_containment(
    events: Iterable[Event], host: str, contained_at: float, grace_s: float = 30
) -> dict[str, Any]:
    leaks = [e for e in events if e.host == host and e.kind in OUTBOUND and e.ts > contained_at + grace_s]
    return {
        "host": host,
        "contained_at": contained_at,
        "outbound_after_containment": len(leaks),
        "holding": not leaks,
        "first_leak": leaks[0].to_dict() if leaks else None,
    }
