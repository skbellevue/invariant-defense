"""Alert model shared by every layer."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

from invariant.events import Event, iso

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def sev_at_least(severity: str, floor: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(floor, 0)


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    layer: str  # L1..L5
    host: str
    ts: float
    description: str = ""
    attack: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    events: list[Event] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        key = json.dumps(
            [self.rule_id, self.host, self.evidence.get("dedupe_key", "")], sort_keys=True, default=str
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["time"] = iso(self.ts)
        d["fingerprint"] = self.fingerprint
        d["events"] = [e.to_dict() for e in self.events]
        return d

    def one_line(self) -> str:
        return f"[{self.severity.upper():8}] {self.layer} {self.rule_id:32} {self.host:16} {self.title}"
