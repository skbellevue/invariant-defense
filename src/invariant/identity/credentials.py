"""Credential inventory audit: short-lived, owned, bound, least-agency.

Reads the ``credentials`` list of an AI-estate file (see config/ai-estate.example.yaml).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

ADMIN_SCOPES = ("admin", "owner", "*", "write:all", "iam:*", "org:admin", "full_access")


@dataclass
class CredFinding:
    credential: str
    severity: str
    rule: str
    message: str


def _as_date(v: Any) -> date | None:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, date):
        return v
    return datetime.fromisoformat(str(v)[:10]).date()


def audit_credentials(
    creds: list[dict[str, Any]], max_age_days: int = 90, today: date | None = None
) -> list[CredFinding]:
    today = today or date.today()
    out: list[CredFinding] = []
    for c in creds or []:
        name = c.get("name", "?")
        rotated = _as_date(c.get("rotated")) or _as_date(c.get("created"))
        expires = _as_date(c.get("expires"))
        scopes = [str(s).lower() for s in c.get("scopes", []) or []]
        if c.get("default"):
            out.append(
                CredFinding(name, "critical", "INV-CRED-DEFAULT", "vendor default credential still in place")
            )
        if not expires and c.get("kind") in ("api_key", "token", "service_account", "access_key", None):
            out.append(CredFinding(name, "medium", "INV-CRED-NOEXPIRY", "static credential with no expiry"))
        if expires and expires < today:
            out.append(
                CredFinding(
                    name, "low", "INV-CRED-EXPIRED", "expired credential still inventoried (remove it)"
                )
            )
        if rotated:
            age = (today - rotated).days
            if age > max_age_days:
                out.append(
                    CredFinding(
                        name, "high", "INV-CRED-AGE", f"not rotated for {age} days (policy {max_age_days})"
                    )
                )
        if c.get("used_by_agent") and any(s.startswith(ADMIN_SCOPES) or s in ADMIN_SCOPES for s in scopes):
            out.append(
                CredFinding(
                    name,
                    "high",
                    "INV-CRED-AGENCY",
                    "AI agent identity holds admin scopes: violates least agency",
                )
            )
        if not c.get("owner"):
            out.append(CredFinding(name, "medium", "INV-CRED-OWNER", "no accountable owner"))
        if c.get("kind") in ("api_key", "token") and not c.get("bound_to"):
            out.append(
                CredFinding(name, "low", "INV-CRED-UNBOUND", "not bound to a workload, device or IP range")
            )
        if c.get("provider") and not (c.get("revocation") or {}).get("runbook"):
            out.append(
                CredFinding(
                    name,
                    "low",
                    "INV-CRED-REVOKE",
                    f"no pre-agreed revocation runbook with {c.get('provider')}",
                )
            )
    return out
