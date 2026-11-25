"""Evaluate an AI-estate inventory against the exposure knowledge base.

The inventory (YAML) lists every internet-facing or internally reachable AI and
automation platform: orchestration (Langflow, Flowise, n8n, Dify), model servers
(Ollama, vLLM), and the stores they lean on (MinIO, Nacos, vector DBs). See
config/ai-estate.example.yaml.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

import yaml

from invariant.exposure import versions


@dataclass
class ExposureFinding:
    asset: str
    severity: str
    rule: str
    title: str
    fix: str = ""
    details: dict[str, Any] = field(default_factory=dict)


def load_estate(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _get(asset: dict[str, Any], dotted: str) -> Any:
    cur: Any = asset
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _cond(asset: dict[str, Any], c: dict[str, Any]) -> bool:
    val = _get(asset, c["key"])
    if "equals" in c:
        return val == c["equals"]
    if "equals_any" in c:
        return val in c["equals_any"]
    if "missing" in c:
        return (val is None) == bool(c["missing"])
    return False


def _days_since(v: Any, today: date) -> int | None:
    if v in (None, ""):
        return None
    d = v if isinstance(v, date) else datetime.fromisoformat(str(v)[:10]).date()
    if isinstance(d, datetime):
        d = d.date()
    return (today - d).days


def evaluate(
    estate: dict[str, Any],
    vulndb: dict[str, Any],
    kev: dict[str, dict[str, Any]] | None = None,
    patch_sla_days: int = 7,
    today: date | None = None,
) -> list[ExposureFinding]:
    today = today or date.today()
    out: list[ExposureFinding] = []
    for asset in estate.get("assets", []) or []:
        name = asset.get("name", "?")
        product = str(asset.get("product", "")).lower()
        version = str(asset.get("version", "") or "")
        facing = bool(asset.get("internet_facing"))

        for v in vulndb.get("vulnerabilities", []) or []:
            if v.get("product") != product or not version:
                continue
            vulnerable = False
            if v.get("fixed") and versions.lt(version, v["fixed"]):
                vulnerable = True
            if v.get("last_affected") and versions.le(version, v["last_affected"]):
                vulnerable = True
            if not vulnerable:
                continue
            in_kev = bool(v.get("kev"))
            kev_entry = (kev or {}).get(v["id"])
            if kev is not None:
                in_kev = kev_entry is not None
            sev = v.get("severity", "high")
            if in_kev and facing:
                sev = "critical"
            out.append(
                ExposureFinding(
                    name,
                    sev,
                    v["id"],
                    f"{v['title']} ({product} {version})",
                    f"Upgrade to {v['fixed']} or later."
                    if v.get("fixed")
                    else "Upgrade and rotate the default key.",
                    {
                        "kev": in_kev,
                        "kev_due": kev_entry.get("dueDate") if kev_entry else None,
                        "ransomware_use": kev_entry.get("knownRansomwareCampaignUse") if kev_entry else None,
                        "internet_facing": facing,
                        "note": v.get("note"),
                    },
                )
            )

        for m in vulndb.get("misconfigurations", []) or []:
            if m.get("product") not in ("*", product):
                continue
            if all(_cond(asset, c) for c in m.get("when", [])):
                sev = m.get("severity", "high")
                out.append(
                    ExposureFinding(
                        name, sev, m["id"], m["title"], m.get("fix", ""), {"internet_facing": facing}
                    )
                )

        age = _days_since(asset.get("last_patched"), today)
        if age is not None and age > patch_sla_days and facing:
            out.append(
                ExposureFinding(
                    name,
                    "medium",
                    "INV-PATCH-AGE",
                    f"Internet-facing AI platform last patched {age} days ago",
                    f"Patch internet-facing AI platforms within {patch_sla_days} days.",
                    {"days": age},
                )
            )
        if not asset.get("owner"):
            out.append(
                ExposureFinding(
                    name,
                    "medium",
                    "INV-NO-OWNER",
                    "Asset has no accountable owner",
                    "Assign an owner who receives patch and exposure alerts.",
                )
            )
    order = ["info", "low", "medium", "high", "critical"]
    out.sort(key=lambda f: order.index(f.severity), reverse=True)
    return out


def coverage(estate: dict[str, Any]) -> dict[str, Any]:
    """Governance metrics the article recommends tracking."""
    assets = estate.get("assets", []) or []
    procs = estate.get("expected_llm_processes", []) or []
    hosts = estate.get("hosts", {}) or {}
    total_hosts = int(hosts.get("total", 0) or 0)
    covered = int(hosts.get("with_egress_telemetry", 0) or 0)
    return {
        "ai_assets": len(assets),
        "internet_facing": sum(1 for a in assets if a.get("internet_facing")),
        "assets_with_owner": sum(1 for a in assets if a.get("owner")),
        "expected_llm_processes": len(procs),
        "egress_telemetry_coverage": round(covered / total_hosts, 3) if total_hosts else None,
        "credentials_inventoried": len(estate.get("credentials", []) or []),
    }
