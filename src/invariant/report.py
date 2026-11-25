"""Reports and the metrics the Invariant Defense Model asks you to track.

Detection rate on known samples is no longer the headline number. Track:
time to detect, time to contain, which invariants fired, and ATT&CK coverage.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from typing import Any

from invariant import LAYERS
from invariant.alerts import SEVERITY_ORDER, Alert
from invariant.attack import name as attack_name
from invariant.events import Event, iso


def metrics(alerts: list[Alert], events: list[Event], contained: dict[str, float]) -> dict[str, Any]:
    # Time to detect is measured from the first *evidential* event: the earliest event cited
    # by any alert on that host. In production add your pipeline's ingestion lag.
    first_event: dict[str, float] = {}
    for a in alerts:
        for e in a.events:
            first_event[a.host] = min(first_event.get(a.host, e.ts), e.ts)
    first_alert: dict[str, Alert] = {}
    for a in sorted(alerts, key=lambda x: x.ts):
        first_alert.setdefault(a.host, a)
    per_host = {}
    for host, a in first_alert.items():
        start = first_event.get(host, a.ts)
        row: dict[str, Any] = {
            "first_alert": a.rule_id,
            "time_to_detect_s": round(a.ts - start, 1),
        }
        if host in contained:
            row["time_to_contain_s"] = round(contained[host] - a.ts, 1)
        per_host[host] = row
    return {
        "alerts": len(alerts),
        "by_severity": dict(Counter(a.severity for a in alerts)),
        "by_layer": dict(sorted(Counter(a.layer for a in alerts).items())),
        "attack_techniques": sorted({t for a in alerts for t in a.attack}),
        "hosts": per_host,
    }


def text_report(
    alerts: list[Alert],
    events: list[Event],
    contained: dict[str, float] | None = None,
    claims: Iterable[dict[str, Any]] = (),
    containment_checks: Iterable[dict[str, Any]] = (),
    min_severity: str = "info",
    dry_run: bool = True,
) -> str:
    contained = contained or {}
    floor = SEVERITY_ORDER.get(min_severity, 0)
    shown = [a for a in alerts if SEVERITY_ORDER.get(a.severity, 0) >= floor]
    lines: list[str] = []
    lines.append("=" * 100)
    lines.append(
        f" INVARIANT DEFENSE REPORT   events={len(events)}   alerts={len(alerts)} (shown {len(shown)})"
    )
    lines.append("=" * 100)
    by_layer: dict[str, list[Alert]] = defaultdict(list)
    for a in shown:
        by_layer[a.layer].append(a)
    for layer in sorted(by_layer):
        lines.append("")
        lines.append(f"── {layer}  {LAYERS.get(layer, '')}")
        for a in by_layer[layer]:
            lines.append(f"  {iso(a.ts)}  {a.one_line()}")
            for k in (
                "process_chain",
                "provider",
                "destination",
                "path",
                "commands",
                "table",
                "subject",
                "rows_in_window",
            ):
                if a.evidence.get(k):
                    lines.append(f"{'':24}{k}: {a.evidence[k]}")
            for act in a.actions:
                state = (
                    "EXECUTED"
                    if act["executed"]
                    else ("pending" if act["adapter"] == "approval" else "dry-run")
                )
                lines.append(f"{'':24}↳ {act['step']:9} [{state}] {act['detail']}")
    m = metrics(alerts, events, contained)
    lines.append("")
    lines.append("── Metrics (stop citing known-sample detection rate; track these)")
    for host, row in m["hosts"].items():
        ttc = (
            f"  time-to-contain={row['time_to_contain_s']}s (simulated clock)"
            if "time_to_contain_s" in row
            else ""
        )
        lines.append(
            f"  {host:16} first={row['first_alert']:12} time-to-detect={row['time_to_detect_s']}s{ttc}"
        )
    lines.append(f"  by layer: {m['by_layer']}   by severity: {m['by_severity']}")
    lines.append("  ATT&CK: " + ", ".join(f"{t} {attack_name(t)}" for t in m["attack_techniques"]))
    claims = list(claims)
    if claims:
        lines.append("")
        lines.append("── Verify, don't trust: agent self-reports vs telemetry")
        for c in claims:
            lines.append(f'  [{c["host"]}] "{c["claim"]}" -> {c["verdict"]}')
    checks = list(containment_checks)
    if checks:
        lines.append("")
        if dry_run:
            lines.append(
                "── Containment (dry-run): outbound activity after the moment isolation would have fired"
            )
            lines.append(
                "   Each counted event is attacker activity that enforced, machine-speed containment would have stopped."
            )
        else:
            lines.append("── Containment verification")
        for c in checks:
            n = c["outbound_after_containment"]
            if dry_run:
                state = f"{n} outbound events would have been blocked" if n else "no later outbound activity"
            else:
                state = "HOLDING" if c["holding"] else f"LEAKING ({n} outbound events after containment)"
            lines.append(f"  {c['host']:16} containment at {iso(c['contained_at'])}: {state}")
    return "\n".join(lines)


def markdown_report(
    alerts: list[Alert], events: list[Event], contained: dict[str, float] | None = None
) -> str:
    m = metrics(alerts, events, contained or {})
    out = ["# Invariant Defense report", "", f"Events analyzed: {len(events)} · Alerts: {len(alerts)}", ""]
    out += ["| Time (UTC) | Severity | Layer | Rule | Host | Title |", "|---|---|---|---|---|---|"]
    for a in alerts:
        out.append(
            f"| {iso(a.ts)} | {a.severity} | {a.layer} | {a.rule_id} | {a.host} | {a.title.replace('|', '/')} |"
        )
    out += [
        "",
        "## Metrics",
        "",
        "| Host | First alert | Time to detect (s) | Time to contain (s) |",
        "|---|---|---|---|",
    ]
    for host, row in m["hosts"].items():
        out.append(
            f"| {host} | {row['first_alert']} | {row['time_to_detect_s']} | {row.get('time_to_contain_s', '—')} |"
        )
    out += ["", "## ATT&CK techniques", ""] + [f"- {t} {attack_name(t)}" for t in m["attack_techniques"]]
    return "\n".join(out) + "\n"


def json_report(
    alerts: list[Alert], events: list[Event], contained: dict[str, float] | None = None, **extra: Any
) -> str:
    return json.dumps(
        {
            "metrics": metrics(alerts, events, contained or {}),
            "alerts": [a.to_dict() for a in alerts],
            **extra,
        },
        indent=2,
        default=str,
    )
