"""macOS Network Extension (Invariant network filter) -> Event.

The content-filter system extension in ``macos/InvariantNetFilter`` attributes every
outbound socket flow to a process (pid, ppid, executable, code signature) and emits one
``network_connect`` record per flow, already in invariant's normalized schema. It writes
the records two ways, and this module reads both:

1. Unified log, read with ``log stream``::

       sudo log stream --style ndjson --level info \\
         --predicate 'subsystem == "com.skbellevue.invariant.netfilter"' \\
         | invariant stream --format nefilter

   Each ndjson object carries the record in ``eventMessage`` after the ``INVFLOW `` prefix.
   ``invariant stream --nefilter-log`` runs that ``log stream`` command for you.

2. JSONL file in the extension's app-group container (rotated), e.g.::

       sudo invariant stream --follow "nefilter:/private/var/root/Library/Group Containers/<TEAMID>.com.skbellevue.invariant/flows.jsonl"

This closes the gap Endpoint Security leaves open (it has no network events): together
with ``eslogger`` the L2 egress layer and the L3 query-then-execute join work on macOS.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from typing import Any

from invariant.events import Event

SUBSYSTEM = "com.skbellevue.invariant.netfilter"
LOG_PREFIX = "INVFLOW "
LOG_STREAM_CMD = [
    "/usr/bin/log",
    "stream",
    "--style",
    "ndjson",
    "--level",
    "info",
    "--predicate",
    f'subsystem == "{SUBSYSTEM}"',
]


def _record_from_log(obj: dict[str, Any]) -> dict[str, Any] | None:
    msg = obj.get("eventMessage")
    if not isinstance(msg, str):
        return None
    i = msg.find(LOG_PREFIX)
    if i < 0:
        return None
    try:
        rec = json.loads(msg[i + len(LOG_PREFIX) :])
    except ValueError:
        return None
    return rec if isinstance(rec, dict) else None


def map_line(line: str) -> Event | None:
    """Map one line: a direct flow record, or a `log stream --style ndjson` object."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    rec = obj if obj.get("kind") == "network_connect" else _record_from_log(obj)
    if not rec or rec.get("kind") != "network_connect":
        return None
    try:
        ev = Event.from_dict(rec)
    except (ValueError, TypeError):
        return None
    ev.fields.setdefault("source", "nefilter")
    return ev


def iter_lines(lines: Iterable[str]) -> Iterator[Event]:
    for line in lines:
        ev = map_line(line)
        if ev is not None:
            yield ev


def read_nefilter(path: str) -> Iterator[Event]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        yield from iter_lines(fh)


def export_config(catalog: dict[str, Any], mode: str = "catalog") -> dict[str, Any]:
    """vendorConfiguration["config"] for the extension (FilterConfig in Swift).

    mode "catalog" reports only flows to model providers (low volume); "all" reports
    every outbound flow (needed for the generic beacon detector and for inventorying
    shadow AI that is not yet in the catalog)."""
    domains: set[str] = set()
    ports: set[int] = set()
    for spec in (catalog.get("providers") or {}).values():
        domains.update(spec.get("domains") or [])
        ports.update(int(p) for p in spec.get("ports") or [])
    return {
        "mode": mode,
        "domains": sorted(domains),
        "ports": sorted(ports),
        "write_file": True,
        "unified_log": True,
        "max_file_bytes": 50 * 1024 * 1024,
    }
