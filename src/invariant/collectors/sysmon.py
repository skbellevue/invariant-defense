"""Microsoft Sysmon -> Event.

Accepts JSON lines in either of two common shapes:

* flat:      {"EventID": 1, "Computer": "WS1", "UtcTime": "...", "Image": "...", ...}
* winlogbeat {"@timestamp": "...", "winlog": {"event_id": 1, "computer_name": "WS1",
              "event_data": {"Image": "...", ...}}}

Mapped event IDs: 1 process create, 3 network connect, 11 file create,
22 DNS query, 23/26 file delete, 29 executable file detected.
Recommended Sysmon config: see deploy/sysmon-invariant.xml.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from invariant.events import Event, parse_ts


def _hashes(s: str | None) -> str | None:
    if not s:
        return None
    for part in str(s).split(","):
        k, _, v = part.partition("=")
        if k.strip().upper() == "SHA256":
            return v.strip().lower()
    return None


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def map_record(rec: dict[str, Any]) -> Event | None:
    if "winlog" in rec:
        w = rec["winlog"]
        eid = _int(w.get("event_id"))
        data = dict(w.get("event_data") or {})
        host = w.get("computer_name") or rec.get("host", {}).get("name", "unknown")
        ts = rec.get("@timestamp") or data.get("UtcTime")
    else:
        eid = _int(rec.get("EventID") or rec.get("EventId") or rec.get("event_id"))
        data = rec.get("EventData") or rec
        host = rec.get("Computer") or rec.get("Hostname") or "unknown"
        ts = data.get("UtcTime") or rec.get("TimeCreated")
    common = dict(
        ts=parse_ts(ts),
        host=str(host),
        user=data.get("User"),
        pid=_int(data.get("ProcessId")),
        image=data.get("Image"),
    )
    if eid == 1:
        return Event(
            "process_start",
            ppid=_int(data.get("ParentProcessId")),
            cmdline=data.get("CommandLine"),
            parent_image=data.get("ParentImage"),
            sha256=_hashes(data.get("Hashes")),
            **common,
        )
    if eid == 3:
        if str(data.get("Initiated", "true")).lower() not in ("true", "1"):
            return None
        return Event(
            "network_connect",
            dst_host=data.get("DestinationHostname") or None,
            dst_ip=data.get("DestinationIp"),
            dst_port=_int(data.get("DestinationPort")),
            **common,
        )
    if eid == 11:
        return Event("file_write", path=data.get("TargetFilename"), **common)
    if eid == 22:
        return Event("dns_query", dst_host=data.get("QueryName"), **common)
    if eid in (23, 26):
        return Event("file_delete", path=data.get("TargetFilename"), **common)
    if eid == 29:
        return Event(
            "file_write", path=data.get("TargetFilename"), sha256=_hashes(data.get("Hashes")), **common
        )
    return None


def read_sysmon(path: str) -> Iterator[Event]:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            ev = map_record(json.loads(line))
            if ev:
                yield ev
