"""Normalized telemetry schema.

Every collector (Sysmon, osquery, EDR export, gateway logs, database audit
logs, the live psutil poller) maps its native records onto :class:`Event`.
Detectors only ever see this schema, which is what keeps them portable.

Event kinds
-----------
process_start     a process was created (pid, ppid, image, cmdline, parent_image)
network_connect   outbound connection (dst_host, dst_ip, dst_port)
dns_query         name resolution (dst_host)
http_request      L7 record from a proxy / AI gateway (dst_host, url, user_agent, fields.api_key_fp)
file_write        file created or modified (path, sha256, entropy, size)
file_rename       file renamed (path -> target_path)
file_delete       file deleted (path)
auth              authentication / token use (user, fields.token, fields.token_id, fields.device_id, src_ip)
account_change    account created / role changed (user, fields.role, fields.target_user)
sql               database statement from an audit log (fields.statement, fields.rows, fields.session)
agent_claim       a statement an AI agent made about its own actions (fields.claim, fields.target)
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

KINDS = {
    "process_start",
    "network_connect",
    "dns_query",
    "http_request",
    "file_write",
    "file_rename",
    "file_delete",
    "auth",
    "account_change",
    "sql",
    "agent_claim",
}


def parse_ts(value: Any) -> float:
    """Accept epoch seconds, epoch millis or ISO-8601 strings; return epoch seconds."""
    if value is None:
        return time.time()
    if isinstance(value, (int, float)):
        v = float(value)
        return v / 1000.0 if v > 10_000_000_000 else v
    s = str(value).strip()
    try:
        return parse_ts(float(s))
    except ValueError:
        pass
    s = s.replace("Z", "+00:00")
    if " " in s and "T" not in s:
        s = s.replace(" ", "T", 1)
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Event:
    kind: str
    ts: float = field(default_factory=time.time)
    host: str = "unknown"
    user: str | None = None
    pid: int | None = None
    ppid: int | None = None
    image: str | None = None
    cmdline: str | None = None
    parent_image: str | None = None
    signed: bool | None = None
    dst_host: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    src_ip: str | None = None
    url: str | None = None
    user_agent: str | None = None
    path: str | None = None
    target_path: str | None = None
    sha256: str | None = None
    entropy: float | None = None
    size: int | None = None
    fields: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ helpers
    @property
    def image_name(self) -> str:
        """Lower-case basename of the process image, platform independent."""
        if not self.image:
            return ""
        return self.image.replace("\\", "/").rsplit("/", 1)[-1].lower()

    @property
    def parent_name(self) -> str:
        if not self.parent_image:
            return ""
        return self.parent_image.replace("\\", "/").rsplit("/", 1)[-1].lower()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v not in (None, {}, "")}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Event:
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        kwargs: dict[str, Any] = {}
        extra: dict[str, Any] = dict(d.get("fields") or {})
        for k, v in d.items():
            if k == "fields":
                continue
            if k in known:
                kwargs[k] = v
            else:
                extra[k] = v
        kind = kwargs.get("kind")
        if kind not in KINDS:
            raise ValueError(f"unknown event kind: {kind!r}")
        kwargs["ts"] = parse_ts(kwargs.get("ts"))
        for int_field in ("pid", "ppid", "dst_port", "size"):
            if kwargs.get(int_field) is not None:
                kwargs[int_field] = int(kwargs[int_field])
        if kwargs.get("entropy") is not None:
            kwargs["entropy"] = float(kwargs["entropy"])
        kwargs["fields"] = extra
        return cls(**kwargs)


def read_jsonl(path: str | Path) -> Iterator[Event]:
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                yield Event.from_dict(json.loads(line))
            except (ValueError, TypeError) as exc:
                raise ValueError(f"{path}:{lineno}: {exc}") from exc


def write_jsonl(events: Iterable[Event], path: str | Path) -> int:
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev.to_dict(), sort_keys=True) + "\n")
            n += 1
    return n
