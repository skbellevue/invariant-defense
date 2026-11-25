"""macOS Endpoint Security (via Apple's ``eslogger``) -> Event.

``eslogger`` ships with macOS 13+ and prints Endpoint Security messages as JSON
Lines. It must run as root, and the app that launches it (Terminal, iTerm, or
the LaunchDaemon itself) needs Full Disk Access::

    sudo eslogger exec create rename unlink close | invariant stream --format eslogger

Apple documents no formal schema: the JSON mirrors ``es_message_t`` from
EndpointSecurity.h and "is NOT API", so field layouts may change between macOS
releases (``schema_version`` is carried into ``fields`` for that reason). This
mapper is deliberately tolerant: it finds the event by the single key under
``event`` instead of trusting numeric ``event_type`` values, accepts file
objects or bare paths, and handles both shapes of ES destination unions
(``existing_file`` / ``new_path``).

Mapped events
  exec            -> process_start   (the new image, args, ppid, code signing)
  create          -> file_write
  close(modified) -> file_write      (preferred over 'write', which fires per syscall)
  write           -> file_write
  rename          -> file_rename
  unlink          -> file_delete

Endpoint Security has no network-connect events. Pair this collector with
``invariant stream --net-interval N`` (psutil sampling as root) or proxy / AI
gateway logs for the L2 egress layer.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Iterator
from typing import Any

from invariant.events import Event, parse_ts

# <kern/cs_blobs.h>
CS_VALID = 0x00000001
CS_ADHOC = 0x00000002


def _path(obj: Any) -> str | None:
    """ES file objects are {"path": ...}; tolerate bare strings."""
    if obj is None:
        return None
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        p = obj.get("path")
        if isinstance(p, str):
            return p
    return None


def _destination(ev: dict[str, Any]) -> str | None:
    """Resolve an ES destination union (create, rename) to a path."""
    dest = ev.get("destination")
    if isinstance(dest, dict):
        if "existing_file" in dest:
            return _path(dest["existing_file"])
        if "new_path" in dest:
            np = dest["new_path"] or {}
            d, name = _path(np.get("dir")), np.get("filename")
            if d and name:
                return os.path.join(d, str(name))
        # some releases flatten the union
        if "dir" in dest and "filename" in dest:
            d = _path(dest.get("dir"))
            if d:
                return os.path.join(d, str(dest["filename"]))
        if "path" in dest:
            return _path(dest)
    for key in ("existing_file", "new_path"):  # union fields hoisted next to destination_type
        if key in ev:
            return _destination({"destination": {key: ev[key]}})
    return None


def signed_state(proc: dict[str, Any]) -> bool | None:
    """True for platform binaries and validly signed non-ad-hoc code, False for
    invalid or ad-hoc signatures (typical of dropped malware), None if unknown."""
    if not isinstance(proc, dict):
        return None
    if proc.get("is_platform_binary"):
        return True
    flags = proc.get("codesigning_flags")
    if flags is None:
        return None
    try:
        flags = int(flags)
    except (TypeError, ValueError):
        return None
    if not flags & CS_VALID or flags & CS_ADHOC:
        return False
    return bool(proc.get("team_id") or proc.get("signing_id")) or None


def _pid(proc: dict[str, Any]) -> int | None:
    tok = proc.get("audit_token") or {}
    v = tok.get("pid", proc.get("pid"))
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _ppid(proc: dict[str, Any]) -> int | None:
    v = proc.get("ppid")
    if v is None:
        v = (proc.get("parent_audit_token") or {}).get("pid")
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _user(proc: dict[str, Any]) -> str | None:
    tok = proc.get("audit_token") or {}
    euid = tok.get("euid")
    return f"uid:{euid}" if euid is not None else None


def _args(exec_ev: dict[str, Any]) -> list[str]:
    args = exec_ev.get("args")
    if isinstance(args, list):
        return [str(a) for a in args]
    if isinstance(args, str):
        return [args]
    return []


def map_record(rec: dict[str, Any], host: str = "localhost") -> Event | None:
    event = rec.get("event")
    if not isinstance(event, dict) or not event:
        return None
    name, ev = next(iter(event.items()))
    if not isinstance(ev, dict):
        return None
    proc = rec.get("process") or {}
    ts = parse_ts(rec.get("time")) if rec.get("time") else parse_ts(None)
    image = _path(proc.get("executable"))
    common: dict[str, Any] = dict(
        ts=ts,
        host=host,
        user=_user(proc),
        pid=_pid(proc),
        image=image,
        signed=signed_state(proc),
    )
    meta = {"source": "eslogger", "schema_version": rec.get("schema_version"), "es_event": name}
    if proc.get("team_id"):
        meta["team_id"] = proc["team_id"]
    if proc.get("signing_id"):
        meta["signing_id"] = proc["signing_id"]

    if name == "exec":
        target = ev.get("target") or {}
        args = _args(ev)
        new_image = _path(target.get("executable")) or image
        cwd = _path(ev.get("cwd"))
        if cwd:
            meta["cwd"] = cwd
        return Event(
            "process_start",
            ts=ts,
            host=host,
            user=_user(target) or common["user"],
            pid=_pid(target) or common["pid"],
            ppid=_ppid(target) if _ppid(target) is not None else _ppid(proc),
            image=new_image,
            cmdline=" ".join(args) if args else new_image,
            parent_image=image if image != new_image else None,
            signed=signed_state(target),
            fields=meta,
        )
    if name == "create":
        path = _destination(ev)
        return Event("file_write", path=path, fields={**meta, "created": True}, **common) if path else None
    if name == "close":
        if not ev.get("modified"):
            return None
        path = _path(ev.get("target"))
        return Event("file_write", path=path, fields=meta, **common) if path else None
    if name == "write":
        path = _path(ev.get("target"))
        return Event("file_write", path=path, fields=meta, **common) if path else None
    if name == "rename":
        src, dst = _path(ev.get("source")), _destination(ev)
        return Event("file_rename", path=src, target_path=dst, fields=meta, **common) if src else None
    if name == "unlink":
        path = _path(ev.get("target"))
        return Event("file_delete", path=path, fields=meta, **common) if path else None
    return None


def iter_lines(lines: Iterable[str], host: str = "localhost") -> Iterator[Event]:
    for line in lines:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue  # eslogger may emit a partial line when interrupted
        ev = map_record(rec, host)
        if ev is not None:
            yield ev


def read_eslogger(path: str, host: str | None = None) -> Iterator[Event]:
    import socket

    with open(path, encoding="utf-8", errors="replace") as fh:
        yield from iter_lines(fh, host or socket.gethostname())
