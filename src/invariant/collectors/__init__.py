"""Collectors map native telemetry onto :class:`invariant.events.Event`."""

from __future__ import annotations

from collections.abc import Iterator

from invariant.events import Event, read_jsonl


def load(path: str, fmt: str = "jsonl") -> Iterator[Event]:
    if fmt == "jsonl":
        return read_jsonl(path)
    if fmt == "sysmon":
        from invariant.collectors.sysmon import read_sysmon

        return read_sysmon(path)
    if fmt == "eslogger":
        from invariant.collectors.eslogger import read_eslogger

        return read_eslogger(path)
    if fmt == "nefilter":
        from invariant.collectors.nefilter import read_nefilter

        return read_nefilter(path)
    raise ValueError(f"unknown format {fmt!r} (expected jsonl, sysmon, eslogger or nefilter)")


FORMATS = ("jsonl", "sysmon", "eslogger", "nefilter")


def line_mapper(fmt: str, host: str | None = None):
    """Return a function mapping one raw text line to an Event (or None), for streaming."""
    import json
    import socket

    host = host or socket.gethostname()
    if fmt == "jsonl":

        def _m(line: str):
            line = line.strip()
            return Event.from_dict(json.loads(line)) if line and not line.startswith("#") else None

        return _m
    if fmt == "sysmon":
        from invariant.collectors.sysmon import map_record as sysmon_map

        return lambda line: sysmon_map(json.loads(line)) if line.strip() else None
    if fmt == "eslogger":
        from invariant.collectors.eslogger import map_record as es_map

        def _e(line: str):
            line = line.strip()
            if not line.startswith("{"):
                return None
            try:
                return es_map(json.loads(line), host)
            except ValueError:
                return None

        return _e
    if fmt == "nefilter":
        from invariant.collectors.nefilter import map_line

        return map_line
    raise ValueError(f"unknown format {fmt!r}")
