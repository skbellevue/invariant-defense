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
    raise ValueError(f"unknown format {fmt!r} (expected jsonl or sysmon)")
