"""L5 detectors: damage in progress.

INV-L5-001  a canary file was modified, renamed or deleted
INV-L5-002  destructive rate: mass rename / delete / high-entropy rewrite by one process
INV-L5-003  destructive DDL (DROP / TRUNCATE) on a database
INV-L5-004  mass UPDATE/DELETE on a protected table (e.g. encrypting Nacos config_info)
"""

from __future__ import annotations

import os
import re
from collections import defaultdict, deque

from invariant.alerts import Alert
from invariant.config import Config
from invariant.engine import Context, Detector
from invariant.events import Event
from invariant.util import norm_path, squash


class CanaryDetector(Detector):
    layer = "L5"
    name = "canary"

    def __init__(self, config: Config, canary_paths: list[str] | None = None):
        paths = list(canary_paths or [])
        manifest = config.get("impact.canary_manifest")
        if manifest and os.path.exists(manifest):
            from invariant.impact.canary import load_manifest

            paths += [r.path for r in load_manifest(manifest)]
        self.paths = {norm_path(p) for p in paths}
        names = config.get("impact.canary_names") or []
        self.names = {n.lower() for n in names}

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        if ev.kind not in ("file_write", "file_rename", "file_delete"):
            return []
        p = norm_path(ev.path)
        if p not in self.paths and p.rsplit("/", 1)[-1] not in self.names:
            return []
        return [
            Alert(
                "INV-L5-001",
                f"Canary file {ev.kind.split('_')[1]}d by '{ev.image_name or '?'}'",
                "critical",
                "L5",
                ev.host,
                ev.ts,
                "No legitimate process touches a canary. Treat as ransomware/wiper activity: contain the host now.",
                ["T1486", "T1485"],
                {
                    "path": ev.path,
                    "target_path": ev.target_path,
                    "process": ev.image,
                    "pid": ev.pid,
                    "dedupe_key": f"{ev.pid}",
                },
                [ev],
            )
        ]


class DestructiveRateDetector(Detector):
    layer = "L5"
    name = "destructive-rate"

    def __init__(self, config: Config):
        c = config.section("impact")
        self.window = float(c.get("destructive_window_s", 60))
        self.threshold = int(c.get("destructive_threshold", 50))
        self.high_entropy = float(c.get("high_entropy", 7.2))
        self.ops: dict[tuple[str, int | None], deque[tuple[float, str, str]]] = defaultdict(deque)

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        op = None
        if ev.kind == "file_rename":
            op = "rename"
        elif ev.kind == "file_delete":
            op = "delete"
        elif ev.kind == "file_write" and ev.entropy is not None and ev.entropy >= self.high_entropy:
            op = "encrypt"
        if not op:
            return []
        key = (ev.host, ev.pid)
        dq = self.ops[key]
        dq.append((ev.ts, op, os.path.splitext(norm_path(ev.target_path or ev.path))[1]))
        while dq and ev.ts - dq[0][0] > self.window:
            dq.popleft()
        if len(dq) < self.threshold:
            return []
        counts: dict[str, int] = defaultdict(int)
        exts: dict[str, int] = defaultdict(int)
        for _, o, x in dq:
            counts[o] += 1
            if o == "rename":
                exts[x] += 1
        top_ext = max(exts.items(), key=lambda kv: kv[1])[0] if exts else None
        return [
            Alert(
                "INV-L5-002",
                f"'{ev.image_name or ev.pid}' performed {len(dq)} destructive file operations in {self.window:.0f}s",
                "critical",
                "L5",
                ev.host,
                ev.ts,
                "Encryption and wiping require touching many files fast. Rate is the invariant; the code that "
                "does it can be regenerated every run.",
                ["T1486", "T1485"],
                {
                    "operations": dict(counts),
                    "dominant_new_extension": top_ext,
                    "process": ev.image,
                    "pid": ev.pid,
                    "dedupe_key": f"{ev.pid}",
                },
                [ev],
            )
        ]


class SqlGuardDetector(Detector):
    layer = "L5"
    name = "sql-guard"
    _dml = re.compile(r"^\s*(update|delete)\b", re.I)
    _where = re.compile(r"\bwhere\b", re.I)

    def __init__(self, config: Config):
        c = config.section("impact")
        self.window = float(c.get("sql_window_s", 120))
        self.mass_rows = int(c.get("sql_mass_rows", 200))
        self.destructive = [d.lower() for d in c.get("sql_destructive", [])]
        self.protected = {t.lower() for t in c.get("protected_tables", [])}
        self.rows: dict[tuple[str, str], deque[tuple[float, int, str]]] = defaultdict(deque)

    def _table(self, ev: Event, stmt: str) -> str:
        t = ev.fields.get("table")
        if t:
            return str(t).lower()
        m = re.search(r"\b(?:update|from|into|table|truncate)\s+(?:table\s+)?([`\"\w.]+)", stmt, re.I)
        return m.group(1).strip('`"').split(".")[-1].lower() if m else "?"

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        if ev.kind != "sql":
            return []
        stmt = str(ev.fields.get("statement", ""))
        low = " ".join(stmt.lower().split())
        table = self._table(ev, stmt)
        session = str(ev.fields.get("session") or ev.user or "?")
        out: list[Alert] = []
        for d in self.destructive:
            if low.startswith(d) or f" {d} " in f" {low} ":
                prot = table in self.protected
                out.append(
                    Alert(
                        "INV-L5-003",
                        f"Destructive SQL '{d.upper()}' on {table}",
                        "critical" if prot else "high",
                        "L5",
                        ev.host,
                        ev.ts,
                        "Schema destruction outside a change window. JADEPUFFER dropped the original Nacos tables "
                        "after encrypting them.",
                        ["T1485"],
                        {
                            "table": table,
                            "statement": squash(stmt, 160),
                            "session": session,
                            "dedupe_key": f"{session}|{d}|{table}",
                        },
                        [ev],
                    )
                )
                break
        if self._dml.match(stmt):
            rows = int(ev.fields.get("rows", 1) or 1)
            dq = self.rows[(ev.host, session)]
            dq.append((ev.ts, rows, table))
            while dq and ev.ts - dq[0][0] > self.window:
                dq.popleft()
            total = sum(r for _, r, t in dq if t == table)
            if total >= self.mass_rows:
                prot = table in self.protected
                no_where = not self._where.search(stmt)
                out.append(
                    Alert(
                        "INV-L5-004",
                        f"{total} rows rewritten in '{table}' by one session in {self.window:.0f}s",
                        "critical" if prot or no_where else "high",
                        "L5",
                        ev.host,
                        ev.ts,
                        "Bulk modification of a configuration/metadata table is how database ransomware encrypts "
                        "(about 1,342 Nacos config records in JADEPUFFER). Throttle at the database too.",
                        ["T1486", "T1485"],
                        {
                            "table": table,
                            "rows_in_window": total,
                            "session": session,
                            "protected": prot,
                            "value_entropy": ev.fields.get("value_entropy"),
                            "dedupe_key": f"{session}|{table}",
                        },
                        [ev],
                    )
                )
        return out


def impact_detectors(config: Config) -> list[Detector]:
    return [CanaryDetector(config), DestructiveRateDetector(config), SqlGuardDetector(config)]
