"""Process lineage: the backbone of behavior detection (L3).

Detecting "a script asked a model for code and then ran the reply" means
following the reply across process boundaries: the requester may be a
VBScript host, the executor its grandchild cmd.exe. ProcessTree keeps a
bounded, per-host map of pid -> process record and answers ancestry queries.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from invariant.events import Event


@dataclass
class Proc:
    host: str
    pid: int
    ppid: int | None
    image: str
    cmdline: str
    ts: float
    user: str | None = None

    @property
    def name(self) -> str:
        return self.image.replace("\\", "/").rsplit("/", 1)[-1].lower()


class ProcessTree:
    def __init__(self, max_procs: int = 200_000):
        self._procs: OrderedDict[tuple[str, int], Proc] = OrderedDict()
        self._max = max_procs

    def observe(self, ev: Event) -> None:
        if ev.kind == "process_start" and ev.pid is not None:
            key = (ev.host, ev.pid)
            # pid reuse: a new start for the same pid replaces the old record
            self._procs[key] = Proc(
                ev.host, ev.pid, ev.ppid, ev.image or "", ev.cmdline or "", ev.ts, ev.user
            )
            self._procs.move_to_end(key)
            if ev.ppid is not None and (ev.host, ev.ppid) not in self._procs and ev.parent_image:
                # synthesize the parent so ancestry works even if we missed its start
                self._procs[(ev.host, ev.ppid)] = Proc(ev.host, ev.ppid, None, ev.parent_image, "", ev.ts)
            while len(self._procs) > self._max:
                self._procs.popitem(last=False)

    def get(self, host: str, pid: int | None) -> Proc | None:
        if pid is None:
            return None
        return self._procs.get((host, pid))

    def ancestors(self, host: str, pid: int | None, max_depth: int = 16) -> list[Proc]:
        out: list[Proc] = []
        seen: set[int] = set()
        cur = self.get(host, pid)
        while cur and cur.ppid is not None and len(out) < max_depth:
            if cur.ppid in seen:
                break
            seen.add(cur.ppid)
            parent = self.get(host, cur.ppid)
            if not parent:
                break
            out.append(parent)
            cur = parent
        return out

    def lineage_pids(self, host: str, pid: int | None) -> list[int]:
        """pid itself followed by its ancestors' pids."""
        if pid is None:
            return []
        return [pid] + [p.pid for p in self.ancestors(host, pid)]

    def chain(self, host: str, pid: int | None) -> str:
        """Human-readable ancestry, e.g. 'explorer.exe > wscript.exe > cmd.exe'."""
        me = self.get(host, pid)
        names = [p.name for p in reversed(self.ancestors(host, pid))]
        if me:
            names.append(me.name)
        return " > ".join(names)
