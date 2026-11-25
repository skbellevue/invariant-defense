"""Streaming detection engine.

Events are processed in timestamp order. Each detector sees every event
together with a shared :class:`Context` (config, process tree, cross-layer
state such as "which processes recently talked to a model"). Alerts are
de-duplicated by fingerprint and optionally handed to the response loop.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from invariant.alerts import Alert
from invariant.config import Config
from invariant.events import Event
from invariant.lineage import ProcessTree


@dataclass
class LlmContact:
    ts: float
    provider: str
    dst: str
    pid: int | None
    image: str
    sanctioned: bool = False  # True if the egress allow-list permitted it


@dataclass
class Context:
    config: Config
    tree: ProcessTree = field(default_factory=ProcessTree)
    # (host, pid) -> recent model contacts; populated by the L2 egress detector
    llm_contacts: dict[tuple[str, int], list[LlmContact]] = field(default_factory=lambda: defaultdict(list))
    # hosts already contained by the response loop: host -> containment ts
    contained: dict[str, float] = field(default_factory=dict)
    first_event_ts: float | None = None
    last_event_ts: float | None = None

    def note_llm_contact(self, ev: Event, provider: str, sanctioned: bool = False) -> None:
        if ev.pid is None:
            return
        lst = self.llm_contacts[(ev.host, ev.pid)]
        lst.append(
            LlmContact(ev.ts, provider, ev.dst_host or ev.dst_ip or "", ev.pid, ev.image or "", sanctioned)
        )
        if len(lst) > 64:
            del lst[:-64]

    def recent_llm_contact(
        self,
        host: str,
        pid: int | None,
        now: float,
        window: float,
        include_sanctioned: bool = False,
    ) -> LlmContact | None:
        """Most recent model contact by ``pid`` or any of its ancestors within ``window`` seconds.

        Sanctioned contacts (allowed by the egress policy, e.g. a developer's coding
        assistant) are skipped unless ``include_sanctioned`` is set: a sanctioned agent
        running the commands it generates is the product working as intended.
        """
        best: LlmContact | None = None
        for p in self.tree.lineage_pids(host, pid):
            for c in self.llm_contacts.get((host, p), ()):
                if c.sanctioned and not include_sanctioned:
                    continue
                if 0 <= now - c.ts <= window and (best is None or c.ts > best.ts):
                    best = c
        return best


class Detector:
    """Base class. Subclasses set ``layer`` and implement ``process``."""

    layer = "L?"
    name = "detector"

    def process(self, ev: Event, ctx: Context) -> list[Alert]:  # pragma: no cover - interface
        return []

    def finish(self, ctx: Context) -> list[Alert]:
        """Called once after the stream ends (for batch analytics)."""
        return []


class Engine:
    def __init__(
        self,
        config: Config,
        detectors: Iterable[Detector] | None = None,
        on_alert: Callable[[Alert, Context], None] | None = None,
    ):
        self.ctx = Context(config=config)
        self.detectors: list[Detector] = (
            list(detectors) if detectors is not None else default_detectors(config)
        )
        self.on_alert = on_alert
        self.alerts: list[Alert] = []
        self._seen: dict[str, Alert] = {}

    def _emit(self, alerts: Iterable[Alert]) -> None:
        for a in alerts:
            fp = a.fingerprint
            if fp in self._seen:
                prev = self._seen[fp]
                prev.evidence["repeat_count"] = prev.evidence.get("repeat_count", 1) + 1
                continue
            self._seen[fp] = a
            self.alerts.append(a)
            if self.on_alert:
                self.on_alert(a, self.ctx)

    def feed(self, ev: Event) -> None:
        ctx = self.ctx
        if ctx.first_event_ts is None:
            ctx.first_event_ts = ev.ts
        ctx.last_event_ts = ev.ts
        ctx.tree.observe(ev)
        for d in self.detectors:
            self._emit(d.process(ev, ctx))

    def run(self, events: Iterable[Event]) -> list[Alert]:
        for ev in sorted(events, key=lambda e: e.ts):
            self.feed(ev)
        return self.finish()

    def finish(self) -> list[Alert]:
        for d in self.detectors:
            self._emit(d.finish(self.ctx))
        self.alerts.sort(key=lambda a: a.ts)
        return self.alerts


def default_detectors(config: Config) -> list[Detector]:
    # Imported here to avoid import cycles.
    from invariant.behavior.detectors import behavior_detectors
    from invariant.egress.detector import egress_detectors
    from invariant.identity.detectors import identity_detectors
    from invariant.impact.detectors import impact_detectors

    # Order matters: L2 runs first so L3 can see model contacts in the same event pass.
    return [
        *egress_detectors(config),
        *behavior_detectors(config),
        *identity_detectors(config),
        *impact_detectors(config),
    ]
