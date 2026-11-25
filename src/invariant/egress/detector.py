"""L2 detectors: govern AI egress.

INV-L2-001  unsanctioned process reached a language-model endpoint
INV-L2-002  one LLM API key used from several hosts / processes (LLMjacking, theft)
INV-L2-003  an API key previously found embedded in a sample is being used
INV-L2-004  periodic model calls from one process (regeneration loop, e.g. hourly rewrite)
INV-L3-010  periodic beaconing to a non-model destination (C2 heartbeat)
"""

from __future__ import annotations

import statistics
from collections import defaultdict

from invariant.alerts import Alert
from invariant.config import Config
from invariant.egress.catalog import EndpointCatalog
from invariant.egress.policy import EgressPolicy
from invariant.engine import Context, Detector
from invariant.events import Event
from invariant.util import glob_any


class LlmEgressDetector(Detector):
    layer = "L2"
    name = "llm-egress"

    def __init__(self, config: Config):
        self.catalog = EndpointCatalog(config.catalog)
        self.policy = EgressPolicy(config.section("egress"))

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        m = self.catalog.match_event(ev)
        if not m:
            return []
        if ev.pid is None and not ev.image:
            # DNS/proxy records without process attribution: we can only inventory
            return []
        decision = self.policy.evaluate(ev, m.provider)
        ctx.note_llm_contact(ev, m.provider, sanctioned=decision.allowed)
        if decision.allowed:
            return []
        if decision.high_risk_process:
            severity = "critical" if ev.signed is False else "high"
        elif ev.signed is False:
            severity = "high"
        else:
            severity = "medium"
        if m.confidence != "high" and severity == "critical":
            severity = "high"
        chain = ctx.tree.chain(ev.host, ev.pid) or ev.image_name
        return [
            Alert(
                rule_id="INV-L2-001",
                title=f"Unsanctioned process '{ev.image_name}' reached LLM provider '{m.provider}'",
                severity=severity,
                layer="L2",
                host=ev.host,
                ts=ev.ts,
                description=(
                    "A process outside the AI egress allow-list contacted a language-model endpoint. "
                    "Malware that generates code or commands at runtime must make this call; script hosts, "
                    "Office and unsigned binaries have no business making it."
                ),
                attack=["T1071.001", "T1027.014"] if decision.high_risk_process else ["T1071.001"],
                evidence={
                    "provider": m.provider,
                    "category": m.category,
                    "match": m.reason,
                    "confidence": m.confidence,
                    "destination": ev.dst_host or ev.url or f"{ev.dst_ip}:{ev.dst_port}",
                    "process_chain": chain,
                    "cmdline": ev.cmdline,
                    "signed": ev.signed,
                    "dedupe_key": f"{ev.image_name}|{m.provider}",
                },
                events=[ev],
            )
        ]


class KeyUseDetector(Detector):
    """Needs L7 records (AI gateway / TLS-inspecting proxy) carrying a key fingerprint."""

    layer = "L2"
    name = "llm-key-use"

    def __init__(self, config: Config):
        self.known_bad = set(config.get("egress.known_bad_key_fps", []) or [])
        self.seen: dict[str, set[tuple[str, str]]] = defaultdict(set)

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        fp = ev.fields.get("api_key_fp")
        if ev.kind != "http_request" or not fp:
            return []
        out: list[Alert] = []
        who = (ev.host, ev.image_name or ev.src_ip or "?")
        self.seen[fp].add(who)
        if fp in self.known_bad:
            out.append(
                Alert(
                    "INV-L2-003",
                    "API key previously found embedded in a sample is in active use",
                    "critical",
                    "L2",
                    ev.host,
                    ev.ts,
                    "A key recovered by hunting (YARA/retrohunt) is being presented to a provider. "
                    "Revoke it with the provider now; this is either the malware or someone reusing its key.",
                    ["T1552.001", "T1496"],
                    {"key_fp": fp, "destination": ev.dst_host or ev.url, "dedupe_key": fp + ev.host},
                    [ev],
                )
            )
        hosts = {h for h, _ in self.seen[fp]}
        if len(hosts) >= 2:
            out.append(
                Alert(
                    "INV-L2-002",
                    f"One LLM API key used from {len(hosts)} hosts",
                    "high",
                    "L2",
                    ev.host,
                    ev.ts,
                    "Provider keys should be bound to one workload. Multi-host use suggests theft "
                    "(LLMjacking) or a key embedded in software that spread.",
                    ["T1552.001", "T1496"],
                    {"key_fp": fp, "users": sorted(f"{h}:{p}" for h, p in self.seen[fp]), "dedupe_key": fp},
                    [ev],
                )
            )
        return out


class BeaconDetector(Detector):
    layer = "L2"
    name = "beacon"

    def __init__(self, config: Config):
        b = config.get("egress.beacon", {}) or {}
        self.min_events = int(b.get("min_events", 4))
        self.max_jitter = float(b.get("max_jitter_ratio", 0.2))
        self.min_interval = float(b.get("min_interval_s", 60))
        self.ignore = [p.lower() for p in (b.get("ignore_processes") or [])]
        self.catalog = EndpointCatalog(config.catalog)
        self.series: dict[tuple[str, str, str], list[float]] = defaultdict(list)
        self.samples: dict[tuple[str, str, str], Event] = {}

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        if ev.kind not in ("network_connect", "http_request"):
            return []
        dst = ev.dst_host or ev.dst_ip
        if not dst or glob_any(ev.image_name, self.ignore):
            return []
        key = (ev.host, ev.image_name, dst)
        ts_list = self.series[key]
        ts_list.append(ev.ts)
        self.samples[key] = ev
        if len(ts_list) > 200:
            del ts_list[:-200]
        if len(ts_list) < self.min_events:
            return []
        intervals = [b - a for a, b in zip(ts_list, ts_list[1:], strict=False) if b - a > 0]
        if len(intervals) < self.min_events - 1:
            return []
        mean = statistics.fmean(intervals)
        if mean < self.min_interval:
            return []
        jitter = statistics.pstdev(intervals) / mean if mean else 1.0
        if jitter > self.max_jitter:
            return []
        m = self.catalog.match_host(dst) or self.catalog.match_port(ev.dst_port)
        evidence = {
            "destination": dst,
            "process": ev.image_name,
            "contacts": len(ts_list),
            "mean_interval_s": round(mean, 1),
            "jitter_ratio": round(jitter, 3),
            "dedupe_key": f"{ev.image_name}|{dst}",
        }
        if m:
            evidence["provider"] = m.provider
            return [
                Alert(
                    "INV-L2-004",
                    f"Periodic model calls every ~{mean / 60:.0f} min from '{ev.image_name}'",
                    "high",
                    "L2",
                    ev.host,
                    ev.ts,
                    "Regular, timer-driven calls to a model API from one process match self-regenerating "
                    "malware (one PROMPTFLUX variant asked Gemini to rewrite its source hourly).",
                    ["T1027.014", "T1071.001"],
                    evidence,
                    [ev],
                )
            ]
        return [
            Alert(
                "INV-L3-010",
                f"Fixed-interval beacon every ~{mean / 60:.0f} min to {dst}",
                "high",
                "L3",
                ev.host,
                ev.ts,
                "Low-jitter periodic connections from one process are a classic C2 heartbeat "
                "(JADEPUFFER's scheduled task beaconed every 30 minutes).",
                ["T1071.001", "T1053"],
                evidence,
                [ev],
            )
        ]


def egress_detectors(config: Config) -> list[Detector]:
    return [LlmEgressDetector(config), KeyUseDetector(config), BeaconDetector(config)]
