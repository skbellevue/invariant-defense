"""Command-line interface.

invariant demo                         replay all synthetic scenarios through every layer
invariant detect --events FILE         run detections on normalized JSONL or Sysmon JSON
invariant hunt PATH...                 find embedded LLM keys, prompts, risky AI configs
invariant exposure --estate FILE       L1 audit of the AI estate (versions, KEV, defaults)
invariant creds --estate FILE          L4 audit of credentials (age, expiry, least agency)
invariant jwt TOKEN                    L4 audit of one bearer token
invariant canary deploy|check|watch    L5 tripwires
invariant snapshot create|verify|restore-test   L5 reversible config stores
invariant catalog --format squid       export LLM endpoints for proxies/firewalls/DNS
invariant live                         poll this machine (needs psutil)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

import yaml

from invariant import __version__
from invariant.alerts import SEVERITY_ORDER, sev_at_least
from invariant.config import Config

ORDER = ["info", "low", "medium", "high", "critical"]


def _cfg(args: argparse.Namespace) -> Config:
    return Config.load(getattr(args, "config", None))


def _engine(cfg: Config, respond: bool, execute: bool, approval: str | None):
    from invariant.engine import Engine
    from invariant.response.loop import ResponseLoop

    loop = None
    if respond:
        rc = dict(cfg.section("response"))
        rc["dry_run"] = not execute
        if approval:
            rc["approval"] = approval
        loop = ResponseLoop(rc)
    return Engine(cfg, on_alert=loop), loop


def _finish(args, engine, loop, events) -> int:
    from invariant.report import json_report, markdown_report, text_report
    from invariant.response.verify import verify_claims, verify_containment

    alerts = engine.alerts
    claims = verify_claims(events)
    checks = [verify_containment(events, h, t) for h, t in engine.ctx.contained.items()]
    dry = not getattr(args, "execute", False)
    print(text_report(alerts, events, engine.ctx.contained, claims, checks, args.min_severity, dry_run=dry))
    if getattr(args, "json", None):
        Path(args.json).write_text(
            json_report(alerts, events, engine.ctx.contained, claims=claims, containment=checks)
        )
        print(f"\nJSON report -> {args.json}")
    if getattr(args, "markdown", None):
        Path(args.markdown).write_text(markdown_report(alerts, events, engine.ctx.contained))
        print(f"Markdown report -> {args.markdown}")
    if loop and getattr(args, "learned", None):
        Path(args.learned).write_text(yaml.safe_dump(loop.learned_config(), sort_keys=False))
        print(f"Learned config (feed back into L1-L5) -> {args.learned}")
    fail_on = getattr(args, "fail_on", None)
    if fail_on and any(sev_at_least(a.severity, fail_on) for a in alerts):
        return 2
    return 0


# ---------------------------------------------------------------- commands
def cmd_detect(args) -> int:
    from invariant.collectors import load

    cfg = _cfg(args)
    events = list(load(args.events, args.format))
    engine, loop = _engine(cfg, args.respond, args.execute, args.approval)
    engine.run(events)
    return _finish(args, engine, loop, events)


def cmd_demo(args) -> int:
    from invariant.simulate import SCENARIOS

    cfg = _cfg(args)
    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    events = [e for n in names for e in SCENARIOS[n]()]
    engine, loop = _engine(cfg, args.respond, False, args.approval)
    engine.run(events)
    print(f"Scenarios: {', '.join(names)} (synthetic telemetry, see src/invariant/simulate.py)\n")
    return _finish(args, engine, loop, events)


def cmd_simulate(args) -> int:
    from invariant.events import write_jsonl
    from invariant.simulate import ESLOGGER_SCENARIOS, NEFILTER_SCENARIOS, SCENARIOS

    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    for n in names:
        count = write_jsonl(SCENARIOS[n](), out / f"{n}.jsonl")
        print(f"{n:12} {count:5} events -> {out / (n + '.jsonl')}")
        if n in ESLOGGER_SCENARIOS:  # also the raw macOS form, for `--format eslogger`
            raw = out / f"{n}.eslogger.jsonl"
            raw.write_text("".join(json.dumps(r) + "\n" for r in ESLOGGER_SCENARIOS[n]()))
            print(f"{'':12} {'':5}        -> {raw} (raw eslogger JSON)")
        if n in NEFILTER_SCENARIOS:
            nf = out / f"{n}.nefilter.jsonl"
            nf.write_text("".join(json.dumps(r) + "\n" for r in NEFILTER_SCENARIOS[n]()))
            print(f"{'':12} {'':5}        -> {nf} (Network Extension flow records)")
    return 0


def cmd_hunt(args) -> int:
    from invariant.egress.catalog import EndpointCatalog
    from invariant.hunt.scanner import scan, scan_ai_configs

    cfg = _cfg(args)
    results = scan(args.paths, yara_dir=args.yara_dir, exclude=args.exclude)
    cfg_findings = scan_ai_configs(args.paths, EndpointCatalog(cfg.catalog).all_domains())
    floor = ORDER.index(args.min_severity)
    results = [r for r in results if ORDER.index(r.severity) >= floor]
    cfg_findings = [f for f in cfg_findings if ORDER.index(f.severity) >= floor]
    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {"files": [asdict(r) for r in results], "ai_configs": [asdict(f) for f in cfg_findings]},
                indent=2,
            )
        )
    for r in results:
        print(f"[{r.severity.upper():8}] {r.path}")
        for v in r.verdicts:
            print(f"           {v['id']:24} {v['title']}")
        for k in r.keys:
            print(
                f"           key {k['provider']:22} {k['redacted']:28} {k['fingerprint']} ({k['confidence']})"
            )
        for y in r.yara:
            print(f"           yara {y}")
    for f in cfg_findings:
        print(f"[{f.severity.upper():8}] {f.file}\n           {f.rule:24} {f.message}")
    fps = sorted({k["fingerprint"] for r in results for k in r.keys})
    if fps:
        print(
            "\nKey fingerprints (add to egress.known_bad_key_fps to alert on use, and revoke with the provider):"
        )
        for fp in fps:
            print(f"  - {fp}")
    if not results and not cfg_findings:
        print("No findings.")
    worst = max(
        [ORDER.index(r.severity) for r in results] + [ORDER.index(f.severity) for f in cfg_findings] + [0]
    )
    return 2 if worst >= ORDER.index("high") else 0


def cmd_exposure(args) -> int:
    from invariant.exposure import kev as kevmod
    from invariant.exposure.inventory import coverage, evaluate, load_estate

    cfg = _cfg(args)
    estate = load_estate(args.estate)
    kev = kevmod.load(args.kev) if args.kev else None
    findings = evaluate(estate, cfg.vulndb, kev, patch_sla_days=args.patch_sla_days)
    cov = coverage(estate)
    if args.json:
        Path(args.json).write_text(
            json.dumps({"coverage": cov, "findings": [asdict(f) for f in findings]}, indent=2, default=str)
        )
    print(f"AI estate: {cov}")
    for f in findings:
        kev_tag = " [KEV]" if f.details.get("kev") else ""
        print(f"[{f.severity.upper():8}] {f.asset:18} {f.rule:28} {f.title}{kev_tag}")
        if f.fix:
            print(f"{'':30}fix: {f.fix}")
    return 2 if any(f.severity == "critical" for f in findings) else 0


def cmd_kev_sync(args) -> int:
    from invariant.exposure.kev import sync

    n = sync(args.output)
    print(f"KEV catalog: {n} entries -> {args.output}")
    return 0


def cmd_probe(args) -> int:
    from invariant.exposure.inventory import load_estate
    from invariant.exposure.probes import probe

    if not args.i_own_these_targets:
        print(
            "Refusing: probing is only for systems you own or are authorized to test. "
            "Re-run with --i-own-these-targets.",
            file=sys.stderr,
        )
        return 1
    estate = load_estate(args.estate)
    for asset in estate.get("assets", []):
        for r in probe(asset, verify_tls=not args.insecure):
            declared = asset.get("version")
            drift = (
                f"  (inventory says {declared})"
                if r.version and declared and r.version != str(declared)
                else ""
            )
            state = f"HTTP {r.status}" if r.reachable else f"unreachable: {r.error}"
            print(f"{r.asset:18} {r.url:60} {state} version={r.version}{drift}")
    return 0


def cmd_creds(args) -> int:
    from invariant.exposure.inventory import load_estate
    from invariant.identity.credentials import audit_credentials

    cfg = _cfg(args)
    estate = load_estate(args.estate)
    findings = audit_credentials(
        estate.get("credentials", []), int(cfg.get("identity.max_secret_age_days", 90))
    )
    for f in sorted(findings, key=lambda x: ORDER.index(x.severity), reverse=True):
        print(f"[{f.severity.upper():8}] {f.credential:28} {f.rule:20} {f.message}")
    if not findings:
        print("No credential findings.")
    return 2 if any(f.severity in ("high", "critical") for f in findings) else 0


def cmd_jwt(args) -> int:
    from invariant.identity.jwt_audit import audit_jwt

    cfg = _cfg(args)
    token = sys.stdin.read().strip() if args.token == "-" else args.token
    r = audit_jwt(
        token,
        cfg.get("identity.default_jwt_secrets", []),
        float(cfg.get("identity.max_token_lifetime_s", 3600)),
    )
    print(
        json.dumps(
            {
                "alg": r.alg,
                "subject": r.subject,
                "lifetime_s": r.lifetime_s,
                "expires_in_s": r.expires_in_s,
                "default_secret": bool(r.default_secret),
                "unsigned": r.unsigned,
                "findings": [{"severity": s, "message": m} for s, m in r.findings],
            },
            indent=2,
        )
    )
    return 2 if r.worst() == "critical" else 0


def cmd_canary(args) -> int:
    from invariant.impact import canary

    if args.action == "deploy":
        recs = canary.deploy(args.dirs)
        canary.save_manifest(recs, args.manifest)
        print(f"Deployed {len(recs)} canaries -> manifest {args.manifest}")
        return 0
    recs = canary.load_manifest(args.manifest)
    if args.action == "check":
        changes = canary.check(recs)
        for c in changes:
            print(f"[CRITICAL] canary {c['change']}: {c['path']}")
        print("All canaries intact." if not changes else f"{len(changes)} canary changes")
        return 2 if changes else 0
    # watch
    import socket

    from invariant.events import Event

    cfg = _cfg(args)
    cfg.data.setdefault("impact", {})["canary_manifest"] = args.manifest
    engine, loop = _engine(cfg, args.respond, args.execute, args.approval)
    print(f"Watching {len(recs)} canaries every {args.interval}s (Ctrl-C to stop)")
    reported: set[str] = set()
    try:
        while True:
            for c in canary.check(recs):
                if c["path"] in reported:
                    continue
                reported.add(c["path"])
                kind = "file_delete" if c["change"].startswith("deleted") else "file_write"
                engine.feed(Event(kind, time.time(), host=socket.gethostname(), path=c["path"]))
                for a in engine.alerts[-1:]:
                    print(a.one_line())
                    for act in a.actions:
                        print(f"    ↳ {act['step']}: {act['detail']}")
            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    return 2 if engine.alerts else 0


def cmd_snapshot(args) -> int:
    from invariant.impact import snapshot

    if args.action == "create":
        root = snapshot.create(args.paths, args.dest, args.label, immutable=args.immutable)
        print(f"Snapshot -> {root}")
        if args.immutable:
            print(f"Immutability: {(root.parent / f'.{root.name}.immutable').read_text()}")
        return 0
    if args.action == "verify":
        problems = snapshot.verify(args.paths[0])
        print("Snapshot verified." if not problems else "\n".join(problems))
        return 2 if problems else 0
    res = snapshot.restore_test(args.paths[0], args.scratch)
    print(json.dumps(res, indent=2))
    return 2 if res["failed"] else 0


def cmd_catalog(args) -> int:
    from invariant.egress.catalog import EndpointCatalog

    cfg = _cfg(args)
    cat = EndpointCatalog(cfg.catalog)
    domains = cat.all_domains()
    if args.format == "plain":
        print("\n".join(domains))
    elif args.format == "squid":
        print("# Squid: log and route LLM traffic; allow only via the sanctioned AI gateway")
        print("acl llm_endpoints dstdomain " + " ".join("." + d for d in domains))
        print("acl ai_gateway src 10.0.50.0/24   # <- your gateway subnet")
        print("http_access allow llm_endpoints ai_gateway")
        print("http_access deny llm_endpoints")
    elif args.format == "rpz":
        print(
            "; DNS RPZ: answer NXDOMAIN for LLM endpoints to non-gateway clients (pair with a gateway view)"
        )
        for d in domains:
            print(f"{d} CNAME .\n*.{d} CNAME .")
    elif args.format == "json":
        print(json.dumps(cfg.catalog, indent=2, default=str))
    elif args.format == "nefilter":
        from invariant.collectors.nefilter import export_config

        print(json.dumps(export_config(cfg.catalog, args.nefilter_mode), indent=2))
    return 0


def cmd_live(args) -> int:
    from invariant.collectors.live import poll
    from invariant.egress.catalog import EndpointCatalog

    cfg = _cfg(args)
    engine, loop = _engine(cfg, args.respond, args.execute, args.approval)
    domains = EndpointCatalog(cfg.catalog).all_domains()
    print(f"Live mode: polling every {args.interval}s; {len(domains)} LLM domains resolved for attribution")
    n_seen = 0
    try:
        for ev in poll(domains, args.interval, args.iterations):
            engine.feed(ev)
            for a in engine.alerts[n_seen:]:
                if SEVERITY_ORDER[a.severity] >= SEVERITY_ORDER[args.min_severity]:
                    print(a.one_line())
            n_seen = len(engine.alerts)
    except KeyboardInterrupt:
        pass
    engine.finish()
    return 0


def _follow(path: str, from_start: bool = False, poll_s: float = 0.5, stop=None):
    """tail -F: yield lines appended to ``path``, surviving rotation and late creation."""
    import os
    import time

    fh, ino = None, None
    while stop is None or not stop.is_set():
        if fh is None:
            try:
                fh = open(path, encoding="utf-8", errors="replace")
                ino = os.fstat(fh.fileno()).st_ino
                if not from_start:
                    fh.seek(0, os.SEEK_END)
                from_start = True  # after a rotation, read the new file from its start
            except OSError:
                time.sleep(poll_s)
                continue
        line = fh.readline()
        if line:
            yield line
            continue
        try:
            st = os.stat(path)
            if st.st_ino != ino or st.st_size < fh.tell():  # rotated or truncated
                fh.close()
                fh = None
                continue
        except OSError:
            fh.close()
            fh = None
        time.sleep(poll_s)


def cmd_stream(args) -> int:
    """Detect on telemetry as it arrives, from several sources at once.

    macOS, both sensors (Endpoint Security for processes and files, the Network
    Extension for connections):

        sudo eslogger exec create rename unlink close \\
          | sudo invariant stream --format eslogger --nefilter-log

    Events from different sources arrive with different latencies; a short reorder
    buffer (--reorder-ms) puts them back in timestamp order before detection, so a
    model call logged a moment after the exec it led to is still joined to it.
    """
    import heapq
    import itertools
    import queue
    import subprocess
    import threading
    import time

    from invariant.collectors import line_mapper

    cfg = _cfg(args)
    engine, loop = _engine(cfg, args.respond, args.execute, args.approval)
    q: queue.Queue = queue.Queue(maxsize=50_000)
    done = object()
    stop = threading.Event()
    sources: list[str] = []

    def pump(lines, fmt: str, signal_done: bool):
        mapper = line_mapper(fmt)
        try:
            for line in lines:
                if stop.is_set():
                    break
                try:
                    ev = mapper(line)
                except (ValueError, TypeError, KeyError):
                    ev = None
                if ev is not None:
                    q.put(ev)
        finally:
            if signal_done:
                q.put(done)

    others = bool(args.follow or args.nefilter_log or args.net_interval)
    primary = args.events != "none" and not (args.events == "-" and sys.stdin.isatty() and others)
    if primary:
        fh = sys.stdin if args.events == "-" else open(args.events, encoding="utf-8", errors="replace")
        threading.Thread(target=pump, args=(fh, args.format, True), daemon=True).start()
        sources.append(f"{args.format}:{'stdin' if args.events == '-' else args.events}")
    for spec in args.follow or []:
        fmt, _, path = spec.partition(":")
        if not path:
            print(f"--follow expects FORMAT:PATH, got {spec!r}", file=sys.stderr)
            return 1
        line_mapper(fmt)  # validate early
        threading.Thread(
            target=pump, args=(_follow(path, args.from_start, stop=stop), fmt, False), daemon=True
        ).start()
        sources.append(f"{fmt}:{path} (follow)")
    proc = None
    if args.nefilter_log:
        from invariant.collectors.nefilter import LOG_STREAM_CMD

        try:
            proc = subprocess.Popen(
                LOG_STREAM_CMD, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
        except OSError as exc:
            print(f"cannot start `log stream` (macOS only): {exc}", file=sys.stderr)
            return 1
        threading.Thread(target=pump, args=(proc.stdout, "nefilter", False), daemon=True).start()
        sources.append("nefilter:unified log")
    if args.net_interval:

        def sample_net():
            from invariant.collectors.live import poll
            from invariant.egress.catalog import EndpointCatalog

            domains = EndpointCatalog(cfg.catalog).all_domains()
            for ev in poll(domains, args.net_interval, include_processes=False):
                if stop.is_set():
                    break
                q.put(ev)

        threading.Thread(target=sample_net, daemon=True).start()
        sources.append(f"psutil every {args.net_interval}s")
    if not sources:
        print("no sources: give --events, --follow, --nefilter-log or --net-interval", file=sys.stderr)
        return 1
    print("Streaming " + " + ".join(sources), file=sys.stderr)

    delay = args.reorder_ms / 1000.0
    heap: list = []
    seq = itertools.count()
    n_seen, n_events = 0, 0

    def release(all_items: bool = False):
        nonlocal n_seen, n_events
        now = time.monotonic()
        while heap and (all_items or now - heap[0][2] >= delay or len(heap) > 20_000):
            # pop the earliest timestamp among events that have waited long enough
            _, _, _, ev = heapq.heappop(heap)
            n_events += 1
            engine.feed(ev)
        for a in engine.alerts[n_seen:]:
            if SEVERITY_ORDER[a.severity] >= SEVERITY_ORDER[args.min_severity]:
                print(a.one_line(), flush=True)
                for act in a.actions:
                    print(f"    ↳ {act['step']}: {act['detail']}", flush=True)
        n_seen = len(engine.alerts)

    try:
        while True:
            try:
                item = q.get(timeout=max(delay / 2, 0.05))
            except queue.Empty:
                release()
                continue
            if item is done:
                break
            # heap order: event time; arrival time decides when it may leave the buffer
            heapq.heappush(heap, (item.ts, next(seq), time.monotonic(), item))
            if delay == 0:
                release(all_items=True)
            else:
                release()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        if proc is not None:
            proc.terminate()
    release(all_items=True)
    engine.finish()
    print(f"{n_events} events, {len(engine.alerts)} alerts", file=sys.stderr)
    fail_on = args.fail_on
    return 2 if fail_on and any(sev_at_least(a.severity, fail_on) for a in engine.alerts) else 0


def cmd_unisolate(args) -> int:
    """Undo local isolation made by the iptables or pf adapter."""
    import subprocess

    from invariant.response.actions import iptables_release_commands, pf_release_commands, resolve_adapter

    adapter = resolve_adapter(args.adapter)
    if adapter == "pf":
        cmds = [" ".join(c) for c in pf_release_commands()]
    elif adapter == "iptables":
        cmds = iptables_release_commands()
    else:
        print(f"nothing to undo for adapter {adapter!r}", file=sys.stderr)
        return 1
    if not args.execute:
        print("Would run (add --execute, as root):")
        print("\n".join(f"  {c}" for c in cmds))
        return 0
    rc = 0
    for c in cmds:
        proc = subprocess.run(c, shell=True, capture_output=True, text=True)  # noqa: S602 - fixed commands
        print(f"{'ok ' if proc.returncode == 0 else 'ERR'} {c} {proc.stderr.strip()}")
        rc = rc or proc.returncode
    return 0 if rc == 0 else 1


# ---------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="invariant", description="Invariant Defense Model reference platform")
    p.add_argument("--version", action="version", version=f"invariant {__version__}")
    p.add_argument("-c", "--config", help="YAML config overriding packaged defaults")
    sub = p.add_subparsers(dest="cmd", required=True)

    def response_flags(sp):
        sp.add_argument("--respond", action="store_true", help="run the response loop on alerts")
        sp.add_argument("--execute", action="store_true", help="actually execute actions (default: dry-run)")
        sp.add_argument(
            "--approval", choices=["deny", "prompt", "file"], help="approval mode for irreversible steps"
        )

    def report_flags(sp):
        sp.add_argument("--min-severity", default="low", choices=ORDER)
        sp.add_argument("--json", help="write JSON report")
        sp.add_argument("--markdown", help="write Markdown report")
        sp.add_argument("--learned", help="write learned config snippet (response loop step 6)")
        sp.add_argument("--fail-on", choices=ORDER, help="exit 2 if any alert at/above this severity")

    sp = sub.add_parser("detect", help="run detections on telemetry")
    sp.add_argument("--events", required=True)
    sp.add_argument("--format", default="jsonl", choices=["jsonl", "sysmon", "eslogger", "nefilter"])
    response_flags(sp)
    report_flags(sp)
    sp.set_defaults(func=cmd_detect)

    sp = sub.add_parser("demo", help="replay synthetic scenarios")
    sp.add_argument(
        "--scenario",
        default="all",
        choices=["all", "promptflux", "lamehug", "jadepuffer", "s1ngularity", "benign"],
    )
    sp.add_argument("--respond", action="store_true")
    sp.add_argument("--approval", choices=["deny", "prompt", "file"])
    report_flags(sp)
    sp.set_defaults(func=cmd_demo)

    sp = sub.add_parser("simulate", help="write synthetic telemetry as JSONL")
    sp.add_argument(
        "scenario", choices=["all", "promptflux", "lamehug", "jadepuffer", "s1ngularity", "benign"]
    )
    sp.add_argument("-o", "--output", default="simulations")
    sp.set_defaults(func=cmd_simulate)

    sp = sub.add_parser("hunt", help="hunt files for embedded LLM keys/prompts and risky AI configs")
    sp.add_argument("paths", nargs="+")
    sp.add_argument("--yara-dir", help="directory of .yar rules (needs yara-python)")
    sp.add_argument(
        "--exclude", action="append", default=[], help="glob on path or file name to skip (repeatable)"
    )
    sp.add_argument("--json")
    sp.add_argument("--min-severity", default="low", choices=ORDER)
    sp.set_defaults(func=cmd_hunt)

    sp = sub.add_parser("exposure", help="L1 audit of the AI estate")
    sp.add_argument("--estate", required=True)
    sp.add_argument("--kev", help="CISA KEV JSON file")
    sp.add_argument("--patch-sla-days", type=int, default=7)
    sp.add_argument("--json")
    sp.set_defaults(func=cmd_exposure)

    sp = sub.add_parser("kev-sync", help="download the CISA KEV catalog")
    sp.add_argument("-o", "--output", default="kev.json")
    sp.set_defaults(func=cmd_kev_sync)

    sp = sub.add_parser("probe", help="read-only fingerprint of AI platforms you own")
    sp.add_argument("--estate", required=True)
    sp.add_argument("--i-own-these-targets", action="store_true")
    sp.add_argument("--insecure", action="store_true", help="skip TLS verification (lab use)")
    sp.set_defaults(func=cmd_probe)

    sp = sub.add_parser("creds", help="L4 credential inventory audit")
    sp.add_argument("--estate", required=True)
    sp.set_defaults(func=cmd_creds)

    sp = sub.add_parser("jwt", help="L4 audit of a bearer token ('-' reads stdin)")
    sp.add_argument("token")
    sp.set_defaults(func=cmd_jwt)

    sp = sub.add_parser("canary", help="L5 canary files")
    sp.add_argument("action", choices=["deploy", "check", "watch"])
    sp.add_argument("dirs", nargs="*")
    sp.add_argument("--manifest", default="canaries.json")
    sp.add_argument("--interval", type=float, default=2.0)
    sp.add_argument("--once", action="store_true")
    response_flags(sp)
    sp.set_defaults(func=cmd_canary)

    sp = sub.add_parser("snapshot", help="L5 config-store snapshots")
    sp.add_argument("action", choices=["create", "verify", "restore-test"])
    sp.add_argument("paths", nargs="+")
    sp.add_argument("--dest", default="./snapshots")
    sp.add_argument("--label")
    sp.add_argument("--scratch", default="./restore-test")
    sp.add_argument(
        "--immutable",
        action="store_true",
        help="also set the OS immutable flag (macOS chflags uchg; Linux chattr +i, root)",
    )
    sp.set_defaults(func=cmd_snapshot)

    sp = sub.add_parser("catalog", help="export LLM endpoint catalog")
    sp.add_argument("--format", default="plain", choices=["plain", "squid", "rpz", "json", "nefilter"])
    sp.add_argument(
        "--nefilter-mode",
        default="catalog",
        choices=["catalog", "all"],
        help="for --format nefilter: report only model endpoints, or every outbound flow",
    )
    sp.set_defaults(func=cmd_catalog)

    sp = sub.add_parser("stream", help="detect on telemetry as it arrives, from one or more sources")
    sp.add_argument("--events", default="-", help="primary source: file, - for stdin (default), or none")
    sp.add_argument("--format", default="jsonl", choices=["jsonl", "sysmon", "eslogger", "nefilter"])
    sp.add_argument(
        "--follow",
        action="append",
        metavar="FORMAT:PATH",
        help="also tail a growing file (repeatable), e.g. nefilter:/path/flows.jsonl",
    )
    sp.add_argument("--from-start", action="store_true", help="--follow reads existing content first")
    sp.add_argument(
        "--nefilter-log",
        action="store_true",
        help="macOS: also read Invariant Network Extension records from the unified log (root)",
    )
    sp.add_argument(
        "--net-interval",
        type=float,
        default=0.0,
        help="also sample network connections every N seconds with psutil (needs root on macOS)",
    )
    sp.add_argument(
        "--reorder-ms",
        type=int,
        default=1500,
        help="buffer to re-order events from sources with different latency (0 = off)",
    )
    sp.add_argument("--min-severity", default="medium", choices=ORDER)
    sp.add_argument("--fail-on", choices=ORDER)
    response_flags(sp)
    sp.set_defaults(func=cmd_stream)

    sp = sub.add_parser("unisolate", help="undo local iptables/pf isolation")
    sp.add_argument("--adapter", default="auto", choices=["auto", "pf", "iptables"])
    sp.add_argument("--execute", action="store_true")
    sp.set_defaults(func=cmd_unisolate)

    sp = sub.add_parser("live", help="poll this machine (psutil)")
    sp.add_argument("--interval", type=float, default=5.0)
    sp.add_argument("--iterations", type=int)
    sp.add_argument("--min-severity", default="medium", choices=ORDER)
    response_flags(sp)
    sp.set_defaults(func=cmd_live)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
