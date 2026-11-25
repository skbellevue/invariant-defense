"""Live endpoint collector (psutil) for quick deployment without an EDR.

Polls running processes and their outbound TCP connections, resolves the
destination through a local reverse-lookup cache built from the LLM catalog
(forward-resolving every catalog domain, since reverse DNS of cloud IPs rarely
returns the API hostname), and emits normalized events.

It is a sampling collector: short-lived connections between polls are missed.
For production, ship Sysmon (Windows), Endpoint Security / Santa (macOS) or
eBPF/auditd (Linux) telemetry instead and use the JSONL/Sysmon readers.
"""

from __future__ import annotations

import socket
import sys
import time
from collections.abc import Iterator

from invariant.events import Event


def build_ip_map(domains: list[str]) -> dict[str, str]:
    ip_map: dict[str, str] = {}
    for d in domains:
        try:
            for info in socket.getaddrinfo(d, 443, proto=socket.IPPROTO_TCP):
                ip_map[info[4][0]] = d
        except OSError:
            continue
    return ip_map


def poll(
    domains: list[str],
    interval: float = 5.0,
    iterations: int | None = None,
    include_processes: bool = True,
) -> Iterator[Event]:
    try:
        import psutil  # type: ignore
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise SystemExit("live mode needs psutil: pip install 'invariant-defense[live]'") from exc

    host = socket.gethostname()
    ip_map = build_ip_map(domains)
    seen_procs: set[tuple[int, float]] = set()
    seen_conns: set[tuple[int, str, int]] = set()
    n = 0
    warned = False
    while iterations is None or n < iterations:
        now = time.time()
        for p in (
            psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"])
            if include_processes
            else ()
        ):
            info = p.info
            key = (info["pid"], info.get("create_time") or 0)
            if key not in seen_procs:
                seen_procs.add(key)
                yield Event(
                    "process_start",
                    ts=info.get("create_time") or now,
                    host=host,
                    pid=info["pid"],
                    ppid=info.get("ppid"),
                    image=info.get("exe") or info.get("name"),
                    cmdline=" ".join(info.get("cmdline") or []),
                    user=info.get("username"),
                )
        try:
            conns = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, PermissionError):
            conns = []
            if not warned:
                warned = True
                print(
                    "invariant: cannot list other processes' connections without root "
                    "(macOS requires it); run with sudo or the L2 egress layer sees nothing",
                    file=sys.stderr,
                )
        for c in conns:
            if not c.raddr or c.pid is None:
                continue
            ip, port = c.raddr.ip, c.raddr.port
            k = (c.pid, ip, port)
            if k in seen_conns:
                continue
            seen_conns.add(k)
            try:
                proc = psutil.Process(c.pid)
                image = proc.exe() or proc.name()
                cmd = " ".join(proc.cmdline())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                image, cmd = None, None
            yield Event(
                "network_connect",
                ts=now,
                host=host,
                pid=c.pid,
                image=image,
                cmdline=cmd,
                dst_ip=ip,
                dst_port=port,
                dst_host=ip_map.get(ip),
            )
        n += 1
        if iterations is None or n < iterations:
            time.sleep(interval)
