"""Response action adapters.

Every adapter is dry-run by default: it records exactly what it would do. Set
``response.dry_run: false`` to execute. Adapters:

* ``log``      record only (default)
* ``iptables`` Linux host isolation, keeping management CIDRs reachable (run locally as root)
* ``pf``       macOS host isolation through a pf anchor under ``com.apple/`` (run locally as root)
* ``auto``     ``pf`` on macOS, ``iptables`` on Linux
* ``webhook``  POST a JSON action request to your SOAR / EDR / ChatOps bridge
* ``command``  run a configured shell template, e.g. ``edrctl contain {host}``

Credential revocation is deliberately provider-agnostic: each provider exposes a
different admin API, so wire ``revoke`` to a webhook or command that knows your
key registry (Vault, cloud KMS, provider admin console automation).
"""

from __future__ import annotations

import json
import shlex
import subprocess
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from invariant.alerts import Alert


@dataclass
class ActionResult:
    step: str
    adapter: str
    target: str
    executed: bool
    ok: bool
    detail: str
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def iptables_isolation_commands(management_cidrs: list[str]) -> list[str]:
    cmds = ["iptables -N INVARIANT-ISOLATE 2>/dev/null || iptables -F INVARIANT-ISOLATE"]
    for cidr in management_cidrs:
        cmds.append(f"iptables -A INVARIANT-ISOLATE -d {shlex.quote(cidr)} -j ACCEPT")
        cmds.append(f"iptables -A INVARIANT-ISOLATE -s {shlex.quote(cidr)} -j ACCEPT")
    cmds += [
        "iptables -A INVARIANT-ISOLATE -o lo -j ACCEPT",
        "iptables -A INVARIANT-ISOLATE -i lo -j ACCEPT",
        "iptables -A INVARIANT-ISOLATE -j DROP",
        "iptables -C OUTPUT -j INVARIANT-ISOLATE 2>/dev/null || iptables -I OUTPUT 1 -j INVARIANT-ISOLATE",
        "iptables -C INPUT -j INVARIANT-ISOLATE 2>/dev/null || iptables -I INPUT 1 -j INVARIANT-ISOLATE",
    ]
    return cmds


PF_ANCHOR = "com.apple/invariant"  # evaluated by the stock /etc/pf.conf `anchor "com.apple/*"`


def pf_isolation_rules(management_cidrs: list[str]) -> str:
    """pf rules for the isolation anchor: loopback and management stay reachable, all else drops."""
    rules = ["pass quick on lo0 all"]
    for cidr in management_cidrs:
        rules.append(f"pass out quick to {cidr} keep state")
        rules.append(f"pass in quick from {cidr} keep state")
    rules.append("block drop quick all")
    return "\n".join(rules) + "\n"


def pf_isolation_commands(management_cidrs: list[str]) -> list[list[str]]:
    """argv lists (no shell): load the anchor, then enable pf (pfctl -E takes a reference)."""
    return [["pfctl", "-a", PF_ANCHOR, "-f", "-"], ["pfctl", "-E"]]


def pf_release_commands() -> list[list[str]]:
    return [["pfctl", "-a", PF_ANCHOR, "-F", "all"]]


def iptables_release_commands() -> list[str]:
    return [
        "iptables -D OUTPUT -j INVARIANT-ISOLATE",
        "iptables -D INPUT -j INVARIANT-ISOLATE",
        "iptables -F INVARIANT-ISOLATE",
        "iptables -X INVARIANT-ISOLATE",
    ]


def resolve_adapter(adapter: str, system: str | None = None) -> str:
    if adapter != "auto":
        return adapter
    import platform

    system = system or platform.system()
    return {"Darwin": "pf", "Linux": "iptables"}.get(system, "log")


class Actions:
    def __init__(self, response_cfg: dict[str, Any]):
        self.cfg = response_cfg
        self.dry = bool(response_cfg.get("dry_run", True))
        self.adapters: dict[str, str] = response_cfg.get("adapters", {}) or {}
        self.commands: dict[str, str] = response_cfg.get("commands", {}) or {}

    # ------------------------------------------------------------------ dispatch
    def run(self, step: str, alert: Alert) -> ActionResult:
        adapter = resolve_adapter(self.adapters.get(step, "log"))
        target = self._target(step, alert)
        if self.dry or adapter == "log":
            return ActionResult(step, adapter, target, False, True, self._describe(step, adapter, alert))
        try:
            if adapter == "webhook":
                return self._webhook(step, adapter, target, alert)
            if adapter == "command":
                return self._command(step, adapter, target, alert)
            if adapter == "iptables" and step == "isolate":
                return self._iptables(step, adapter, target)
            if adapter == "pf" and step == "isolate":
                return self._pf(step, adapter, target)
        except Exception as exc:  # noqa: BLE001 - report, never crash the loop
            return ActionResult(step, adapter, target, True, False, f"error: {exc}")
        return ActionResult(
            step, adapter, target, False, False, f"adapter '{adapter}' not valid for '{step}'"
        )

    def _target(self, step: str, alert: Alert) -> str:
        if step == "revoke":
            ev = alert.evidence
            return str(
                ev.get("key_fp")
                or ev.get("token_fp")
                or ev.get("target_user")
                or ev.get("account")
                or ev.get("subject")
                or ev.get("provider")
                or alert.host
            )
        return alert.host

    def _describe(self, step: str, adapter: str, alert: Alert) -> str:
        if step == "isolate":
            if adapter == "iptables":
                cmds = iptables_isolation_commands(self.cfg.get("management_cidrs", []))
                return "would run: " + " && ".join(cmds[:3]) + " …"
            if adapter == "pf":
                rules = pf_isolation_rules(self.cfg.get("management_cidrs", [])).strip().replace("\n", "; ")
                return f"would load pf anchor {PF_ANCHOR} [{rules}] and enable pf"
            return f"would network-isolate host {alert.host} (keep management channel)"
        if step == "revoke":
            what = self._target(step, alert)
            return f"would revoke credentials/sessions referenced by the alert ({what}) and the host's provider keys"
        if step == "snapshot":
            return f"would capture volatile evidence and snapshot config stores for {alert.host}"
        if step == "notify":
            return f"would page on-call: {alert.rule_id} {alert.title}"
        return f"would run {step}"

    def _fmt(self, template: str, alert: Alert, target: str) -> str:
        values = {
            "host": shlex.quote(alert.host),
            "rule": shlex.quote(alert.rule_id),
            "target": shlex.quote(target),
            "key_ref": shlex.quote(target),
            "severity": shlex.quote(alert.severity),
        }
        return template.format(**values)

    def _command(self, step: str, adapter: str, target: str, alert: Alert) -> ActionResult:
        tmpl = self.commands.get(step)
        if not tmpl:
            return ActionResult(step, adapter, target, False, False, "no command template configured")
        cmd = self._fmt(tmpl, alert, target)
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)  # noqa: S602
        return ActionResult(
            step, adapter, target, True, proc.returncode == 0, (proc.stdout or proc.stderr).strip()[:400]
        )

    def _webhook(self, step: str, adapter: str, target: str, alert: Alert) -> ActionResult:
        url = self.cfg.get("webhook_url")
        if not url:
            return ActionResult(step, adapter, target, False, False, "webhook_url not configured")
        body = json.dumps({"action": step, "target": target, "alert": alert.to_dict()}, default=str).encode()
        req = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - operator-configured URL
            return ActionResult(step, adapter, target, True, 200 <= resp.status < 300, f"HTTP {resp.status}")

    def _pf(self, step: str, adapter: str, target: str) -> ActionResult:
        rules = pf_isolation_rules(self.cfg.get("management_cidrs", []))
        load, enable = pf_isolation_commands(self.cfg.get("management_cidrs", []))
        proc = subprocess.run(load, input=rules, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            return ActionResult(
                step, adapter, target, True, False, f"pfctl load failed: {proc.stderr.strip()}"
            )
        proc = subprocess.run(enable, capture_output=True, text=True, timeout=30)
        # pfctl -E prints "pf enabled" / "Token : N" on stderr even on success
        ok = proc.returncode == 0
        return ActionResult(
            step,
            adapter,
            target,
            True,
            ok,
            f"isolated locally via pf anchor {PF_ANCHOR}"
            if ok
            else f"pfctl -E failed: {proc.stderr.strip()}",
        )

    def _iptables(self, step: str, adapter: str, target: str) -> ActionResult:
        cmds = iptables_isolation_commands(self.cfg.get("management_cidrs", []))
        for c in cmds:
            proc = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=30)  # noqa: S602
            if proc.returncode != 0 and "||" not in c:
                return ActionResult(step, adapter, target, True, False, f"failed: {c}: {proc.stderr.strip()}")
        return ActionResult(step, adapter, target, True, True, f"isolated locally ({len(cmds)} rules)")
