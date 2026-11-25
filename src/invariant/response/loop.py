"""The response loop wired into the engine via ``on_alert``.

1. alert on an invariant          (engine)
2. auto-isolate the host           (reversible: automatic)
3. revoke keys and tokens          (blast radius: approval by default)
4. human approves high-impact steps
5. verify, don't trust             (claims and containment checked against telemetry)
6. feed new analytics back         (learned IOCs/keys exported for L1-L5 config)
"""

from __future__ import annotations

from typing import Any

from invariant.alerts import Alert, sev_at_least
from invariant.engine import Context
from invariant.response.actions import ActionResult, Actions
from invariant.response.approvals import ApprovalGate


class ResponseLoop:
    def __init__(self, response_cfg: dict[str, Any]):
        self.cfg = response_cfg
        self.actions = Actions(response_cfg)
        self.gate = ApprovalGate(
            response_cfg.get("approval", "deny"), response_cfg.get("approval_dir", "./approvals")
        )
        self.min_sev = response_cfg.get("min_severity", "high")
        self.playbooks: list[dict[str, Any]] = response_cfg.get("playbooks", []) or []
        self.log: list[dict[str, Any]] = []
        self.learned: dict[str, set[str]] = {"key_fps": set(), "token_fps": set(), "destinations": set()}

    def _playbook(self, alert: Alert) -> dict[str, Any] | None:
        for pb in self.playbooks:
            m = pb.get("match", {})
            if "layers" in m and alert.layer not in m["layers"]:
                continue
            if "rules" in m and alert.rule_id not in m["rules"]:
                continue
            return pb
        return None

    def __call__(self, alert: Alert, ctx: Context) -> None:
        if not sev_at_least(alert.severity, self.min_sev):
            return
        pb = self._playbook(alert)
        if not pb:
            return
        # step 6: learn
        for k in ("key_fp",):
            if alert.evidence.get(k):
                self.learned["key_fps"].add(alert.evidence[k])
        if alert.evidence.get("token_fp"):
            self.learned["token_fps"].add(alert.evidence["token_fp"])
        if alert.evidence.get("destination") and alert.layer in ("L2", "L3"):
            self.learned["destinations"].add(str(alert.evidence["destination"]))

        for step in pb.get("steps", []):
            if step == "verify":
                continue  # verification runs after the stream (needs later telemetry)
            if step == "isolate" and alert.host in ctx.contained:
                continue
            if step in pb.get("approve", []):
                ok, why = self.gate.approve(step, alert)
                if not ok:
                    rec = ActionResult(step, "approval", alert.host, False, False, why, ts=alert.ts)
                    alert.actions.append(rec.to_dict())
                    self.log.append({"alert": alert.rule_id, "playbook": pb["name"], **rec.to_dict()})
                    continue
            res = self.actions.run(step, alert)
            res.ts = alert.ts  # simulated clock: the loop acts at alert time
            alert.actions.append(res.to_dict())
            self.log.append({"alert": alert.rule_id, "playbook": pb["name"], **res.to_dict()})
            if step == "isolate" and res.ok:
                ctx.contained.setdefault(alert.host, alert.ts)

    def learned_config(self) -> dict[str, Any]:
        """YAML-ready snippet to merge into your config (step 6: feed analytics back)."""
        return {
            "egress": {"known_bad_key_fps": sorted(self.learned["key_fps"])},
            "notes": {
                "forged_or_abused_token_fps": sorted(self.learned["token_fps"]),
                "destinations_to_review": sorted(self.learned["destinations"]),
            },
        }
