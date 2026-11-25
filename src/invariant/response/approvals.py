"""Human sign-off for irreversible steps.

Modes:
* ``deny``   never auto-approve; the step is queued as 'pending' (default, safe for pipelines)
* ``prompt`` ask on the terminal (interactive use)
* ``file``   write a request JSON to ``approval_dir`` and approve only if a matching
             ``<id>.approved`` file exists (bridge to ChatOps: a bot writes the file)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from invariant.alerts import Alert


class ApprovalGate:
    def __init__(self, mode: str = "deny", approval_dir: str = "./approvals"):
        self.mode = mode
        self.dir = Path(approval_dir)

    def request_id(self, step: str, alert: Alert) -> str:
        return f"{alert.fingerprint}-{step}"

    def approve(self, step: str, alert: Alert) -> tuple[bool, str]:
        rid = self.request_id(step, alert)
        if self.mode == "prompt" and sys.stdin.isatty():
            ans = input(f"\nAPPROVE '{step}' for {alert.rule_id} on {alert.host}? [y/N] ").strip().lower()
            return ans in ("y", "yes"), "approved at terminal" if ans in (
                "y",
                "yes",
            ) else "declined at terminal"
        if self.mode == "file":
            self.dir.mkdir(parents=True, exist_ok=True)
            req = self.dir / f"{rid}.request.json"
            if not req.exists():
                req.write_text(
                    json.dumps({"id": rid, "step": step, "alert": alert.to_dict()}, indent=2, default=str)
                )
            if (self.dir / f"{rid}.approved").exists():
                return True, f"approved via {rid}.approved"
            return False, f"pending: create {self.dir / (rid + '.approved')} to approve"
        return False, "pending human approval (approval mode: deny)"
