# Architecture

```
            ┌──────────────── telemetry ─────────────────┐
 Sysmon/EDR │ process, network, DNS, file                │
 Proxy/GW   │ http_request (+ api_key_fp)                │──► collectors ──► Event (normalized)
 IdP/apps   │ auth, account_change                       │                        │
 DB audit   │ sql                                        │                        ▼
 Agents     │ agent_claim                                │              ┌──────────────────┐
            └────────────────────────────────────────────┘              │  Engine          │
                                                                        │  ProcessTree     │
 ai-estate.yaml ──► L1 exposure (batch) ──► findings                    │  Context:        │
 files/repos   ──► L2 hunt (batch)      ──► fingerprints ─┐             │   llm_contacts   │
                                                          │             │   contained      │
                                                          ▼             │ L2 → L3 → L4 → L5│
                                              egress.known_bad_key_fps  └────────┬─────────┘
                                                          ▲                      │ Alert
                                                          │                      ▼
                                                 learned config ◄──── ResponseLoop (isolate, revoke*,
                                                                      snapshot, notify, verify)
                                                                      * human approval
```

## Design choices

**One schema.** Detectors only see `Event`. Adding a telemetry source means writing a mapper, never touching
detection logic.

**Cross-layer context.** The L2 egress detector records every model contact per `(host, pid)`, marked sanctioned
or not. L3 detectors ask "did this process or any ancestor make an unsanctioned model call in the last N
seconds?" That single question is what turns "cmd.exe ran whoami" (noise) into "the reply from a model was
executed" (critical).

**Sanctioned agents are not alerts.** A developer's coding assistant asking a model and running `pytest` is the
product working. Sanctioned contacts are excluded from escalation by default; the allow-list is where that
judgment lives, with an owner.

**Streaming, bounded memory.** Each detector keeps sliding windows or bounded maps. The engine sorts a batch by
time; in live mode events are fed as they arrive.

**Dedupe by fingerprint.** `(rule, host, dedupe_key)`; repeats increment `evidence.repeat_count`.

**Response is a callback.** The loop runs inside `on_alert`, so containment happens at alert time, not after a
batch. Steps marked `approve` wait for a human (`deny`, `prompt`, or `file` for ChatOps bridges).

**Verify, don't trust.** Agent narration is a lead. `verify_claims` checks each claim against telemetry
(exfiltration needs outbound volume to the claimed destination). `verify_containment` checks that isolated
hosts actually went quiet.

## Extending

* New telemetry: add `collectors/<source>.py` returning `Event`s; register in `collectors/__init__.py`.
* New detector: subclass `engine.Detector`, set `layer`, implement `process()` (and `finish()` for batch analytics),
  add it to the layer's `*_detectors()` factory, add a test in `tests/` and a row in `docs/detection-catalog.md`.
* New provider: add it to `data/llm-endpoints.yaml` (and the Sysmon/Sigma lists).
* New platform CVE or misconfiguration: add to `data/vulndb.yaml`.
* New response adapter: extend `response/actions.py`; keep dry-run the default.
