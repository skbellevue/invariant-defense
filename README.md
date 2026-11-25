# invariant-defense

**Detect AI-enabled malware by what it must do, not by what it looks like.**

`invariant-defense` is an open-source reference implementation of the **Invariant Defense Model**, described in
[*Signatures Can't Catch What Rewrites Itself: A Defense Model for AI-Enabled Malware*](https://kameni.com/blog/signatures-cant-catch-what-rewrites-itself-a-defense-model-for-ai-enabled-malwar-ktv4n).

Malware that asks a language model for its next command, or rewrites its own source every hour, leaves no stable
artifact for a signature to match. But AI lets an attacker change the **form** of an attack cheaply, not its
**requirements**. Whatever the code looks like, the attack still:

| Layer | Invariant | Control in this repo |
|---|---|---|
| **L0** | (cheap filter) | Signatures and reputation are kept; YARA rules for keys/prompts live in `rules/yara` |
| **L1** | needs a way in | `invariant exposure`: AI-platform inventory vs. CVEs, CISA KEV, default secrets, patch age |
| **L2** | must reach a model | AI egress allow-list, LLM endpoint catalog, beacon analytics, key reuse; `invariant hunt` for embedded keys and prompts |
| **L3** | must run on a host | process-lineage analytics: model-reply-executed, generated scripts, self-rewrite, persistence, app-server shells, recon bursts, staging, AI-CLI abuse |
| **L4** | must borrow privilege | JWT forgery with public default keys, spoofed service User-Agents, session replay, backdoor admins, credential age and least agency |
| **L5** | must touch data | canary files and tables, destructive-rate limits, SQL guards for PostgreSQL and MySQL, verified config snapshots |
| **Loop** | speed is a control | isolate automatically, revoke with approval, verify agent self-reports against telemetry, feed learned indicators back |

Everything runs on the Python standard library plus PyYAML. `yara-python` and `psutil` are optional.

> **Status.** Reference implementation for learning, labs and as a starting point for production engineering.
> The detections are deliberately transparent and tested against synthetic telemetry modeled on public reporting.
> Tune thresholds and allow-lists for your environment before you let the response loop execute anything.

---

## Quick start

```bash
git clone https://github.com/<you>/invariant-defense && cd invariant-defense
pip install -e ".[dev]"          # or: pip install .   (runtime only)
invariant demo --respond          # replay four scenarios through every layer, dry-run response
pytest -o addopts="" -q           # 75 tests
```

The demo replays synthetic telemetry (no malware, no real keys, documentation IP ranges only):

| Scenario | Modeled on | What fires |
|---|---|---|
| `promptflux` | VBScript dropper asking Gemini to rewrite it hourly (GTIG, Nov 2025) | L2 egress, periodic model calls, self-rewrite, Startup persistence, removable-media spread |
| `lamehug` | Python stealer asking a Qwen model on Hugging Face for recon commands (CERT-UA/GTIG, 2025) | L2 egress, **model reply executed**, recon burst, document staging |
| `jadepuffer` | LLM-agent intrusion: Langflow RCE, MinIO defaults, forged Nacos token, config encryption (Sysdig via Trend Micro, Jul 2026) | app-server shell, recon, beacon, default login, UA bypass, forged token, backdoor admin, mass SQL rewrite, DROP; agent claims verified |
| `benign` | developer using sanctioned AI tools | nothing (false-positive control) |

Note what `jadepuffer` teaches: the victim never contacted a model (the agent ran elsewhere), so L2 is blind and
the other four invariants carry the detection. Defense in depth is not a slogan here; it is the design.

---

## Commands

```bash
# Detection on your telemetry (normalized JSONL or Sysmon JSON / Winlogbeat)
invariant detect --events telemetry.jsonl --respond --json report.json --learned learned.yaml
invariant detect --events sysmon.json --format sysmon --fail-on high      # CI / pipeline gate

# L1 exposure: inventory vs. vulnerabilities, KEV, defaults, patch age
invariant kev-sync -o kev.json
invariant exposure --estate config/ai-estate.example.yaml --kev kev.json
invariant probe --estate my-estate.yaml --i-own-these-targets             # read-only version check

# L2 hunting: embedded provider keys, prompts-as-code, risky AI-assistant configs
invariant hunt ./samples ./repos --yara-dir rules/yara --json hunt.json
invariant catalog --format squid       # proxy ACL: LLM endpoints only via your AI gateway
invariant catalog --format rpz         # DNS response-policy zone

# L4 identity
invariant jwt "$TOKEN"                 # default-key forgery, alg none, lifetime
invariant creds --estate config/ai-estate.example.yaml

# L5 impact
invariant canary deploy /srv/share /home/finance --manifest canaries.json
invariant canary watch --manifest canaries.json --respond
invariant snapshot create /exports/nacos --dest /mnt/worm --label nacos
invariant snapshot restore-test /mnt/worm/nacos-20261124T000000Z --scratch /tmp/restore

# Live, agentless (samples connections every N seconds; needs psutil)
invariant live --interval 5
```

Exit codes: `0` clean, `2` findings at or above the threshold (`--fail-on`, or high/critical for `hunt`, `exposure`, `creds`, `jwt`).

---

## Repository layout

```
src/invariant/
  events.py, engine.py, lineage.py      normalized schema, streaming engine, process tree
  egress/      L2  catalog, allow-list policy, egress / key-use / beacon detectors
  hunt/        L2  key patterns, prompt analysis, AI-assistant config audit, scanner (+YARA)
  behavior/    L3  ten technique detectors
  identity/    L4  JWT audit, token/UA/session/account detectors, credential inventory audit
  impact/      L5  canaries, destructive-rate and SQL detectors, snapshots
  exposure/    L1  inventory evaluation, KEV, version logic, opt-in probes
  response/        loop, action adapters (log/iptables/webhook/command), approvals, verification
  collectors/      JSONL, Sysmon/Winlogbeat, live psutil
  data/            defaults.yaml, llm-endpoints.yaml, vulndb.yaml
rules/
  yara/        provider keys, query-then-execute, self-rewrite, analyst prompt injection, ransomware prompts
  sigma/       8 rules (validated with pySigma, convert to Splunk/Elastic/Sentinel)
  osquery/     5 hunting queries
  sql/         PostgreSQL and MySQL/MariaDB impact guards (integration-tested)
deploy/        Sysmon config fragment
config/        example AI-estate inventory and override config
tests/         75 unit and end-to-end tests + SQL integration tests
docs/          architecture, detection catalog, deployment, governance metrics, sources
```

## Deploying

See [docs/deployment.md](docs/deployment.md). In short:

1. **Telemetry.** Windows: Sysmon with `deploy/sysmon-invariant.xml` merged in. Linux: auditd/eBPF exporter to JSONL.
   macOS: Endpoint Security-based agent to JSONL. Proxy/AI-gateway logs as `http_request`. Database audit logs as `sql`.
2. **Policy.** Write your egress allow-list (`config/invariant.example.yaml`). Route all sanctioned model traffic
   through one AI gateway; everything else reaching a provider is either shadow AI or malware.
3. **Inventory.** Fill in `ai-estate.yaml`, run `exposure` and `creds` weekly, fix criticals in days.
4. **Rules.** Load `rules/sigma` into your SIEM, `rules/yara` into retrohunting, the SQL guards into config databases.
5. **Response.** Start dry-run with `approval: file`. Wire `isolate` to your EDR's containment API through a webhook,
   `revoke` to your key registry. Exercise it in a tabletop before setting `dry_run: false`.

## Detection catalog

Full table with ATT&CK mappings and tuning notes: [docs/detection-catalog.md](docs/detection-catalog.md).

## Security and responsible use

This is defensive software. The simulator emits telemetry records, not payloads. Probing is opt-in, read-only
and gated behind `--i-own-these-targets`. Response actions are dry-run by default and irreversible steps require
human approval. Report vulnerabilities in this project as described in [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
