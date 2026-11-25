# Deployment guide

## 1. Telemetry by platform

| Platform | Source | Events needed | Mapper |
|---|---|---|---|
| Windows | Sysmon 15 + `deploy/sysmon-invariant.xml` via Winlogbeat/NXLog/Vector | 1, 3, 11, 22, 23 | `--format sysmon` |
| Linux | auditd (execve, connect), eBPF agents (Tetragon, Falco JSON output) → JSONL | process_start, network_connect, file_* | write a 20-line mapper to `Event` |
| macOS | Endpoint Security clients (e.g. Santa, commercial EDR export) → JSONL | exec, network, file | same |
| AI gateway | LiteLLM / Envoy / API gateway access logs | http_request with `api_key_fp` = sha256 prefix of the key | JSONL |
| Web/WAF | access logs of AI platforms (Langflow, Nacos) | http_request with `user_agent`, `src_ip`, `url` | JSONL |
| IdP / apps | sign-in logs | auth with `token_id`, `device_id`, `outcome`; never log raw tokens in production, log `token_fp` | JSONL |
| Databases | pgAudit, MariaDB server_audit, MySQL Enterprise Audit | sql with `statement`, `rows`, `session`, `table` | JSONL |

Normalized JSONL example (one object per line):

```json
{"kind":"network_connect","ts":"2026-11-20T09:00:06Z","host":"WS-FIN-042","pid":5100,"image":"C:\\Windows\\System32\\wscript.exe","dst_host":"generativelanguage.googleapis.com","dst_port":443,"signed":false}
```

## 2. Egress architecture

1. Stand up one AI gateway (LiteLLM, an API gateway, or your cloud provider's private endpoints). Issue provider
   keys only to the gateway; workloads authenticate to the gateway with short-lived, workload-bound credentials.
2. At the proxy/firewall, allow LLM endpoints only from the gateway: `invariant catalog --format squid`.
   At DNS, answer NXDOMAIN to non-gateway clients: `invariant catalog --format rpz` (pair with a gateway view).
3. Keep logging attempts from everywhere else: those attempts are INV-L2-001 alerts with process attribution
   from the endpoint telemetry.

## 3. Response wiring

| Step | Recommended adapter | Notes |
|---|---|---|
| isolate | `webhook` → SOAR → EDR containment API | keep the management channel open; Linux fallback `iptables` runs locally as root |
| revoke | `command` → script that calls your key registry / provider admin API / IdP session revocation | approval required by default |
| snapshot | `webhook` → forensic collection + `invariant snapshot create` on config exports | |
| notify | `webhook` → paging/ChatOps | |

Approval with ChatOps: set `approval: file`; a bot posts the `*.request.json` to the channel and writes
`<id>.approved` when an authorized responder clicks approve.

## 4. Databases

* PostgreSQL: run `rules/sql/postgres_impact_guard.sql` as superuser, then `SELECT invariant.protect('schema.table');`
  for each configuration/metadata table. Ship the server log; alert on lines containing `invariant:`.
* MySQL/MariaDB (Nacos): run `rules/sql/mysql_impact_guard.sql` in the Nacos schema, then remove DROP/ALTER from the
  runtime account. Alert on SQLSTATE 45000 messages starting with `invariant:` in the audit log.
* Back up configuration stores offline and immutably (object lock or offline media). Measure restore time
  with `invariant snapshot restore-test` monthly.

## 5. Rollout plan

| Week | Do | Exit criterion |
|---|---|---|
| 1-2 | Inventory (estate YAML), egress logging only, `hunt` on golden images and repos | every LLM-calling process has an owner |
| 3-4 | Sigma rules in SIEM in alert-only mode, canaries on file shares, SQL guards in staging | false-positive rate reviewed |
| 5-8 | Gateway enforcement for servers, response loop dry-run with file approvals | tabletop completed |
| 9-12 | Enforce isolate on high-confidence rules (L3-001, L3-006, L5-001, L5-002) | time-to-contain measured in minutes |
