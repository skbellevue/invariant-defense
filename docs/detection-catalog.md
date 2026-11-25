# Detection catalog

Every detector targets a requirement the attack cannot regenerate away. Severity escalates when evidence from
two invariants coincides (for example a behavior detector whose process tree also made an unsanctioned model call).

## L2 · Model dependency

| ID | Detects | Severity | ATT&CK | Data | Tuning |
|---|---|---|---|---|---|
| INV-L2-001 | Process outside the egress allow-list reaches an LLM endpoint | critical (script host/LOLBin + unsigned), high (script host or unsigned), medium | T1071.001, T1027.014 | network_connect, dns_query, http_request | `egress.allow`, `egress.high_risk_processes` |
| INV-L2-002 | One API key fingerprint used from ≥2 hosts | high | T1552.001, T1496 | AI gateway / TLS proxy logs with `api_key_fp` | bind keys to workloads |
| INV-L2-003 | Key found by hunting is presented to a provider | critical | T1552.001, T1496 | gateway logs | `egress.known_bad_key_fps` (from `invariant hunt`) |
| INV-L2-004 | Low-jitter periodic model calls from one process | high | T1027.014, T1071.001 | network_connect | `egress.beacon.*` |

Static hunting (`invariant hunt`, `rules/yara`): `HUNT-LLM-EXEC`, `HUNT-LLM-EVASION`, `HUNT-LLM-HARMFUL`,
`HUNT-ANALYST-INJECTION`, `HUNT-EMBEDDED-KEY`, `HUNT-KEY`, `HUNT-PROMPT`; AI-assistant configs: `AICFG-HOOK-NET`,
`AICFG-HOOK`, `AICFG-BASEURL`, `AICFG-LITERAL-KEY`, `AICFG-BYPASS`, `AICFG-ALLOW-ALL`, `AICFG-MCP-AUTOAPPROVE`,
`AICFG-MCP-NET`, `AICFG-MCP-UNPINNED`, `AICFG-MCP-REMOTE`.

## L3 · Behavior

| ID | Detects | Severity | ATT&CK | Modeled on |
|---|---|---|---|---|
| INV-L3-001 | Process (or ancestor) made an unsanctioned model call, then spawned a shell/interpreter within the window | critical | T1059, T1027.014 | LAMEHUG/PROMPTSTEAL, PromptLock |
| INV-L3-002 | Script written minutes ago is executed (writer not a dev tool) | high; critical with model call | T1059 | generated-code loaders |
| INV-L3-003 | One script rewritten into ≥3 distinct hashes (self-referencing or model-fed) | high; critical with model call | T1027.014 | PROMPTFLUX hourly rewrite |
| INV-L3-004 | Script/binary written to an autostart location | medium → critical | T1547.001, T1053 | PROMPTFLUX Startup copy |
| INV-L3-005 | Script copied to removable media or a share | high | T1091 | PROMPTFLUX propagation |
| INV-L3-006 | App server (Langflow, Nacos, Flowise, n8n…) spawns shell/downloader/decoder | high; critical with decode or pipe-to-shell | T1190, T1059, T1140 | JADEPUFFER initial access |
| INV-L3-007 | ≥4 distinct discovery commands from one driver process within 120 s | medium; critical with model call | T1082, T1016, T1033, T1057 | LAMEHUG one-liners |
| INV-L3-008 | ≥15 documents written into one directory within 10 min | medium; high with model call | T1074.001 | LAMEHUG `C:\ProgramData\info` |
| INV-L3-009 | AI CLI started by an unexpected parent or with secret-hunting prompt + approval bypass | high / critical | T1059, T1552.001 | QUIETVAULT |
| INV-L3-010 | Low-jitter periodic connections to a non-model destination | high | T1071.001, T1053 | JADEPUFFER 30-minute beacon |
| INV-L3-011 | Natural-language agent narration in a command, script or SQL | low (lead only) | T1059 | JADEPUFFER "High-ROI" comments |

## L4 · Identity

| ID | Detects | Severity | ATT&CK |
|---|---|---|---|
| INV-L4-001 | Bearer token verifies with a public default secret (e.g. Nacos `token.secret.key`) | critical | T1606, T1078 |
| INV-L4-002 | Token without expiry or longer than policy | medium | T1550 |
| INV-L4-003 | Unsigned token (`alg: none`) | critical | T1606 |
| INV-L4-004 | `Nacos-Server` User-Agent from a non-cluster address (CVE-2021-29441) | critical | T1190, T1550 |
| INV-L4-005 | Session token used from a second device/address within 15 min | high | T1550, T1606.001 |
| INV-L4-006 | Privileged account created/elevated; critical within 1 h of a forged token on the same service | high / critical | T1136, T1078 |
| INV-L4-007 | Successful login with a vendor default account | critical | T1078.001 |

Inventory audit (`invariant creds`): `INV-CRED-DEFAULT`, `INV-CRED-AGE`, `INV-CRED-NOEXPIRY`, `INV-CRED-EXPIRED`,
`INV-CRED-AGENCY` (agent identity with admin scopes), `INV-CRED-OWNER`, `INV-CRED-UNBOUND`, `INV-CRED-REVOKE`.

## L5 · Impact

| ID | Detects | Severity | ATT&CK |
|---|---|---|---|
| INV-L5-001 | Canary file modified/renamed/deleted (or canary table read, via SQL guard log) | critical | T1486, T1485 |
| INV-L5-002 | ≥50 renames/deletes/high-entropy writes by one process in 60 s | critical | T1486, T1485 |
| INV-L5-003 | DROP/TRUNCATE (critical on protected tables) | high / critical | T1485 |
| INV-L5-004 | ≥200 rows UPDATE/DELETE on one table by one session in 120 s | high / critical | T1486, T1485 |

The SQL guards in `rules/sql` enforce L5-003/004 inside the database itself and log `invariant:` lines.

## L1 · Exposure

Built-in knowledge (`src/invariant/data/vulndb.yaml`): CVE-2025-3248 (Langflow < 1.3.0, KEV), CVE-2021-29441
(Nacos < 1.4.1), CVE-2021-43116 (Nacos ≤ 2.0.3 default JWT key), and misconfigurations: MinIO default root,
Nacos default token key / identity / auth disabled, Langflow auto-login on reachable instances, Ollama bound to
all interfaces, any internet-facing service without auth. Plus `INV-PATCH-AGE` and `INV-NO-OWNER`.
Supply the CISA KEV feed with `--kev` to make KEV status authoritative.
