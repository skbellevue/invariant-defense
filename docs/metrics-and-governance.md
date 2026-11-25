# Metrics and governance

Stop citing known-sample detection rate as protection against AI-enabled threats. Track:

| Metric | Source in this repo | Target |
|---|---|---|
| Time to contain (alert → isolation) | `report.metrics()["hosts"][h]["time_to_contain_s"]` | minutes |
| Time to detect (first evidential event → alert) | same | seconds to minutes (plus ingestion lag) |
| AI egress telemetry coverage | `exposure` → `egress_telemetry_coverage` | > 95 % of hosts |
| LLM-calling processes with an owner | `expected_llm_processes` vs. INV-L2-001 volume | 100 % |
| Patch age of internet-facing AI platforms | `INV-PATCH-AGE` | ≤ 7 days |
| Default/unrotated secrets | `INV-CRED-*`, `INV-*-DEFAULT-*` | zero criticals |
| Config-store restore time | `snapshot restore-test` → `restore_seconds` | tested monthly |
| ATT&CK techniques covered by behavior analytics | `report.metrics()["attack_techniques"]` | growing quarter on quarter |

## Ownership (assign names, not teams)

* Egress allow-list and AI gateway
* Provider key inventory and pre-agreed revocation path with each provider
* AI-estate inventory (exposure)
* Response playbooks and approvers

## Procurement questions for vendors

1. Can you attribute every LLM-endpoint session to a process, signer and user?
2. Do you alert when a freshly generated script runs, independent of its hash?
3. How do you protect your own AI-assisted analysis from prompt injection embedded in samples?
4. Can your containment API be called by our SOAR within seconds, and is it reversible?
