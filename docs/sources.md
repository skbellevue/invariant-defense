# Sources

Detection logic and simulations are informed by public reporting. Paraphrased; see originals for detail.

* Google Threat Intelligence Group, *GTIG AI Threat Tracker: Advances in Threat Actor Usage of AI Tools*, 5 Nov 2025 — PROMPTFLUX, PROMPTSTEAL/LAMEHUG, QUIETVAULT, FRUITSHELL, PROMPTLOCK. https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools
* SentinelLABS, *LLM-Enabled Malware in the Wild* (LABScon 2025) — key and prompt hunting, MalTerminal. https://www.sentinelone.com/labs/labscon25-replay-llm-enabled-malware-in-the-wild/
* Trend Micro, *The Signs Were There: What the First Autonomous Ransomware Case Confirms*, 24 Jul 2026 — JADEPUFFER chain (Sysdig research). https://www.trendmicro.com/en_us/research/26/g/autonomous-ransomware.html
* NVD, CVE-2025-3248 (Langflow < 1.3.0). https://nvd.nist.gov/vuln/detail/CVE-2025-3248
* GitHub Security Lab, GHSL-2020-325/326 (Nacos auth bypass, CVE-2021-29441, fixed 1.4.1). https://securitylab.github.com/advisories/GHSL-2020-325_326-nacos/
* NVD, CVE-2021-43116 (Nacos default JWT key). https://nvd.nist.gov/vuln/detail/CVE-2021-43116
* Alibaba Cloud, *Important Nacos vulnerabilities* — default `token.secret.key` and `server.identity` remediation. https://help.aliyun.com/en/acsg/nacos-high-risk-vulnerability
* CISA, Known Exploited Vulnerabilities catalog and JSON feed. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
* Check Point Research, *Caught in the Hook: RCE and API Token Exfiltration Through Claude Code Project Files*, 25 Feb 2026 (CVE-2025-59536, CVE-2026-21852). https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/
* Snyk, *Weaponizing AI Coding Agents for Malware in the Nx Malicious Package*, 27 Aug 2025 — s1ngularity AI-CLI abuse and shell-profile tampering (macOS replay). https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package
* StepSecurity, *s1ngularity: Popular Nx Build System Package Compromised*, Aug 2025. https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware
* Apple, eslogger(1) manual (macOS 13+): JSON modeled on es_message_t, no schema guarantee, root + Full Disk Access required. https://keith.github.io/xcode-man-pages/eslogger.1.html
* Apple, NEFilterSocketFlow (remoteHostname, remoteFlowEndpoint) and NEFilterFlow (sourceAppAuditToken) documentation. https://developer.apple.com/documentation/networkextension/nefiltersocketflow
* Apple Developer Forums, NEFilterSocketFlow remoteHostname is often nil; audit-token availability. https://developer.apple.com/forums/thread/679860
* XcodeGen project spec (system-extension product type, local packages). https://yonaskolb.github.io/XcodeGen/Docs/ProjectSpec.html
* MITRE ATT&CK T1027.014 Polymorphic Code. https://attack.mitre.org/techniques/T1027/014/
* Key formats: public secret-scanning rule sets (gitleaks, GitLab secret detection) and provider documentation.
