# Security policy

## Reporting a vulnerability in this project

Please open a private security advisory on GitHub (Security → Report a vulnerability) rather than a public
issue. Include a description, affected version and reproduction steps. Expect an acknowledgement within
5 business days.

## Scope and safe use

* This project is defensive. The simulator writes telemetry records only; it contains no payloads.
* `invariant probe` performs unauthenticated, read-only GET requests and refuses to run without
  `--i-own-these-targets`. Only probe systems you own or are authorized to test.
* Response actions default to dry-run. Irreversible steps require human approval.
* Never commit real provider keys. Tests assemble fake keys at runtime so secret scanners stay quiet.
* Logs produced by the platform redact secrets and use fingerprints (`sha256:` prefix) instead.
