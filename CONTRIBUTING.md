# Contributing

1. `pip install -e ".[dev]"`
2. Add or change a detector with a test that fails before your change (`tests/`).
3. Keep detections explainable: every alert carries `description`, ATT&CK ids and evidence a responder can act on.
4. If you model a new campaign, add a synthetic scenario to `src/invariant/simulate.py`, cite public sources in
   `docs/sources.md`, and use documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and
   bracketed placeholders, never real attacker infrastructure or payloads.
5. `make lint test rules` must pass. Database guards: `make db-test` with local PostgreSQL and MariaDB.
6. Update `docs/detection-catalog.md`.
