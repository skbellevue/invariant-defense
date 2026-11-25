import base64
from datetime import date

from conftest import rule_ids

from invariant.events import Event
from invariant.identity.credentials import audit_credentials
from invariant.identity.jwt_audit import audit_jwt, b64url_encode, sign_hs

NACOS_69 = "SecretKey012345678901234567890123456789012345678901234567890123456789"
NACOS_68 = "SecretKey01234567890123456789012345678901234567890123456789012345678"


def test_default_key_raw_and_base64_decoded(cfg):
    secrets = cfg.get("identity.default_jwt_secrets")
    t1 = sign_hs({"alg": "HS256"}, {"sub": "nacos", "iat": 0, "exp": 100}, NACOS_69.encode())
    t2 = sign_hs({"alg": "HS256"}, {"sub": "nacos", "iat": 0, "exp": 100}, base64.b64decode(NACOS_68))
    for t in (t1, t2):
        r = audit_jwt(t, secrets, now=50)
        assert r.default_secret and r.worst() == "critical" and r.subject == "nacos"


def test_unknown_key_not_flagged(cfg):
    t = sign_hs({"alg": "HS256"}, {"sub": "u", "iat": 0, "exp": 600}, b"a-real-random-secret-0f9e8d7c6b5a")
    r = audit_jwt(t, cfg.get("identity.default_jwt_secrets"), now=10)
    assert not r.default_secret and r.worst() == "info"


def test_alg_none_and_no_expiry():
    h = b64url_encode(b'{"alg":"none"}')
    p = b64url_encode(b'{"sub":"admin"}')
    r = audit_jwt(f"{h}.{p}.", [])
    assert r.unsigned and r.no_expiry and r.worst() == "critical"


def test_long_lifetime():
    t = sign_hs({"alg": "HS256"}, {"sub": "u", "iat": 0, "exp": 86400}, b"k" * 32)
    r = audit_jwt(t, [], max_lifetime_s=3600, now=1)
    assert any("lifetime" in m for _, m in r.findings)


def test_forged_token_then_admin_creation_escalates(run):
    tok = sign_hs({"alg": "HS256"}, {"sub": "nacos", "iat": 0, "exp": 3000}, NACOS_69.encode())
    evs = [
        Event("auth", 10, "nacos-01", "nacos", fields={"token": tok, "service": "nacos"}),
        Event(
            "account_change",
            40,
            "nacos-01",
            "nacos",
            fields={"target_user": "backdoor", "role": "ROLE_ADMIN"},
        ),
    ]
    alerts = run(evs)
    assert "INV-L4-001" in rule_ids(alerts)
    admin = [a for a in alerts if a.rule_id == "INV-L4-006"][0]
    assert admin.severity == "critical" and admin.evidence["after_forged_token"]


def test_spoofed_nacos_user_agent(cfg, run):
    ev = Event(
        "http_request",
        1,
        "nacos-01",
        src_ip="10.9.9.9",
        url="/nacos/v1/cs/configs",
        user_agent="Nacos-Server",
    )
    assert "INV-L4-004" in rule_ids(run([ev]))
    cfg.data["identity"]["trusted_cluster_ips"] = ["10.9.9.9"]
    assert "INV-L4-004" not in rule_ids(run([ev], cfg))


def test_session_replay(run):
    evs = [
        Event("auth", 1, "idp", "alice", fields={"token_id": "s1", "device_id": "laptop-a"}),
        Event("auth", 60, "idp", "alice", fields={"token_id": "s1", "device_id": "vps-x"}),
    ]
    assert "INV-L4-005" in rule_ids(run(evs))


def test_default_account_login(run):
    ev = Event("auth", 1, "minio-01", "minioadmin", fields={"service": "minio", "outcome": "success"})
    assert "INV-L4-007" in rule_ids(run([ev]))


def test_credential_audit():
    creds = [
        {
            "name": "gemini-prod",
            "kind": "api_key",
            "provider": "google",
            "created": "2025-01-01",
            "owner": "ml-team",
        },
        {
            "name": "agent-sa",
            "kind": "service_account",
            "used_by_agent": True,
            "scopes": ["admin"],
            "rotated": "2026-11-01",
            "expires": "2026-12-01",
            "owner": "platform",
        },
        {"name": "minio-root", "kind": "access_key", "default": True},
    ]
    rules = {(f.credential, f.rule) for f in audit_credentials(creds, 90, today=date(2026, 11, 24))}
    assert ("gemini-prod", "INV-CRED-AGE") in rules
    assert ("gemini-prod", "INV-CRED-NOEXPIRY") in rules
    assert ("gemini-prod", "INV-CRED-REVOKE") in rules
    assert ("agent-sa", "INV-CRED-AGENCY") in rules
    assert ("minio-root", "INV-CRED-DEFAULT") in rules
    assert ("minio-root", "INV-CRED-OWNER") in rules
