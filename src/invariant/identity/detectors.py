"""L4 detectors: borrowed privilege.

INV-L4-001  token signed with a public default secret (forged credential)
INV-L4-002  token with no expiry or excessive lifetime
INV-L4-003  unsigned token (alg none)
INV-L4-004  spoofed service User-Agent used to bypass authentication (e.g. Nacos CVE-2021-29441)
INV-L4-005  session token replayed from a new device / address
INV-L4-006  privileged account created or elevated
INV-L4-007  successful login with a vendor default account
"""

from __future__ import annotations

from collections import defaultdict

from invariant.alerts import Alert
from invariant.config import Config
from invariant.engine import Context, Detector
from invariant.events import Event
from invariant.identity.jwt_audit import audit_jwt
from invariant.util import fingerprint_secret, glob_any

DEFAULT_ACCOUNTS = {"minioadmin", "nacos", "admin", "root", "elastic", "neo4j", "postgres", "guest", "sa"}


class TokenAuditDetector(Detector):
    layer = "L4"
    name = "token-audit"

    def __init__(self, config: Config):
        idc = config.section("identity")
        self.secrets = idc.get("default_jwt_secrets", [])
        self.max_lifetime = float(idc.get("max_token_lifetime_s", 3600))
        self.forged_hosts: dict[str, float] = {}

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        token = ev.fields.get("token")
        if ev.kind not in ("auth", "http_request") or not token:
            return []
        r = audit_jwt(str(token), self.secrets, self.max_lifetime, now=ev.ts)
        if not r.valid_format:
            return []
        tfp = fingerprint_secret(str(token))
        base_ev = {"subject": r.subject, "alg": r.alg, "token_fp": tfp, "service": ev.fields.get("service")}
        out: list[Alert] = []
        if r.default_secret:
            self.forged_hosts[ev.host] = ev.ts
            out.append(
                Alert(
                    "INV-L4-001",
                    f"Token for '{r.subject}' is signed with a public default key",
                    "critical",
                    "L4",
                    ev.host,
                    ev.ts,
                    "The signing key is published in vendor defaults, so the token can be minted by anyone. "
                    "JADEPUFFER forged a Nacos admin token this way. Rotate the key; every token it signed is suspect.",
                    ["T1606", "T1078"],
                    {**base_ev, "dedupe_key": tfp},
                    [ev],
                )
            )
        if r.unsigned:
            out.append(
                Alert(
                    "INV-L4-003",
                    "Unsigned (alg none) token accepted",
                    "critical",
                    "L4",
                    ev.host,
                    ev.ts,
                    "A service accepted a token without a signature.",
                    ["T1606"],
                    {**base_ev, "dedupe_key": tfp},
                    [ev],
                )
            )
        if r.no_expiry or (r.lifetime_s and r.lifetime_s > self.max_lifetime):
            out.append(
                Alert(
                    "INV-L4-002",
                    f"Long-lived token in use for '{r.subject}'"
                    + (" (no expiry)" if r.no_expiry else f" ({r.lifetime_s / 3600:.0f} h)"),
                    "medium",
                    "L4",
                    ev.host,
                    ev.ts,
                    "Stolen access is only as valuable as it is durable. Policy is short, device-bound tokens.",
                    ["T1550"],
                    {
                        **base_ev,
                        "lifetime_s": r.lifetime_s,
                        "dedupe_key": f"life|{r.subject}|{ev.fields.get('service')}",
                    },
                    [ev],
                )
            )
        return out


class SpoofedAgentDetector(Detector):
    layer = "L4"
    name = "spoofed-user-agent"

    def __init__(self, config: Config):
        idc = config.section("identity")
        self.uas = [u.lower() for u in idc.get("spoofable_user_agents", [])]
        self.trusted = set(idc.get("trusted_cluster_ips", []) or [])

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        if ev.kind != "http_request" or not ev.user_agent:
            return []
        if ev.user_agent.strip().lower() not in self.uas or ev.src_ip in self.trusted:
            return []
        return [
            Alert(
                "INV-L4-004",
                f"Server-to-server User-Agent '{ev.user_agent}' from untrusted {ev.src_ip or '?'}",
                "critical",
                "L4",
                ev.host,
                ev.ts,
                "Old Nacos releases skip authentication for requests that merely claim to come from another Nacos "
                "node (CVE-2021-29441, fixed in 1.4.1). Only cluster members should ever send this header.",
                ["T1190", "T1550"],
                {"src_ip": ev.src_ip, "url": ev.url, "dedupe_key": f"{ev.src_ip}|{ev.user_agent}"},
                [ev],
            )
        ]


class SessionReplayDetector(Detector):
    layer = "L4"
    name = "session-replay"

    def __init__(self, config: Config):
        self.window = float(config.get("identity.session_window_s", 900))
        self.seen: dict[str, list[tuple[float, str]]] = defaultdict(list)

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        tid = ev.fields.get("token_id")
        if ev.kind != "auth" or not tid:
            return []
        where = str(ev.fields.get("device_id") or ev.src_ip or "")
        if not where:
            return []
        hist = self.seen[tid]
        hist[:] = [(t, w) for t, w in hist if ev.ts - t <= self.window]
        others = sorted({w for _, w in hist if w != where})
        hist.append((ev.ts, where))
        if not others:
            return []
        return [
            Alert(
                "INV-L4-005",
                f"Session token for '{ev.user}' used from {len(others) + 1} devices/addresses",
                "high",
                "L4",
                ev.host,
                ev.ts,
                "The same session appeared from different devices within the window: a stolen cookie or token. "
                "Device-bound sessions make this replay fail outright.",
                ["T1550", "T1606.001"],
                {
                    "token_id": tid,
                    "now_from": where,
                    "previously_from": others,
                    "dedupe_key": f"{tid}|{where}",
                },
                [ev],
            )
        ]


class AccountChangeDetector(Detector):
    layer = "L4"
    name = "account-change"

    def __init__(self, config: Config, token_audit: TokenAuditDetector):
        self.admin_roles = [r.lower() for r in config.get("identity.admin_roles", [])]
        self.token_audit = token_audit

    def process(self, ev: Event, ctx: Context) -> list[Alert]:
        out: list[Alert] = []
        if ev.kind == "account_change":
            role = str(ev.fields.get("role", "")).lower()
            action = str(ev.fields.get("action", "created"))
            if role and glob_any(role, self.admin_roles):
                forged_ts = self.token_audit.forged_hosts.get(ev.host)
                after_forgery = forged_ts is not None and 0 <= ev.ts - forged_ts <= 3600
                out.append(
                    Alert(
                        "INV-L4-006",
                        f"Privileged account '{ev.fields.get('target_user', '?')}' {action} by '{ev.user or '?'}'",
                        "critical" if after_forgery else "high",
                        "L4",
                        ev.host,
                        ev.ts,
                        "New administrators outside a change window are how intruders keep access. "
                        + (
                            "This one follows a forged-token event on the same service."
                            if after_forgery
                            else ""
                        ),
                        ["T1136", "T1078"],
                        {
                            "target_user": ev.fields.get("target_user"),
                            "role": role,
                            "actor": ev.user,
                            "after_forged_token": after_forgery,
                            "dedupe_key": str(ev.fields.get("target_user")),
                        },
                        [ev],
                    )
                )
        if ev.kind == "auth" and ev.fields.get("outcome", "success") == "success":
            is_default = ev.fields.get("credential_type") == "default" or (
                (ev.user or "").lower() in DEFAULT_ACCOUNTS and ev.fields.get("password_is_default")
            )
            if is_default or (ev.user or "").lower() == "minioadmin":
                out.append(
                    Alert(
                        "INV-L4-007",
                        f"Login with vendor default account '{ev.user}' on {ev.fields.get('service', 'service')}",
                        "critical",
                        "L4",
                        ev.host,
                        ev.ts,
                        "Default credentials are published. JADEPUFFER walked into MinIO this way.",
                        ["T1078.001"],
                        {
                            "service": ev.fields.get("service"),
                            "src_ip": ev.src_ip,
                            "account": ev.user,
                            "dedupe_key": f"{ev.user}|{ev.fields.get('service')}",
                        },
                        [ev],
                    )
                )
        return out


def identity_detectors(config: Config) -> list[Detector]:
    ta = TokenAuditDetector(config)
    return [
        ta,
        SpoofedAgentDetector(config),
        SessionReplayDetector(config),
        AccountChangeDetector(config, ta),
    ]
