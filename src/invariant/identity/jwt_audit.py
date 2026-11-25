"""Offline JWT auditing (no third-party JWT library required).

Answers four questions about a bearer token seen in logs or handed to you
during an incident:

* is it unsigned (``alg: none``)?
* was it signed with a publicly known default secret (e.g. Nacos'
  documented ``token.secret.key``), meaning anyone could have minted it?
* does it expire, and how long does it live?
* who does it claim to be?

Never log full tokens; use :func:`invariant.util.fingerprint_secret`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any

_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def b64url_decode(s: str) -> bytes:
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def key_variants(secret: str) -> list[bytes]:
    """A secret may be used raw or Base64-decoded (Nacos decodes it)."""
    out = [secret.encode()]
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        for pad in ("", "=", "==", "==="):
            try:
                k = decoder(secret + pad)
            except (binascii.Error, ValueError):
                continue
            if k and k not in out:
                out.append(k)
            break
    return out


def sign_hs(header: dict[str, Any], payload: dict[str, Any], key: bytes) -> str:
    """Create an HS* JWT. Used by tests and the simulator, not by detection."""
    alg = header.get("alg", "HS256")
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(key, f"{h}.{p}".encode(), _HASHES[alg]).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


@dataclass
class JwtReport:
    valid_format: bool
    header: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    alg: str | None = None
    unsigned: bool = False
    default_secret: str | None = None
    lifetime_s: float | None = None
    expires_in_s: float | None = None
    no_expiry: bool = False
    findings: list[tuple[str, str]] = field(default_factory=list)  # (severity, message)

    @property
    def subject(self) -> str | None:
        for k in ("sub", "username", "user", "preferred_username", "email"):
            if k in self.payload:
                return str(self.payload[k])
        return None

    def worst(self) -> str:
        order = ["info", "low", "medium", "high", "critical"]
        return max((s for s, _ in self.findings), key=order.index, default="info")


def audit_jwt(
    token: str,
    default_secrets: list[str] | None = None,
    max_lifetime_s: float = 3600,
    now: float | None = None,
) -> JwtReport:
    now = time.time() if now is None else now
    parts = token.strip().split(".")
    if len(parts) != 3:
        return JwtReport(False, findings=[("info", "not a JWS compact token")])
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (ValueError, binascii.Error):
        return JwtReport(False, findings=[("info", "undecodable header or payload")])
    r = JwtReport(True, header=header, payload=payload, alg=str(header.get("alg", "")))

    if r.alg.lower() == "none" or not parts[2]:
        r.unsigned = True
        r.findings.append(("critical", "token is unsigned (alg none / empty signature): trivially forgeable"))

    if r.alg in _HASHES and parts[2]:
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        try:
            sig = b64url_decode(parts[2])
        except (ValueError, binascii.Error):
            sig = b""
        for secret in default_secrets or []:
            for key in key_variants(secret):
                if hmac.compare_digest(hmac.new(key, signing_input, _HASHES[r.alg]).digest(), sig):
                    r.default_secret = secret[:12] + "…"
                    r.findings.append(
                        (
                            "critical",
                            "signature verifies with a PUBLIC DEFAULT secret: anyone could mint this token",
                        )
                    )
                    break
            if r.default_secret:
                break

    exp, iat = payload.get("exp"), payload.get("iat")
    if exp is None:
        r.no_expiry = True
        r.findings.append(("high", "token has no expiry (exp): stolen copies work forever"))
    else:
        try:
            r.expires_in_s = float(exp) - now
            if iat is not None:
                r.lifetime_s = float(exp) - float(iat)
            if r.lifetime_s is not None and r.lifetime_s > max_lifetime_s:
                r.findings.append(
                    (
                        "medium",
                        f"lifetime {r.lifetime_s / 3600:.1f} h exceeds policy {max_lifetime_s / 3600:.1f} h",
                    )
                )
            elif r.lifetime_s is None and r.expires_in_s > max_lifetime_s:
                r.findings.append(("medium", f"expires in {r.expires_in_s / 3600:.1f} h, beyond policy"))
        except (TypeError, ValueError):
            r.findings.append(("low", "non-numeric exp/iat"))
    return r
