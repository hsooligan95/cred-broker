"""Tokens: HMAC-SHA256 signed, stdlib only.

Wire format: ``base64url(canonical_json_claims) + "." + base64url(hmac)``.
The claims carry the scope the token is bound to — agent, resource,
actions, trace ID, issued-at / expires-at (epoch seconds), and a unique
``jti`` the broker can revoke. Verification recomputes the HMAC over
the exact payload bytes with a constant-time compare; any tampering
with claims or signature fails closed.

This is a pattern implementation: HMAC with a broker-held key stands in
for the asymmetric signing / KMS a production broker would use.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json


class TokenError(ValueError):
    """A token is malformed, forged, expired, revoked, or out of scope."""


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def mint(claims: dict, key: bytes) -> str:
    payload = _b64encode(canonical(claims).encode())
    sig = hmac.new(key, payload.encode(), hashlib.sha256).digest()
    return f"{payload}.{_b64encode(sig)}"


def verify(token: str, key: bytes) -> dict:
    """Return the claims of a well-formed, correctly signed token.

    Raises TokenError on any structural or signature problem. Expiry,
    revocation, and scope are the broker's checks, not this layer's.
    """
    if not isinstance(token, str) or token.count(".") != 1:
        raise TokenError("malformed token: expected '<payload>.<signature>'")
    payload_b64, sig_b64 = token.split(".")
    expected = hmac.new(key, payload_b64.encode(), hashlib.sha256).digest()
    try:
        given = _b64decode(sig_b64)
    except Exception:
        raise TokenError("malformed token: signature is not base64url") from None
    if not hmac.compare_digest(expected, given):
        raise TokenError("bad signature: token was forged or tampered with")
    try:
        claims = json.loads(_b64decode(payload_b64))
    except Exception:
        raise TokenError("malformed token: payload is not JSON") from None
    if not isinstance(claims, dict):
        raise TokenError("malformed token: payload is not a claims object")
    return claims
