"""The broker: request -> policy -> mint -> use -> revoke.

Lifecycle of a credential:

1. ``request`` — an agent asks for (resource, actions, ttl,
   justification) under a task trace ID. The policy engine's decision
   (a decision_record) is audited either way. On allow, a token is
   minted bound to the *granted* scope and the trace ID, and an
   ``issue`` event is audited. The token is an opaque signed handle:
   it contains claims, not any secret.
2. ``use`` — the tool-side shim presents the token plus the concrete
   (resource, action) it is about to perform. The broker verifies the
   signature, expiry (against the injected clock), revocation, and
   scope, in that order; any failure is audited as ``use_rejected``
   and raised as TokenError — fail closed. On success the backing
   store performs the work with the real (synthetic) secret inside
   its own call and only the work result crosses back.
3. ``revoke`` — a token's ``jti`` is revoked (task end, operator
   action); later use is rejected even before expiry.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from datetime import datetime, timezone

from . import tokens
from .audit import AuditLog
from .clock import SystemClock, iso
from .policy import Policy
from .store import BackingStore
from .trace_emit import emit_events_if_configured


@dataclass
class CredentialRequest:
    agent: str
    resource: str
    actions: tuple[str, ...]
    ttl_seconds: int
    justification: str
    trace_id: str


@dataclass
class UseResult:
    resource: str
    action: str
    result: str
    jti: str


class Broker:
    def __init__(self, *, policy: Policy, signing_key: bytes, clock=None,
                 audit_path=None, store: BackingStore | None = None):
        self._policy = policy
        self._key = signing_key
        self._clock = clock if clock is not None else SystemClock()
        self._audit = AuditLog(audit_path)
        self._store = store if store is not None else BackingStore()
        self._revoked: set[str] = set()
        self._counter = itertools.count(1)

    # -- audit helpers -------------------------------------------------
    def _log(self, req_agent: str, trace_id: str, type: str,
             payload: dict, kind: str = "event") -> dict:
        return self._audit.append(trace_id=trace_id, ts=self._clock.now(),
                                  agent=req_agent, type=type,
                                  payload=payload, kind=kind)

    @property
    def audit_events(self) -> list[dict]:
        return self._audit.events

    # -- lifecycle -----------------------------------------------------
    def request(self, req: CredentialRequest) -> str:
        """Ask policy and, if allowed, mint a scoped token.

        Returns the token string. Raises tokens.TokenError on deny —
        the denial is still audited as a decision_record first.
        """
        decision = self._policy.evaluate(
            agent=req.agent, resource=req.resource, actions=req.actions,
            ttl_seconds=req.ttl_seconds)
        self._log(req.agent, req.trace_id, "policy_decision", {
            "requested_resource": req.resource,
            "requested_actions": list(req.actions),
            "requested_ttl_seconds": req.ttl_seconds,
            "justification": req.justification,
            "allowed": decision.allowed,
            "scoped_down": decision.scoped_down,
            "granted_resource": decision.resource,
            "granted_actions": list(decision.actions),
            "granted_ttl_seconds": decision.ttl_seconds,
            "cuts": list(decision.cuts),
            "reason": decision.reason,
        }, kind="decision_record")
        if not decision.allowed:
            raise tokens.TokenError(f"policy denied: {decision.reason}")
        now = int(self._clock.now().timestamp())
        claims = {
            "jti": f"cred-{next(self._counter):04d}",
            "agent": req.agent,
            "resource": decision.resource,
            "actions": list(decision.actions),
            "trace_id": req.trace_id,
            "iat": now,
            "exp": now + decision.ttl_seconds,
        }
        token = tokens.mint(claims, self._key)
        self._log(req.agent, req.trace_id, "issue", {
            "jti": claims["jti"],
            "resource": claims["resource"],
            "actions": claims["actions"],
            "expires_at": iso(datetime.fromtimestamp(
                claims["exp"], tz=timezone.utc)),
            "scoped_down": decision.scoped_down,
        })
        emit_events_if_configured(self._audit.events[-2:])
        return token

    def use(self, token: str, *, resource: str, action: str,
            agent: str) -> UseResult:
        """Verify a token for one concrete use; perform the work.

        Fail closed: signature, expiry, revocation, agent binding, and
        scope are all checked, every rejection is audited, and the
        secret is touched only after all checks pass.
        """
        try:
            claims = tokens.verify(token, self._key)
        except tokens.TokenError as exc:
            self._log(agent, "", "use_rejected",
                      {"resource": resource, "action": action,
                       "reason": str(exc)})
            raise
        trace_id = claims.get("trace_id", "")
        jti = claims.get("jti", "?")

        def reject(reason: str) -> tokens.TokenError:
            event = self._log(agent, trace_id, "use_rejected",
                              {"jti": jti, "resource": resource,
                               "action": action, "reason": reason})
            emit_events_if_configured([event])
            return tokens.TokenError(reason)

        now = int(self._clock.now().timestamp())
        if now >= claims["exp"]:
            raise reject(f"token expired at {claims['exp']} (now {now})")
        if jti in self._revoked:
            raise reject(f"token {jti} has been revoked")
        if claims["agent"] != agent:
            raise reject(f"token was issued to {claims['agent']!r}, not {agent!r}")
        if not _in_scope(claims["resource"], resource):
            raise reject(f"resource {resource!r} is outside the token's "
                         f"scope {claims['resource']!r}")
        if action not in claims["actions"]:
            raise reject(f"action {action!r} is not in the token's "
                         f"actions {claims['actions']}")
        result = self._store.perform(resource, action)
        event = self._log(agent, trace_id, "use",
                          {"jti": jti, "resource": resource,
                           "action": action, "outcome": "performed"})
        emit_events_if_configured([event])
        return UseResult(resource=resource, action=action,
                         result=result, jti=jti)

    def revoke(self, token: str, *, agent: str, reason: str = "task ended") -> str:
        claims = tokens.verify(token, self._key)
        jti = claims["jti"]
        self._revoked.add(jti)
        event = self._log(agent, claims.get("trace_id", ""), "revoke",
                          {"jti": jti, "reason": reason})
        emit_events_if_configured([event])
        return jti


def _in_scope(granted: str, resource: str) -> bool:
    if granted.endswith("/*"):
        return resource == granted[:-2] or resource.startswith(granted[:-1])
    return resource == granted
