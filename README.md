# CredBroker — a credential broker for agents

**The agent never holds a long-lived key.** Instead of handing an AI
agent a database password that lives for months, the agent *requests*
access — resource, actions, justification, under its task's trace ID —
a policy engine approves, denies, or **scopes the request down**, and
the broker mints a signed token that expires in **minutes** and is
bound to exactly that scope. The tool-side shim presents the token at
call time; the real secret is consumed inside the tool's own call and
never crosses back into the agent's context, prompts, or logs. Every
issue, use, rejection, and revocation is written to a **hash-chained
audit log** of AgentTrace schema v1 events.

This is the credential-lifecycle half of the platform story told
across this portfolio: [agent-gate](https://github.com/hsooligan95/agent-gate)
governs *what an agent may do*; CredBroker governs *what it may hold*.

## Run it

```bash
PYTHONPATH=src python3 -m credbroker.demo   # the five demos, deterministic
PYTHONPATH=src python3 -m unittest discover -s tests   # 18 tests
```

No dependencies — Python 3.11+ standard library only (HMAC-SHA256
signing, hash-chained JSONL audit). The demo runs on an injected fake
clock starting 2026-01-01T00:00:00Z, so its output is byte-stable run
over run; the full transcript is committed as `demo-output.txt`.

## The five demos (real captured output)

```
CredBroker demo - trace trace-cred-demo-0001 - clock 2026-01-01T00:00:00Z
========================================================================

DEMO 1 - scoped issue + successful in-scope use
  issued token (jti cred-0001, scope db/factory/pumps [read], TTL 300s)
  use db/factory/pumps read -> OK: pump P-104: operational, no maintenance hold
  (the secret was consumed inside the tool-side call; only the
   work result above ever came back to the agent)

DEMO 2 - out-of-scope use rejected
  use db/factory/pumps write -> REJECTED (action 'write' was never granted): action 'write' is not in the token's actions ['read']
  use deploy/checkout-api read -> REJECTED (resource outside the token's scope): resource 'deploy/checkout-api' is outside the token's scope 'db/factory/pumps'

DEMO 3 - expired token rejected
  advancing the clock 301s (token TTL was 300s)...
  use after expiry -> REJECTED: token expired at 1767225900 (now 1767225901)

DEMO 4 - scope-down: agent asks broad, policy grants narrow
  asked:    resource db/*, actions [read, write], TTL 3600s
  granted:  resource db/factory/*, actions ['read'], TTL 300s (jti cred-0002)
  use db/factory/inventory read -> OK: SKU-2211 gaskets: 14 in stock at plant store
  use write under scoped-down token -> REJECTED: action 'write' is not in the token's actions ['read']

DEMO 5 - revocation mid-flight
  use deploy/checkout-api deploy -> OK: checkout-api deploy started (build 4821)
  revoked cred-0003 while it still had time left
  use after revoke -> REJECTED: token cred-0003 has been revoked

AUDIT - hash chain over every decision, issue, use, and revoke
  15 events: policy_decision, issue, use, use_rejected, use_rejected, use_rejected, policy_decision, issue, use, use_rejected, policy_decision, issue, use, revoke, use_rejected
  chain verify: OK - chain intact
  decision_records: 3 (policy decisions, computed at decision time)
  all 15 events carry trace_id trace-cred-demo-0001: True

LEAK CHECK - searching the full transcript above (everything the
agent ever saw, plus this report) for the backing store's secrets:
  db/factory/pumps: secret occurs 0 time(s)
  db/factory/inventory: secret occurs 0 time(s)
  deploy/checkout-api: secret occurs 0 time(s)
  RESULT: PASS - no secret ever reached the agent side
```

## How it works

- **Policy engine** (`policy.py`) — a rule is a *ceiling* per agent:
  broadest resource, allowed actions, longest TTL. A request is
  granted the intersection of ask and ceiling — nothing intersects →
  deny (default deny, no rule = no access); intersection narrower
  than the ask → **scope down**, with every cut recorded on the
  policy `decision_record`.
- **Tokens** (`tokens.py`) — `base64url(claims) + "." +
  base64url(HMAC-SHA256)`, stdlib only. Claims bind agent, resource,
  actions, **trace ID**, issue/expiry, and a revocable `jti`.
  Verification uses a constant-time compare; tampered claims and
  wrong-key forgeries fail closed (both are tested).
- **Use path** (`broker.py`) — checks, in order: signature → expiry
  (against the injected clock) → revocation → agent binding →
  resource scope → action scope. Every rejection is audited before it
  is raised. Only after all checks pass does the backing store
  perform the work, returning the *result*, never the secret.
- **Audit** (`audit.py`) — append-only JSONL hash chain using the
  same construction as [agent-trace](https://github.com/hsooligan95/agent-trace)
  (SHA-256 over canonical JSON, genesis-linked). Tampering is
  detected at the exact `seq`, and the log refuses to extend a broken
  chain. Policy decisions are emitted as `decision_record`s — computed
  by the policy branch, at decision time, from the deciding values.
- **AgentTrace emission** (`trace_emit.py`) — with `CREDBROKER_TRACE_ID`
  (or `AGENTTRACE_TRACE_ID`) set, the same events are written in
  pre-store AgentTrace schema v1 shape to `CREDBROKER_TRACE_OUT`.
  Verified against the real thing: all 15 demo events validate with
  agent-trace's own schema module, append into a real AgentTrace
  store, and the store's chain verifies (15 events, OK).

## Tests — 18, all passing

The five demos as tests (including the boundary case: valid at
TTL−1s, rejected at TTL+1s), scope-down cuts recorded exactly,
unknown-agent denial audited as a decision record, token tampering
(flipped payload char, re-signed claims with a wrong key), agent
binding, audit-chain verification, chain tamper detected at the exact
sequence number, and refusal to extend a broken chain.

## Limitations — read these

- **This is a pattern implementation, not a production secrets
  manager.** It demonstrates the broker lifecycle — request, policy,
  scope-down, mint, verify, revoke, audit — with real mechanics. It
  is not hardened for deployment: no transport security, no
  multi-process concurrency control on the audit file, no key
  management service.
- **HMAC with a broker-held symmetric key** stands in for the
  asymmetric signing / KMS / HSM a production broker (e.g. AWS STS,
  which this is modeled on) would use. Anyone holding the signing key
  can mint tokens; a production design must not have that property on
  the verification side.
- **The backing store is simulated.** Secrets are clearly synthetic
  in-memory values (`store.py`); the "tool-side shim" is a method
  call in the same process, not a separate tool process. The boundary
  it demonstrates — secret consumed inside the call, only results
  crossing back — is the pattern; the isolation is not real.
- **Revocation is in-memory** (a set of `jti`s); it does not persist
  across broker restarts, and there is no token introspection
  endpoint. Expiry is the primary control, by design: TTLs are
  minutes, so the revocation window is short.
- **The leak check proves a narrow, honest thing:** in this demo's
  transcript, the synthetic secrets never appear. It is a grep over
  one deterministic run, not a proof about arbitrary agents or tools.
