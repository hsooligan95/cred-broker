# Copilot instructions — cred-broker

You are working in **CredBroker**, a credential broker for AI agents: an
agent requests access (resource + actions + justification) under its
task's trace ID, a policy engine approves, denies, or scopes the request
down, and the broker mints a signed token that expires in minutes, bound
to exactly that scope. The agent never holds a long-lived key.

## Stack

- Python 3.11+, standard library ONLY — zero dependencies. HMAC-SHA256
  token signing, hash-chained JSONL audit of AgentTrace schema v1
  events.
- `src/credbroker/`: `broker.py`, `policy.py`, `tokens.py`, `audit.py`,
  `store.py` (simulated vault), `clock.py` (injected clock),
  `trace_emit.py`, `demo.py`.

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests   # 18 tests
PYTHONPATH=src python3 -m credbroker.demo              # five demos, deterministic
```

## Architecture notes

- Verification is fail-closed and ordered: signature -> expiry ->
  revocation -> agent binding -> scope. Never reorder or skip a step.
- Grant = intersection of the ask with the agent's policy ceiling;
  every cut (resource narrowed, action dropped, TTL shortened) is
  recorded. Scope-down is a feature, not an error.
- The real secret is consumed inside the tool-side call only and never
  crosses back to the agent. A leak-check test greps the full demo
  transcript for secret material — keep it passing.
- Determinism: the clock is injected (`FakeClock` in tests/demo), so
  `demo-output.txt` is byte-stable and committed. Regenerate it in the
  same change whenever behavior changes.
- The audit chain refuses to extend a broken chain; the HMAC key here
  stands in for KMS/asymmetric signing — this is a pattern
  implementation, not a production secrets manager. Keep that framing.

## Shared rules

- Use Unix LF line endings in every file; never CRLF.
- Never commit secrets, tokens, or credentials — real or synthetic-looking.
- Tests must pass before you describe a change as complete; run the test
  command above and report honestly if you cannot.
- Prefer the smallest complete implementation: reuse what already exists in
  this repo before adding new code, files, or dependencies.
