"""The five demos, one deterministic run.

Run:  PYTHONPATH=src python3 -m credbroker.demo

A FakeClock starts at 2026-01-01T00:00:00Z and only advances when a
demo advances it, the trace ID is fixed, and token IDs are sequential,
so the transcript below is byte-stable run over run. All secrets are
synthetic (see store.py). The demo closes with the leak check: the
full transcript — which includes everything the agent ever saw — is
searched for the backing store's secret values.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from . import tokens
from .audit import verify
from .broker import Broker, CredentialRequest
from .clock import FakeClock
from .policy import Policy, Rule
from .store import SECRETS

SIGNING_KEY = b"demo-signing-key-not-a-real-secret"
TRACE_ID = "trace-cred-demo-0001"
START = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
AUDIT_PATH = Path(__file__).resolve().parents[2] / "demo-audit.jsonl"

POLICY = Policy([
    Rule("qa-agent", "db/factory/*", frozenset({"read"}), 300),
    Rule("deploy-agent", "deploy/checkout-api", frozenset({"deploy"}), 600),
])


def run() -> str:
    out = io.StringIO()
    with redirect_stdout(out):
        _run()
    return out.getvalue()


def _run() -> None:
    if AUDIT_PATH.exists():
        AUDIT_PATH.unlink()
    clock = FakeClock(START)
    broker = Broker(policy=POLICY, signing_key=SIGNING_KEY, clock=clock,
                    audit_path=AUDIT_PATH)
    print(f"CredBroker demo - trace {TRACE_ID} - clock 2026-01-01T00:00:00Z")
    print("=" * 72)

    print("\nDEMO 1 - scoped issue + successful in-scope use")
    tok = broker.request(CredentialRequest(
        agent="qa-agent", resource="db/factory/pumps", actions=("read",),
        ttl_seconds=300, justification="answer a pump status question",
        trace_id=TRACE_ID))
    print(f"  issued token (jti cred-0001, scope db/factory/pumps [read], TTL 300s)")
    res = broker.use(tok, resource="db/factory/pumps", action="read",
                     agent="qa-agent")
    print(f"  use db/factory/pumps read -> OK: {res.result}")
    print("  (the secret was consumed inside the tool-side call; only the")
    print("   work result above ever came back to the agent)")

    print("\nDEMO 2 - out-of-scope use rejected")
    for resource, action, label in [
            ("db/factory/pumps", "write", "action 'write' was never granted"),
            ("deploy/checkout-api", "read", "resource outside the token's scope")]:
        try:
            broker.use(tok, resource=resource, action=action, agent="qa-agent")
            print(f"  use {resource} {action} -> NOT REJECTED (BUG)")
        except tokens.TokenError as exc:
            print(f"  use {resource} {action} -> REJECTED ({label}): {exc}")

    print("\nDEMO 3 - expired token rejected")
    print("  advancing the clock 301s (token TTL was 300s)...")
    clock.advance(301)
    try:
        broker.use(tok, resource="db/factory/pumps", action="read",
                   agent="qa-agent")
        print("  use after expiry -> NOT REJECTED (BUG)")
    except tokens.TokenError as exc:
        print(f"  use after expiry -> REJECTED: {exc}")

    print("\nDEMO 4 - scope-down: agent asks broad, policy grants narrow")
    tok2 = broker.request(CredentialRequest(
        agent="qa-agent", resource="db/*", actions=("read", "write"),
        ttl_seconds=3600, justification="needs 'full database access'",
        trace_id=TRACE_ID))
    claims = tokens.verify(tok2, SIGNING_KEY)
    print(f"  asked:    resource db/*, actions [read, write], TTL 3600s")
    print(f"  granted:  resource {claims['resource']}, actions {claims['actions']}, "
          f"TTL {claims['exp'] - claims['iat']}s (jti {claims['jti']})")
    res = broker.use(tok2, resource="db/factory/inventory", action="read",
                     agent="qa-agent")
    print(f"  use db/factory/inventory read -> OK: {res.result}")
    try:
        broker.use(tok2, resource="db/factory/inventory", action="write",
                   agent="qa-agent")
        print("  use write under scoped-down token -> NOT REJECTED (BUG)")
    except tokens.TokenError as exc:
        print(f"  use write under scoped-down token -> REJECTED: {exc}")

    print("\nDEMO 5 - revocation mid-flight")
    tok3 = broker.request(CredentialRequest(
        agent="deploy-agent", resource="deploy/checkout-api",
        actions=("deploy",), ttl_seconds=600,
        justification="ship build 4821", trace_id=TRACE_ID))
    res = broker.use(tok3, resource="deploy/checkout-api", action="deploy",
                     agent="deploy-agent")
    print(f"  use deploy/checkout-api deploy -> OK: {res.result}")
    jti = broker.revoke(tok3, agent="deploy-agent",
                        reason="task ended early - operator revoked")
    print(f"  revoked {jti} while it still had time left")
    try:
        broker.use(tok3, resource="deploy/checkout-api", action="deploy",
                   agent="deploy-agent")
        print("  use after revoke -> NOT REJECTED (BUG)")
    except tokens.TokenError as exc:
        print(f"  use after revoke -> REJECTED: {exc}")

    print("\nAUDIT - hash chain over every decision, issue, use, and revoke")
    result = verify(AUDIT_PATH)
    events = broker.audit_events
    kinds = [e["type"] for e in events]
    print(f"  {result.count} events: {', '.join(kinds)}")
    print(f"  chain verify: {'OK - chain intact' if result.ok else 'BROKEN'}")
    decisions = [e for e in events if e["kind"] == "decision_record"]
    print(f"  decision_records: {len(decisions)} (policy decisions, computed at decision time)")
    print(f"  all {len(events)} events carry trace_id {TRACE_ID}: "
          f"{all(e['trace_id'] == TRACE_ID for e in events)}")


def main() -> None:
    transcript = run()
    print(transcript, end="")
    print("LEAK CHECK - searching the full transcript above (everything the")
    print("agent ever saw, plus this report) for the backing store's secrets:")
    leaks = 0
    for resource, secret in SECRETS.items():
        hits = transcript.count(secret)
        leaks += hits
        print(f"  {resource}: secret occurs {hits} time(s)")
    print(f"  RESULT: {'PASS - no secret ever reached the agent side' if leaks == 0 else 'FAIL'}")


if __name__ == "__main__":
    main()
