"""CredBroker test suite (stdlib unittest; also runs under pytest).

Covers the five demos, token tamper/forgery rejection, policy denial,
agent binding, audit-chain integrity and tamper detection, and the
AgentTrace schema v1 shape of every emitted event.
"""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from credbroker import Broker, CredentialRequest, FakeClock, Policy, Rule
from credbroker import audit, tokens
from credbroker.trace_emit import to_trace_event

KEY = b"test-signing-key-not-a-real-secret"
OTHER_KEY = b"some-other-key"
TRACE = "trace-test-0001"
START = datetime(2026, 1, 1, tzinfo=timezone.utc)

POLICY = Policy([
    Rule("qa-agent", "db/factory/*", frozenset({"read"}), 300),
    Rule("deploy-agent", "deploy/checkout-api", frozenset({"deploy"}), 600),
])


def make_broker(clock=None, audit_path=None):
    return Broker(policy=POLICY, signing_key=KEY,
                  clock=clock if clock is not None else FakeClock(START),
                  audit_path=audit_path)


def qa_request(**overrides):
    base = dict(agent="qa-agent", resource="db/factory/pumps",
                actions=("read",), ttl_seconds=300,
                justification="test", trace_id=TRACE)
    base.update(overrides)
    return CredentialRequest(**base)


class TestFiveDemos(unittest.TestCase):
    def test_demo1_scoped_issue_and_in_scope_use(self):
        broker = make_broker()
        tok = broker.request(qa_request())
        res = broker.use(tok, resource="db/factory/pumps", action="read",
                         agent="qa-agent")
        self.assertIn("operational", res.result)
        self.assertEqual(res.jti, "cred-0001")

    def test_demo2_out_of_scope_action_rejected(self):
        broker = make_broker()
        tok = broker.request(qa_request())
        with self.assertRaises(tokens.TokenError):
            broker.use(tok, resource="db/factory/pumps", action="write",
                       agent="qa-agent")

    def test_demo2_out_of_scope_resource_rejected(self):
        broker = make_broker()
        tok = broker.request(qa_request())
        with self.assertRaises(tokens.TokenError):
            broker.use(tok, resource="deploy/checkout-api", action="read",
                       agent="qa-agent")

    def test_demo3_expired_token_rejected(self):
        clock = FakeClock(START)
        broker = make_broker(clock=clock)
        tok = broker.request(qa_request())
        clock.advance(301)
        with self.assertRaises(tokens.TokenError) as ctx:
            broker.use(tok, resource="db/factory/pumps", action="read",
                       agent="qa-agent")
        self.assertIn("expired", str(ctx.exception))

    def test_demo3_token_valid_one_second_before_expiry(self):
        clock = FakeClock(START)
        broker = make_broker(clock=clock)
        tok = broker.request(qa_request())
        clock.advance(299)
        res = broker.use(tok, resource="db/factory/pumps", action="read",
                         agent="qa-agent")
        self.assertEqual(res.jti, "cred-0001")

    def test_demo4_scope_down(self):
        broker = make_broker()
        tok = broker.request(qa_request(
            resource="db/*", actions=("read", "write"), ttl_seconds=3600))
        claims = tokens.verify(tok, KEY)
        self.assertEqual(claims["resource"], "db/factory/*")
        self.assertEqual(claims["actions"], ["read"])
        self.assertEqual(claims["exp"] - claims["iat"], 300)
        decisions = [e for e in broker.audit_events
                     if e["type"] == "policy_decision"]
        self.assertTrue(decisions[-1]["payload"]["scoped_down"])
        self.assertEqual(len(decisions[-1]["payload"]["cuts"]), 3)
        with self.assertRaises(tokens.TokenError):
            broker.use(tok, resource="db/factory/pumps", action="write",
                       agent="qa-agent")

    def test_demo5_revocation_mid_flight(self):
        broker = make_broker()
        tok = broker.request(CredentialRequest(
            agent="deploy-agent", resource="deploy/checkout-api",
            actions=("deploy",), ttl_seconds=600, justification="ship",
            trace_id=TRACE))
        broker.use(tok, resource="deploy/checkout-api", action="deploy",
                   agent="deploy-agent")
        broker.revoke(tok, agent="deploy-agent")
        with self.assertRaises(tokens.TokenError) as ctx:
            broker.use(tok, resource="deploy/checkout-api", action="deploy",
                       agent="deploy-agent")
        self.assertIn("revoked", str(ctx.exception))


class TestPolicyAndTokens(unittest.TestCase):
    def test_unknown_agent_denied_and_audited(self):
        broker = make_broker()
        with self.assertRaises(tokens.TokenError) as ctx:
            broker.request(qa_request(agent="rogue-agent"))
        self.assertIn("denied", str(ctx.exception))
        decision = broker.audit_events[-1]
        self.assertEqual(decision["kind"], "decision_record")
        self.assertFalse(decision["payload"]["allowed"])

    def test_resource_outside_ceiling_denied(self):
        broker = make_broker()
        with self.assertRaises(tokens.TokenError):
            broker.request(qa_request(resource="deploy/checkout-api"))

    def test_token_tamper_claims_rejected(self):
        broker = make_broker()
        tok = broker.request(qa_request())
        payload, sig = tok.split(".")
        forged_claims = tokens.verify(tok, KEY)
        forged_claims["actions"] = ["read", "write"]
        forged = tokens.mint(forged_claims, OTHER_KEY)
        with self.assertRaises(tokens.TokenError):
            broker.use(forged, resource="db/factory/pumps", action="write",
                       agent="qa-agent")
        # Flip one character of the genuine payload, keep the signature.
        flipped = ("A" if payload[0] != "A" else "B") + payload[1:]
        with self.assertRaises(tokens.TokenError):
            broker.use(f"{flipped}.{sig}", resource="db/factory/pumps",
                       action="read", agent="qa-agent")

    def test_token_signed_with_wrong_key_rejected(self):
        claims = {"jti": "cred-9999", "agent": "qa-agent",
                  "resource": "db/factory/pumps", "actions": ["read"],
                  "trace_id": TRACE, "iat": int(START.timestamp()),
                  "exp": int(START.timestamp()) + 300}
        forged = tokens.mint(claims, OTHER_KEY)
        broker = make_broker()
        with self.assertRaises(tokens.TokenError) as ctx:
            broker.use(forged, resource="db/factory/pumps", action="read",
                       agent="qa-agent")
        self.assertIn("signature", str(ctx.exception))

    def test_token_bound_to_issuing_agent(self):
        broker = make_broker()
        tok = broker.request(qa_request())
        with self.assertRaises(tokens.TokenError):
            broker.use(tok, resource="db/factory/pumps", action="read",
                       agent="deploy-agent")

    def test_token_bound_to_trace_id(self):
        broker = make_broker()
        tok = broker.request(qa_request())
        claims = tokens.verify(tok, KEY)
        self.assertEqual(claims["trace_id"], TRACE)


class TestAuditChain(unittest.TestCase):
    def test_chain_verifies_and_events_are_schema_v1(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            broker = make_broker(audit_path=path)
            tok = broker.request(qa_request())
            broker.use(tok, resource="db/factory/pumps", action="read",
                       agent="qa-agent")
            result = audit.verify(path)
            self.assertTrue(result.ok, result.detail)
            self.assertEqual(result.count, 3)
            for event in audit.load(path):
                self.assertEqual(event["schema_version"], "1")
                self.assertEqual(event["source"], "cred-broker")
                self.assertEqual(event["trace_id"], TRACE)
                for field in ("ts", "agent", "type", "kind", "payload",
                              "seq", "prev_hash", "hash"):
                    self.assertIn(field, event)

    def test_chain_tamper_detected_at_exact_seq(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            broker = make_broker(audit_path=path)
            tok = broker.request(qa_request())
            broker.use(tok, resource="db/factory/pumps", action="read",
                       agent="qa-agent")
            lines = path.read_text(encoding="utf-8").splitlines()
            entry = json.loads(lines[1])
            entry["payload"]["resource"] = "db/*"  # rewrite history
            lines[1] = json.dumps(entry)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            result = audit.verify(path)
            self.assertFalse(result.ok)
            self.assertEqual(result.broken_seq, 2)

    def test_broken_chain_refuses_to_extend(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            broker = make_broker(audit_path=path)
            broker.request(qa_request())
            lines = path.read_text(encoding="utf-8").splitlines()
            entry = json.loads(lines[0])
            entry["payload"]["allowed"] = False
            lines[0] = json.dumps(entry)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                make_broker(audit_path=path)

    def test_rejections_are_audited(self):
        broker = make_broker()
        tok = broker.request(qa_request())
        with self.assertRaises(tokens.TokenError):
            broker.use(tok, resource="db/factory/pumps", action="write",
                       agent="qa-agent")
        types = [e["type"] for e in broker.audit_events]
        self.assertEqual(types, ["policy_decision", "issue", "use_rejected"])

    def test_trace_event_shape_matches_agenttrace_core_fields(self):
        broker = make_broker()
        broker.request(qa_request())
        event = to_trace_event(broker.audit_events[0])
        self.assertEqual(set(event), {"schema_version", "trace_id", "ts",
                                      "source", "agent", "type", "kind",
                                      "payload"})
        self.assertEqual(event["kind"], "decision_record")


if __name__ == "__main__":
    unittest.main()
