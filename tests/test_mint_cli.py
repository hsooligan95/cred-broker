"""Tests for the agent-gate bridge: mint_cli + Broker.verify_token.

The bridge contract agent-gate's TypeScript verifier reproduces:
checks run signature -> expiry -> revocation -> agent binding ->
resource scope -> action scope, in that order, failing closed.
"""

import tempfile
import unittest
from pathlib import Path

from credbroker import Broker, Policy, Rule, TokenError
from credbroker.clock import SystemClock
from credbroker.mint_cli import BRIDGE_POLICY, main, mint_token

KEY = b"demo-signing-key-not-a-real-secret"
TRACE = "trace-gate-bridge-test"


def bridge_broker():
    return Broker(policy=BRIDGE_POLICY, signing_key=KEY, clock=SystemClock())


class TestVerifyToken(unittest.TestCase):
    def test_covering_token_verifies(self):
        token, jti = mint_token(agent="demo-agent", resource="tool/*",
                                actions=("call",), ttl_seconds=3600,
                                trace_id=TRACE)
        claims = bridge_broker().verify_token(
            token, resource="tool/list_resources", action="call",
            agent="demo-agent")
        self.assertEqual(claims["jti"], jti)
        self.assertEqual(claims["trace_id"], TRACE)

    def test_narrower_resource_denied_on_scope(self):
        token, _ = mint_token(agent="demo-agent",
                              resource="tool/get_cost_summary",
                              actions=("call",), ttl_seconds=3600,
                              trace_id=TRACE)
        broker = bridge_broker()
        broker.verify_token(token, resource="tool/get_cost_summary",
                            action="call", agent="demo-agent")
        with self.assertRaises(TokenError) as ctx:
            broker.verify_token(token, resource="tool/list_resources",
                                action="call", agent="demo-agent")
        self.assertIn("outside the token's scope", str(ctx.exception))

    def test_ungranted_action_denied(self):
        read_only = Policy([Rule("demo-agent", "tool/*",
                                 frozenset({"read"}), 3600)])
        token, _ = mint_token(agent="demo-agent", resource="tool/*",
                              actions=("read",), ttl_seconds=3600,
                              trace_id=TRACE, policy=read_only)
        with self.assertRaises(TokenError) as ctx:
            bridge_broker().verify_token(
                token, resource="tool/list_resources", action="call",
                agent="demo-agent")
        self.assertIn("not in the token's actions", str(ctx.exception))

    def test_expired_token_denied(self):
        token, _ = mint_token(agent="demo-agent", resource="tool/*",
                              actions=("call",), ttl_seconds=3600,
                              trace_id=TRACE, expired=True)
        with self.assertRaises(TokenError) as ctx:
            bridge_broker().verify_token(
                token, resource="tool/list_resources", action="call",
                agent="demo-agent")
        self.assertIn("expired", str(ctx.exception))

    def test_expiry_checked_before_scope(self):
        # An expired AND out-of-scope presentation reports expiry:
        # the verify order is part of the bridge contract.
        token, _ = mint_token(agent="demo-agent",
                              resource="tool/get_cost_summary",
                              actions=("call",), ttl_seconds=3600,
                              trace_id=TRACE, expired=True)
        with self.assertRaises(TokenError) as ctx:
            bridge_broker().verify_token(
                token, resource="tool/list_resources", action="call",
                agent="demo-agent")
        self.assertIn("expired", str(ctx.exception))

    def test_agent_binding_enforced(self):
        token, _ = mint_token(agent="demo-agent", resource="tool/*",
                              actions=("call",), ttl_seconds=3600,
                              trace_id=TRACE)
        with self.assertRaises(TokenError) as ctx:
            bridge_broker().verify_token(
                token, resource="tool/list_resources", action="call",
                agent="readonly-agent")
        self.assertIn("was issued to", str(ctx.exception))


class TestMintCli(unittest.TestCase):
    def test_cli_writes_a_usable_token_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "token.txt"
            rc = main(["--agent", "demo-agent", "--resource", "tool/*",
                       "--trace-id", TRACE, "--out", str(out)])
            self.assertEqual(rc, 0)
            token = out.read_text(encoding="utf-8")
            claims = bridge_broker().verify_token(
                token, resource="tool/terminate_instance", action="call",
                agent="demo-agent")
            self.assertEqual(claims["resource"], "tool/*")

    def test_cli_revoke_file_records_the_jti(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "token.txt"
            revoked = Path(tmp) / "revoked.txt"
            rc = main(["--agent", "demo-agent", "--resource", "tool/*",
                       "--trace-id", TRACE, "--out", str(out),
                       "--revoke-file", str(revoked)])
            self.assertEqual(rc, 0)
            token = out.read_text(encoding="utf-8")
            from credbroker import tokens
            jti = tokens.verify(token, KEY)["jti"]
            self.assertEqual(revoked.read_text(encoding="utf-8").splitlines(),
                             [jti])


if __name__ == "__main__":
    unittest.main()
