"""Mint bridge: issue CredBroker tokens for agent-gate's broker mode.

agent-gate (TypeScript) can require a CredBroker token before it will
execute a tool call. The token has to come from the real broker — real
policy evaluation, real scope-down rules — so this CLI is the minting
side of that bridge:

    PYTHONPATH=src python3 -m credbroker.mint_cli \
        --agent demo-agent --resource 'tool/*' --actions call \
        --ttl 3600 --trace-id <the gate session's trace ID> \
        --out token.txt

The bridge policy below mirrors the identities in agent-gate's
shipped policy.json: a gate tool call maps to the broker resource
``tool/<tool name>`` and the single action ``call``. A token minted
with ``--resource tool/get_cost_summary`` therefore covers exactly one
tool; ``tool/*`` covers all of them.

The default signing key is the same synthetic demo key as
credbroker.demo — this is a local bridge between two demos, not a
deployment. ``--expired`` mints against a clock fixed in 2020 so the
token is already expired whenever it is presented; ``--revoke-file``
additionally revokes the token and appends its jti to the given file
(the file agent-gate reads for its revocation check).
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import tokens
from .broker import Broker, CredentialRequest
from .clock import FakeClock, SystemClock
from .demo import SIGNING_KEY
from .policy import Policy, Rule

# Ceilings for the gate bridge: any tool resource, the "call" action,
# at most one hour — the intersection logic in Policy does the rest.
BRIDGE_POLICY = Policy([
    Rule("demo-agent", "tool/*", frozenset({"call"}), 3600),
    Rule("readonly-agent", "tool/*", frozenset({"call"}), 3600),
])

EXPIRED_START = datetime(2020, 1, 1, tzinfo=timezone.utc)


def mint_token(*, agent: str, resource: str, actions: tuple[str, ...],
               ttl_seconds: int, trace_id: str, key: bytes = SIGNING_KEY,
               expired: bool = False, revoke_file: str | None = None,
               policy: Policy = BRIDGE_POLICY,
               justification: str = "agent-gate broker bridge") -> tuple[str, str]:
    """Mint one bridge token with the real broker. Returns (token, jti)."""
    clock = FakeClock(EXPIRED_START) if expired else SystemClock()
    broker = Broker(policy=policy, signing_key=key, clock=clock)
    token = broker.request(CredentialRequest(
        agent=agent, resource=resource, actions=actions,
        ttl_seconds=ttl_seconds, justification=justification,
        trace_id=trace_id))
    jti = tokens.verify(token, key)["jti"]
    if revoke_file:
        broker.revoke(token, agent=agent, reason="revoked for bridge demo")
        with open(revoke_file, "a", encoding="utf-8") as fh:
            fh.write(jti + "\n")
    return token, jti


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="credbroker.mint_cli",
        description="Mint a CredBroker token for agent-gate's broker mode.")
    parser.add_argument("--agent", required=True)
    parser.add_argument("--resource", required=True,
                        help="granted resource, e.g. 'tool/*' or "
                             "'tool/get_cost_summary'")
    parser.add_argument("--actions", default="call",
                        help="comma-separated actions (default: call)")
    parser.add_argument("--ttl", type=int, default=3600)
    parser.add_argument("--trace-id", required=True,
                        help="the gate session's trace ID to bind to")
    parser.add_argument("--out", required=True, help="token file to write")
    parser.add_argument("--key", default=None,
                        help="signing key (default: the synthetic demo key)")
    parser.add_argument("--expired", action="store_true",
                        help="mint against a 2020 clock so the token is "
                             "already expired")
    parser.add_argument("--revoke-file", default=None,
                        help="also revoke the token and append its jti "
                             "to this file")
    args = parser.parse_args(argv)
    key = args.key.encode() if args.key else SIGNING_KEY
    token, jti = mint_token(
        agent=args.agent, resource=args.resource,
        actions=tuple(a.strip() for a in args.actions.split(",") if a.strip()),
        ttl_seconds=args.ttl, trace_id=args.trace_id, key=key,
        expired=args.expired, revoke_file=args.revoke_file)
    Path(args.out).write_text(token, encoding="utf-8")
    print(f"minted {jti} for agent {args.agent!r}: resource {args.resource}, "
          f"ttl {args.ttl}s{' (already expired)' if args.expired else ''}"
          f"{' (revoked)' if args.revoke_file else ''} -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
