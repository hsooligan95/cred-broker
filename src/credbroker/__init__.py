"""CredBroker: short-lived, tightly scoped credentials for AI agents.

An agent never holds a long-lived key. It requests access (resource +
action + justification), a policy engine approves, denies, or scopes
the request down, and the broker mints an HMAC-signed token that
expires in minutes and is bound to exactly that scope and to the
task's trace ID. Every issue / use / revoke lands in a hash-chained
audit log shaped as AgentTrace schema v1 events.
"""

from .broker import Broker, CredentialRequest, UseResult
from .clock import FakeClock, SystemClock
from .policy import Policy, PolicyDecision, Rule
from .tokens import TokenError

__all__ = [
    "Broker",
    "CredentialRequest",
    "FakeClock",
    "Policy",
    "PolicyDecision",
    "Rule",
    "SystemClock",
    "TokenError",
    "UseResult",
]
