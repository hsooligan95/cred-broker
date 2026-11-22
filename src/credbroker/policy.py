"""Policy engine: approve, deny, or scope down a credential request.

A Rule is a ceiling for one agent: the broadest resource it may ever
touch, the actions it may ever perform there, and the longest TTL it
may ever be granted. A request is granted the *intersection* of what
it asks for and what its rule allows:

- nothing intersects        -> DENY (default deny; no rule = no access)
- intersection == request   -> ALLOW as asked
- intersection <  request   -> SCOPE DOWN: grant the narrower credential
  and say exactly what was cut. The agent gets useful access without
  the broad access it asked for, and the cut is on the record.

Resource matching is exact or prefix: rule resource ``db/factory/*``
covers ``db/factory/pumps``; a request for ``db/*`` is broader than the
rule, so it is scoped down to the rule's resource.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    agent: str
    resource: str  # ceiling, may end in "/*"
    actions: frozenset[str]
    max_ttl_seconds: int


@dataclass
class PolicyDecision:
    allowed: bool
    scoped_down: bool
    resource: str | None = None
    actions: tuple[str, ...] = ()
    ttl_seconds: int = 0
    cuts: tuple[str, ...] = field(default_factory=tuple)
    reason: str = ""


def _covers(ceiling: str, resource: str) -> bool:
    """True if `resource` is at or under `ceiling`."""
    if ceiling.endswith("/*"):
        return resource == ceiling[:-2] or resource.startswith(ceiling[:-1])
    return resource == ceiling


def _narrower(a: str, b: str) -> str:
    """The narrower of two resources where one covers the other."""
    return a if _covers(b, a) else b


class Policy:
    def __init__(self, rules: list[Rule]):
        self._rules = rules

    def evaluate(self, *, agent: str, resource: str,
                 actions: tuple[str, ...], ttl_seconds: int) -> PolicyDecision:
        rule = next((r for r in self._rules if r.agent == agent), None)
        if rule is None:
            return PolicyDecision(False, False,
                                  reason=f"no policy rule for agent {agent!r} (default deny)")
        if not (_covers(rule.resource, resource) or _covers(resource, rule.resource)):
            return PolicyDecision(
                False, False,
                reason=f"resource {resource!r} is outside agent {agent!r}'s "
                       f"ceiling {rule.resource!r}")
        granted_resource = _narrower(resource, rule.resource)
        granted_actions = tuple(a for a in actions if a in rule.actions)
        if not granted_actions:
            return PolicyDecision(
                False, False,
                reason=f"none of the requested actions {list(actions)} are "
                       f"allowed for agent {agent!r} on {rule.resource!r}")
        granted_ttl = min(ttl_seconds, rule.max_ttl_seconds)
        cuts = []
        if granted_resource != resource:
            cuts.append(f"resource {resource!r} -> {granted_resource!r}")
        dropped = [a for a in actions if a not in granted_actions]
        if dropped:
            cuts.append(f"actions dropped: {', '.join(dropped)}")
        if granted_ttl != ttl_seconds:
            cuts.append(f"ttl {ttl_seconds}s -> {granted_ttl}s")
        return PolicyDecision(
            allowed=True,
            scoped_down=bool(cuts),
            resource=granted_resource,
            actions=granted_actions,
            ttl_seconds=granted_ttl,
            cuts=tuple(cuts),
            reason="granted as asked" if not cuts else "granted scoped down",
        )
