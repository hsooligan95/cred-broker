"""Emit-side AgentTrace event emission — optional, off by default.

Follows the pattern factory-floor-agent established: when a trace ID
is supplied via the environment — ``CREDBROKER_TRACE_ID``, falling
back to ``AGENTTRACE_TRACE_ID`` — the broker's audit events are also
written, in pre-store AgentTrace schema v1 shape (core fields only;
the AgentTrace store assigns ``seq`` / ``prev_hash`` / ``hash`` on
ingest), to the path in ``CREDBROKER_TRACE_OUT`` (default:
``./cred-broker-trace.jsonl``).

Every event is reshaped only from the broker's computed state: the
policy engine's decision values, the minted claims, the use checks'
outcomes. Nothing is narrated. Policy decisions keep
``kind: "decision_record"`` because the policy branch computed them
from the values in the payload. With no trace ID in the environment,
nothing extra is written and behaviour is unchanged.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULT_OUT = "cred-broker-trace.jsonl"
CORE_FIELDS = ("schema_version", "trace_id", "ts", "source", "agent",
               "type", "kind", "payload")


def trace_id_from_env(env: dict | None = None) -> str | None:
    env = os.environ if env is None else env
    return env.get("CREDBROKER_TRACE_ID") or env.get("AGENTTRACE_TRACE_ID") or None


def to_trace_event(audit_event: dict) -> dict:
    """Strip store fields, leaving a pre-store AgentTrace v1 event."""
    return {k: audit_event[k] for k in CORE_FIELDS}


def emit_events_if_configured(audit_events: list[dict], *,
                              trace_id: str | None = None) -> Path | None:
    """Append the given audit events to the trace file, if configured.

    Emission is configured when a trace ID is in the environment (an
    explicit ``trace_id`` argument overrides the environment lookup,
    for callers running a traced session programmatically). Only
    events carrying that trace ID are written. Returns the path
    written, or None.
    """
    if trace_id is None:
        trace_id = trace_id_from_env()
    if not trace_id:
        return None
    out = Path(os.environ.get("CREDBROKER_TRACE_OUT", DEFAULT_OUT))
    with out.open("a", encoding="utf-8") as fh:
        for event in audit_events:
            if event["trace_id"] == trace_id:
                fh.write(json.dumps(to_trace_event(event)) + "\n")
    return out
