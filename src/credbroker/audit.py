"""Hash-chained audit log of AgentTrace schema v1 events.

Every broker action — policy decision, issue, use (accepted or
rejected), revoke — is appended as one event carrying the AgentTrace
core fields (``schema_version: "1"``, ``trace_id``, ``ts``, ``source``,
``agent``, ``type``, ``kind``, ``payload``) plus the store fields the
AgentTrace store assigns: ``seq``, ``prev_hash``, ``hash`` (SHA-256
over the canonical JSON of the event without its ``hash`` field, the
same construction agent-trace uses). Rewriting, deleting, or
reordering any entry breaks the chain at that entry, and ``verify``
names the exact ``seq``.

Policy decisions are emitted with ``kind: "decision_record"`` — they
are made by this code branch, at decision time, from the values that
decided them. Everything else is ``kind: "event"``.

Secrets are never written here: payloads carry resource, action,
scope, and outcome — never a secret value and never a full token
(only its ``jti``).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .clock import iso
from .tokens import canonical

SCHEMA_VERSION = "1"
SOURCE = "cred-broker"
GENESIS = "0" * 64


@dataclass
class VerifyResult:
    ok: bool
    count: int
    broken_seq: int | None = None
    detail: str = ""


def _hash(event_without_hash: dict) -> str:
    return hashlib.sha256(canonical(event_without_hash).encode()).hexdigest()


class AuditLog:
    """Append-only JSONL hash chain. One instance per audit file."""

    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path is not None else None
        self.events: list[dict] = []
        self._prev = GENESIS
        if self.path is not None and self.path.exists() \
                and self.path.read_text(encoding="utf-8").strip():
            result = verify(self.path)
            if not result.ok:
                raise ValueError(
                    f"refusing to extend a broken audit chain "
                    f"(seq {result.broken_seq}: {result.detail})")
            self.events = load(self.path)
            self._prev = self.events[-1]["hash"]

    def append(self, *, trace_id: str, ts, agent: str, type: str,
               payload: dict, kind: str = "event") -> dict:
        event = {
            "schema_version": SCHEMA_VERSION,
            "trace_id": trace_id,
            "ts": iso(ts),
            "source": SOURCE,
            "agent": agent,
            "type": type,
            "kind": kind,
            "payload": payload,
            "seq": len(self.events) + 1,
            "prev_hash": self._prev,
        }
        event["hash"] = _hash(event)
        self._prev = event["hash"]
        self.events.append(event)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event) + "\n")
        return event


def load(path: str | Path) -> list[dict]:
    return [json.loads(line)
            for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip()]


def verify(path: str | Path) -> VerifyResult:
    lines = [l for l in Path(path).read_text(encoding="utf-8").splitlines()
             if l.strip()]
    prev = GENESIS
    for i, line in enumerate(lines, start=1):
        entry = json.loads(line)
        if entry.get("schema_version") != SCHEMA_VERSION:
            return VerifyResult(False, len(lines), entry.get("seq", i),
                                f"unsupported schema_version {entry.get('schema_version')!r}")
        if entry["seq"] != i:
            return VerifyResult(False, len(lines), entry.get("seq", i),
                                f"seq discontinuity: position {i} holds seq {entry['seq']}")
        if entry["prev_hash"] != prev:
            return VerifyResult(False, len(lines), entry["seq"],
                                "prev_hash does not match the previous event's hash")
        body = {k: v for k, v in entry.items() if k != "hash"}
        if _hash(body) != entry["hash"]:
            return VerifyResult(False, len(lines), entry["seq"],
                                "hash mismatch: stored event content was altered")
        prev = entry["hash"]
    return VerifyResult(True, len(lines), None, "chain intact")
