"""Clocks. The broker never reads wall time directly: a clock is
injected, so tests and demos run on a deterministic FakeClock and can
step time forward to prove expiry behaviour exactly.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FakeClock:
    """Deterministic clock: fixed start, advances only when told."""

    def __init__(self, start: datetime):
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
