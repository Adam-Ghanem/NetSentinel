from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from time import monotonic


@dataclass(frozen=True, slots=True)
class SuppressionDecision:
    """Explain whether an alert should be emitted or suppressed."""

    emit: bool
    reason: str


@dataclass(frozen=True, slots=True)
class SuppressionMetrics:
    """Expose cumulative suppression outcomes without leaking alert keys."""

    emitted: int
    suppressed: int
    expired: int
    evicted: int
    tracked_entries: int


@dataclass(frozen=True, slots=True)
class _SuppressionEntry:
    emitted_at: float
    expires_at: float


class AlertSuppressor:
    """Bound duplicate-alert state by cooldown, expiry, and maximum entries."""

    def __init__(
        self,
        *,
        cooldown_seconds: float = 60.0,
        max_entries: int = 10_000,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if cooldown_seconds <= 0:
            raise ValueError("cooldown_seconds must be greater than zero")
        if max_entries <= 0:
            raise ValueError("max_entries must be greater than zero")

        self.cooldown_seconds = cooldown_seconds
        self.max_entries = max_entries
        self._clock = clock
        self._last_emitted: OrderedDict[str, _SuppressionEntry] = OrderedDict()
        self._emitted = 0
        self._suppressed = 0
        self._expired = 0
        self._evicted = 0

    @property
    def tracked_entries(self) -> int:
        """Return the current number of retained suppression keys."""

        return len(self._last_emitted)

    def metrics(self) -> SuppressionMetrics:
        """Return a sanitized cumulative metrics snapshot."""

        return SuppressionMetrics(
            emitted=self._emitted,
            suppressed=self._suppressed,
            expired=self._expired,
            evicted=self._evicted,
            tracked_entries=self.tracked_entries,
        )

    def evaluate(
        self,
        key: str,
        *,
        cooldown_seconds: float | None = None,
    ) -> SuppressionDecision:
        """Return a deterministic decision using an optional per-alert cooldown."""

        if not key:
            raise ValueError("suppression key must not be empty")
        effective_cooldown = (
            self.cooldown_seconds if cooldown_seconds is None else cooldown_seconds
        )
        if effective_cooldown <= 0:
            raise ValueError("cooldown_seconds must be greater than zero")

        now = self._clock()
        self._expire(now)
        previous = self._last_emitted.get(key)

        if previous is not None and now < previous.expires_at:
            self._suppressed += 1
            return SuppressionDecision(emit=False, reason="duplicate-within-cooldown")

        self._last_emitted[key] = _SuppressionEntry(
            emitted_at=now,
            expires_at=now + effective_cooldown,
        )
        self._last_emitted.move_to_end(key)
        self._emitted += 1
        self._enforce_capacity()
        return SuppressionDecision(emit=True, reason="new-or-expired")

    def _expire(self, now: float) -> None:
        expired_keys = [
            key for key, entry in self._last_emitted.items() if now >= entry.expires_at
        ]
        for key in expired_keys:
            del self._last_emitted[key]
        self._expired += len(expired_keys)

    def _enforce_capacity(self) -> None:
        while len(self._last_emitted) > self.max_entries:
            self._last_emitted.popitem(last=False)
            self._evicted += 1
