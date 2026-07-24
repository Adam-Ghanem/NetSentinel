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
        self._last_emitted: OrderedDict[str, float] = OrderedDict()

    @property
    def tracked_entries(self) -> int:
        """Return the current number of retained suppression keys."""

        return len(self._last_emitted)

    def evaluate(self, key: str) -> SuppressionDecision:
        """Return a deterministic decision and update state only on emission."""

        if not key:
            raise ValueError("suppression key must not be empty")

        now = self._clock()
        self._expire(now)
        previous = self._last_emitted.get(key)

        if previous is not None and now - previous < self.cooldown_seconds:
            return SuppressionDecision(emit=False, reason="duplicate-within-cooldown")

        self._last_emitted[key] = now
        self._last_emitted.move_to_end(key)
        self._enforce_capacity()
        return SuppressionDecision(emit=True, reason="new-or-expired")

    def _expire(self, now: float) -> None:
        expiry_cutoff = now - self.cooldown_seconds
        while self._last_emitted:
            _, emitted_at = next(iter(self._last_emitted.items()))
            if emitted_at > expiry_cutoff:
                break
            self._last_emitted.popitem(last=False)

    def _enforce_capacity(self) -> None:
        while len(self._last_emitted) > self.max_entries:
            self._last_emitted.popitem(last=False)
