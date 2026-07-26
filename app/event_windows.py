from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Callable, Hashable
from dataclasses import dataclass
from time import monotonic
from typing import Generic, TypeVar

KeyT = TypeVar("KeyT", bound=Hashable)
EventT = TypeVar("EventT")


@dataclass(frozen=True, slots=True)
class WindowSnapshot:
    """Aggregate state metrics without exposing event keys or payloads."""

    tracked_keys: int
    tracked_events: int
    expired_events: int
    evicted_keys: int
    dropped_events: int


@dataclass(frozen=True, slots=True)
class _TimedEvent(Generic[EventT]):
    observed_at: float
    value: EventT


class BoundedEventWindows(Generic[KeyT, EventT]):
    """Maintain deterministic, bounded sliding windows keyed by detector identity."""

    def __init__(
        self,
        *,
        window_seconds: float,
        max_keys: int = 10_000,
        max_events_per_key: int = 1_000,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")
        if max_keys <= 0:
            raise ValueError("max_keys must be greater than zero")
        if max_events_per_key <= 0:
            raise ValueError("max_events_per_key must be greater than zero")

        self.window_seconds = float(window_seconds)
        self.max_keys = max_keys
        self.max_events_per_key = max_events_per_key
        self._clock = clock
        self._windows: OrderedDict[KeyT, deque[_TimedEvent[EventT]]] = OrderedDict()
        self._expired_events = 0
        self._evicted_keys = 0
        self._dropped_events = 0

    def add(self, key: KeyT, value: EventT, *, observed_at: float | None = None) -> int:
        """Add an event and return the number of events remaining in its window."""

        now = self._clock() if observed_at is None else observed_at
        self.expire(now=now)

        if key not in self._windows and len(self._windows) >= self.max_keys:
            _, evicted = self._windows.popitem(last=False)
            self._evicted_keys += 1
            self._dropped_events += len(evicted)

        window = self._windows.setdefault(key, deque())
        self._windows.move_to_end(key)
        window.append(_TimedEvent(observed_at=now, value=value))

        while len(window) > self.max_events_per_key:
            window.popleft()
            self._dropped_events += 1

        return len(window)

    def values(self, key: KeyT, *, now: float | None = None) -> tuple[EventT, ...]:
        """Return an immutable view of current values for one key."""

        current = self._clock() if now is None else now
        self.expire(now=current)
        window = self._windows.get(key)
        if window is None:
            return ()
        self._windows.move_to_end(key)
        return tuple(event.value for event in window)

    def count(self, key: KeyT, *, now: float | None = None) -> int:
        """Return the current event count for one key."""

        return len(self.values(key, now=now))

    def expire(self, *, now: float | None = None) -> int:
        """Expire stale events and empty keys, returning the number removed."""

        current = self._clock() if now is None else now
        cutoff = current - self.window_seconds
        removed = 0
        empty_keys: list[KeyT] = []

        for key, window in self._windows.items():
            while window and window[0].observed_at < cutoff:
                window.popleft()
                removed += 1
            if not window:
                empty_keys.append(key)

        for key in empty_keys:
            del self._windows[key]

        self._expired_events += removed
        return removed

    def snapshot(self) -> WindowSnapshot:
        """Return aggregate counters without mutating expiry state."""

        return WindowSnapshot(
            tracked_keys=len(self._windows),
            tracked_events=sum(len(window) for window in self._windows.values()),
            expired_events=self._expired_events,
            evicted_keys=self._evicted_keys,
            dropped_events=self._dropped_events,
        )
