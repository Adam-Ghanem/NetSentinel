from app.event_windows import BoundedEventWindows


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def test_window_expires_events_deterministically():
    clock = FakeClock()
    windows = BoundedEventWindows[str, int](window_seconds=10, clock=clock)

    windows.add("source-a", 1)
    clock.advance(5)
    windows.add("source-a", 2)
    clock.advance(6)

    assert windows.values("source-a") == (2,)
    assert windows.snapshot().expired_events == 1


def test_window_enforces_per_key_event_limit():
    windows = BoundedEventWindows[str, int](
        window_seconds=60,
        max_events_per_key=2,
        clock=lambda: 0.0,
    )

    windows.add("source-a", 1)
    windows.add("source-a", 2)
    windows.add("source-a", 3)

    assert windows.values("source-a") == (2, 3)
    assert windows.snapshot().dropped_events == 1


def test_window_evicts_least_recently_used_key():
    windows = BoundedEventWindows[str, int](
        window_seconds=60,
        max_keys=2,
        clock=lambda: 0.0,
    )

    windows.add("source-a", 1)
    windows.add("source-b", 2)
    assert windows.values("source-a") == (1,)
    windows.add("source-c", 3)

    assert windows.values("source-a") == (1,)
    assert windows.values("source-b") == ()
    assert windows.values("source-c") == (3,)
    snapshot = windows.snapshot()
    assert snapshot.evicted_keys == 1
    assert snapshot.dropped_events == 1


def test_snapshot_is_aggregate_and_does_not_expose_keys_or_payloads():
    windows = BoundedEventWindows[str, dict[str, str]](
        window_seconds=60,
        clock=lambda: 0.0,
    )
    windows.add("192.0.2.10", {"secret": "payload"})

    snapshot = windows.snapshot()

    assert snapshot.tracked_keys == 1
    assert snapshot.tracked_events == 1
    assert "192.0.2.10" not in repr(snapshot)
    assert "payload" not in repr(snapshot)


def test_invalid_limits_fail_fast():
    invalid_arguments = [
        {"window_seconds": 0},
        {"window_seconds": 1, "max_keys": 0},
        {"window_seconds": 1, "max_events_per_key": 0},
    ]

    for arguments in invalid_arguments:
        try:
            BoundedEventWindows(**arguments)
        except ValueError:
            continue
        raise AssertionError(f"Expected ValueError for {arguments}")
