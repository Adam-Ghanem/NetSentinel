from app.event_windows import BoundedEventWindows


def test_snapshot_tracks_events_without_recounting_window_contents():
    windows = BoundedEventWindows[str, int](
        window_seconds=60,
        max_events_per_key=2,
        max_keys=2,
        clock=lambda: 0.0,
    )

    windows.add("source-a", 1)
    windows.add("source-a", 2)
    windows.add("source-a", 3)
    windows.add("source-b", 4)
    windows.add("source-c", 5)

    snapshot = windows.snapshot()

    assert snapshot.tracked_keys == 2
    assert snapshot.tracked_events == 3
    assert snapshot.dropped_events == 2


def test_snapshot_count_decreases_when_events_expire():
    now = 0.0

    def clock() -> float:
        return now

    windows = BoundedEventWindows[str, int](window_seconds=10, clock=clock)
    windows.add("source-a", 1)
    windows.add("source-a", 2)

    now = 11.0
    assert windows.values("source-a") == ()
    snapshot = windows.snapshot()

    assert snapshot.tracked_events == 0
    assert snapshot.tracked_keys == 0
    assert snapshot.expired_events == 2
