from datetime import datetime, timezone

import pytest

from app.alert_suppression import AlertSuppressor
from app.detection_engine import DetectionEngine
from app.detection_observability import DetectionObservability
from app.event_windows import WindowSnapshot


class Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


def test_snapshot_exposes_sanitized_suppression_metrics():
    clock = Clock()
    suppressor = AlertSuppressor(clock=clock)
    generated_at = datetime(2026, 7, 25, 13, 0, tzinfo=timezone.utc)
    observability = DetectionObservability(suppressor, now=lambda: generated_at)

    suppressor.evaluate("sensitive-alert-key")
    suppressor.evaluate("sensitive-alert-key")

    payload = observability.snapshot().to_dict()

    assert payload == {
        "generated_at": "2026-07-25T13:00:00+00:00",
        "suppression": {
            "emitted": 1,
            "suppressed": 1,
            "expired": 0,
            "evicted": 0,
            "tracked_entries": 1,
        },
        "port_scan_state": None,
        "derived": {
            "total_decisions": 2,
            "suppression_ratio": 0.5,
        },
    }
    assert "sensitive-alert-key" not in str(payload)


def test_snapshot_exposes_sanitized_port_scan_state_pressure():
    snapshot = WindowSnapshot(
        tracked_keys=4,
        tracked_events=17,
        expired_events=9,
        evicted_keys=2,
        dropped_events=3,
    )
    observability = DetectionObservability(
        AlertSuppressor(),
        port_scan_snapshot=lambda: snapshot,
    )

    payload = observability.snapshot().to_dict()

    assert payload["port_scan_state"] == {
        "tracked_keys": 4,
        "tracked_events": 17,
        "expired_events": 9,
        "evicted_keys": 2,
        "dropped_events": 3,
        "cardinality_limited_events": 0,
    }
    assert "source_ip" not in str(payload)
    assert "dest_port" not in str(payload)


def test_snapshot_is_immutable_point_in_time_view():
    suppressor = AlertSuppressor()
    observability = DetectionObservability(suppressor)

    first = observability.snapshot()
    suppressor.evaluate("alert-a")
    second = observability.snapshot()

    assert first.suppression.emitted == 0
    assert second.suppression.emitted == 1


def test_empty_snapshot_uses_zero_suppression_ratio():
    snapshot = DetectionObservability(AlertSuppressor()).snapshot()

    assert snapshot.total_decisions == 0
    assert snapshot.suppression_ratio == 0.0


def test_observability_rejects_naive_timestamps():
    observability = DetectionObservability(
        AlertSuppressor(),
        now=lambda: datetime(2026, 7, 25, 13, 0),
    )

    with pytest.raises(ValueError, match="timezone-aware"):
        observability.snapshot()


def test_detection_engine_exposes_same_read_only_snapshot():
    suppressor = AlertSuppressor()
    engine = object.__new__(DetectionEngine)
    engine.observability = DetectionObservability(
        suppressor,
        port_scan_snapshot=lambda: WindowSnapshot(1, 2, 3, 4, 5),
    )

    suppressor.evaluate("alert-a")
    snapshot = engine.metrics_snapshot()

    assert snapshot.suppression.emitted == 1
    assert snapshot.port_scan_state == WindowSnapshot(1, 2, 3, 4, 5)
    assert snapshot.port_scan_state.cardinality_limited_events == 0
