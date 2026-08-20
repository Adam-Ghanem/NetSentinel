import pytest

from app.detector_policies import DetectorKind, DetectorWindowPolicy
from app.stateful_detectors import DetectorObservation, StatefulDetector, build_detector


class Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def test_scan_scores_distinct_destinations_within_window():
    clock = Clock()
    detector = build_detector(DetectorKind.SCAN, threshold=3, clock=clock)

    for port in (22, 80, 443):
        signal = detector.observe(DetectorObservation("source-a", port, clock.value))

    assert signal.triggered is True
    assert signal.score == 3.0
    assert signal.sample_count == 3


def test_flood_scores_event_volume_and_expires_old_events():
    clock = Clock()
    detector = build_detector(DetectorKind.FLOOD, threshold=3, clock=clock)

    detector.observe(DetectorObservation("source-a", "packet", clock.value))
    clock.advance(1)
    detector.observe(DetectorObservation("source-a", "packet", clock.value))
    clock.advance(1)
    signal = detector.observe(DetectorObservation("source-a", "packet", clock.value))

    assert signal.triggered is True
    assert signal.score == 3.0

    clock.advance(11)
    signal = detector.observe(DetectorObservation("source-a", "packet", clock.value))
    assert signal.triggered is False
    assert signal.sample_count == 1


def test_beacon_scores_stable_intervals():
    clock = Clock()
    detector = build_detector(DetectorKind.BEACON, threshold=0.9, clock=clock)

    for offset in (0, 10, 20, 30):
        clock.value = offset
        signal = detector.observe(DetectorObservation("source-a", "dest-a", clock.value))

    assert signal.triggered is True
    assert signal.score == pytest.approx(1.0)
    assert signal.sample_count == 4


def test_beacon_downgrades_irregular_intervals():
    clock = Clock()
    detector = build_detector(DetectorKind.BEACON, threshold=0.9, clock=clock)

    for offset in (0, 5, 20, 23):
        clock.value = offset
        signal = detector.observe(DetectorObservation("source-a", "dest-a", clock.value))

    assert signal.triggered is False
    assert 0.0 < signal.score < 0.9


def test_detector_rejects_non_positive_thresholds():
    policy = DetectorWindowPolicy(DetectorKind.SCAN, 60, 10, 10, 10)

    with pytest.raises(ValueError, match="threshold"):
        StatefulDetector(policy, threshold=0)
