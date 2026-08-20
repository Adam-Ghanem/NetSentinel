from __future__ import annotations

from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Hashable

from app.detector_policies import DetectorKind, DetectorWindowPolicy, get_detector_policy
from app.event_windows import BoundedEventWindows


@dataclass(frozen=True, slots=True)
class DetectorObservation:
    """Minimal normalized observation required by stateful detectors."""

    key: Hashable
    value: Hashable
    observed_at: float


@dataclass(frozen=True, slots=True)
class DetectorSignal:
    """Sanitized detector result without packet payloads or identifiers."""

    kind: DetectorKind
    triggered: bool
    score: float
    threshold: float
    sample_count: int


class StatefulDetector:
    """Evaluate one detector family over an explicitly bounded event window."""

    def __init__(self, policy: DetectorWindowPolicy, *, threshold: int | float, clock=None) -> None:
        if threshold <= 0:
            raise ValueError("threshold must be greater than zero")
        self.policy = policy
        self.threshold = float(threshold)
        self._windows = BoundedEventWindows.from_policy(policy, clock=clock) if clock else BoundedEventWindows.from_policy(policy)

    def observe(self, observation: DetectorObservation) -> DetectorSignal:
        value = (observation.value, observation.observed_at) if self.policy.kind is DetectorKind.BEACON else observation.value
        count = self._windows.add(observation.key, value, observed_at=observation.observed_at)
        values = self._windows.values(observation.key, now=observation.observed_at)

        if self.policy.kind is DetectorKind.SCAN:
            score = float(len(set(values)))
        elif self.policy.kind is DetectorKind.FLOOD:
            score = float(count)
        else:
            timestamps = [item[1] for item in values]
            intervals = [b - a for a, b in zip(timestamps, timestamps[1:]) if b > a]
            if not intervals:
                score = 0.0
            else:
                average = mean(intervals)
                deviation = pstdev(intervals) if len(intervals) > 1 else 0.0
                score = 1.0 / (1.0 + deviation / average) if average > 0 else 0.0

        return DetectorSignal(
            kind=self.policy.kind,
            triggered=score >= self.threshold,
            score=score,
            threshold=self.threshold,
            sample_count=len(values),
        )


def build_detector(kind: DetectorKind, *, threshold: int | float, clock=None) -> StatefulDetector:
    """Build a detector with the reviewed bounded policy for its family."""

    return StatefulDetector(get_detector_policy(kind), threshold=threshold, clock=clock)
