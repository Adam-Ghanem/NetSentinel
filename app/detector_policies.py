from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class DetectorKind(StrEnum):
    """Stateful detector families with explicit bounded-window policies."""

    SCAN = "scan"
    FLOOD = "flood"
    BEACON = "beacon"


@dataclass(frozen=True, slots=True)
class DetectorWindowPolicy:
    """Validated state budget for one detector family."""

    kind: DetectorKind
    window_seconds: float
    max_keys: int
    max_events_per_key: int
    max_distinct_values_per_key: int

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")
        if self.max_keys <= 0:
            raise ValueError("max_keys must be greater than zero")
        if self.max_events_per_key <= 0:
            raise ValueError("max_events_per_key must be greater than zero")
        if self.max_distinct_values_per_key <= 0:
            raise ValueError("max_distinct_values_per_key must be greater than zero")


DEFAULT_DETECTOR_POLICIES: dict[DetectorKind, DetectorWindowPolicy] = {
    DetectorKind.SCAN: DetectorWindowPolicy(
        kind=DetectorKind.SCAN,
        window_seconds=60,
        max_keys=2_000,
        max_events_per_key=256,
        max_distinct_values_per_key=128,
    ),
    DetectorKind.FLOOD: DetectorWindowPolicy(
        kind=DetectorKind.FLOOD,
        window_seconds=10,
        max_keys=4_000,
        max_events_per_key=512,
        max_distinct_values_per_key=64,
    ),
    DetectorKind.BEACON: DetectorWindowPolicy(
        kind=DetectorKind.BEACON,
        window_seconds=300,
        max_keys=2_000,
        max_events_per_key=128,
        max_distinct_values_per_key=32,
    ),
}


def get_detector_policy(kind: DetectorKind) -> DetectorWindowPolicy:
    """Return the immutable policy for a detector family."""

    return DEFAULT_DETECTOR_POLICIES[kind]
