from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.port_scan_detector import UniquePortScanDetector
from app.port_scan_policy import PortScanPolicy


def test_policy_defaults_are_bounded_and_immutable():
    policy = PortScanPolicy()

    assert policy.threshold == 5
    assert policy.window_seconds == 10.0
    assert policy.max_sources == 10_000
    assert policy.max_events_per_source == 1_000

    with pytest.raises(ValidationError):
        policy.threshold = 10


def test_policy_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        PortScanPolicy.model_validate({"threshold": 5, "unexpected": True})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("threshold", 1),
        ("window_seconds", 0),
        ("max_sources", 0),
        ("max_events_per_source", 1),
    ],
)
def test_policy_rejects_unsafe_bounds(field: str, value: int | float):
    with pytest.raises(ValidationError):
        PortScanPolicy.model_validate({field: value})


def test_policy_rejects_capacity_below_threshold():
    with pytest.raises(ValidationError, match="at least threshold"):
        PortScanPolicy(threshold=20, max_events_per_source=19)


def test_detector_applies_validated_policy():
    policy = PortScanPolicy(
        threshold=7,
        window_seconds=30,
        max_sources=200,
        max_events_per_source=50,
    )

    detector = UniquePortScanDetector(policy=policy)

    assert detector.policy is policy
    assert detector.threshold == 7
    assert detector.window_seconds == 30


def test_detector_preserves_legacy_keyword_configuration():
    detector = UniquePortScanDetector(
        threshold=8,
        window_seconds=45,
        max_sources=300,
        max_events_per_source=60,
    )

    assert detector.policy == PortScanPolicy(
        threshold=8,
        window_seconds=45,
        max_sources=300,
        max_events_per_source=60,
    )


def test_detector_rejects_ambiguous_policy_configuration():
    with pytest.raises(ValueError, match="cannot be combined"):
        UniquePortScanDetector(policy=PortScanPolicy(), threshold=6)
