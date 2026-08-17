import pytest

from app.detector_policies import DetectorKind, DetectorWindowPolicy


def test_policy_rejects_zero_event_budget():
    with pytest.raises(ValueError):
        DetectorWindowPolicy(max_events=0, max_distinct_values_per_key=1)


def test_policy_rejects_distinct_budget_above_event_budget():
    with pytest.raises(ValueError):
        DetectorWindowPolicy(max_events=10, max_distinct_values_per_key=11)


def test_policy_defaults_are_keyed_by_supported_detector_kind():
    assert {DetectorKind.SCAN, DetectorKind.FLOOD, DetectorKind.BEACON} == set(DetectorKind)
