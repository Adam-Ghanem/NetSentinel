import pytest

from app.detector_policies import (
    DEFAULT_DETECTOR_POLICIES,
    DetectorKind,
    DetectorWindowPolicy,
    get_detector_policy,
)


def test_default_policies_cover_all_stateful_detector_families():
    assert set(DEFAULT_DETECTOR_POLICIES) == {
        DetectorKind.SCAN,
        DetectorKind.FLOOD,
        DetectorKind.BEACON,
    }


def test_detector_policy_lookup_is_stable_and_immutable():
    policy = get_detector_policy(DetectorKind.SCAN)

    assert policy is DEFAULT_DETECTOR_POLICIES[DetectorKind.SCAN]
    assert policy.window_seconds == 60
    assert policy.max_events_per_key == 256
    assert policy.max_distinct_values_per_key == 128


def test_detector_policy_rejects_unbounded_or_invalid_limits():
    invalid = {
        "window_seconds": 0,
        "max_keys": 1,
        "max_events_per_key": 1,
        "max_distinct_values_per_key": 1,
    }

    for field in invalid:
        arguments = {
            "kind": DetectorKind.SCAN,
            "window_seconds": 1,
            "max_keys": 1,
            "max_events_per_key": 1,
            "max_distinct_values_per_key": 1,
        }
        arguments[field] = 0
        with pytest.raises(ValueError):
            DetectorWindowPolicy(**arguments)


def test_policy_values_are_bounded_positive_state_budgets():
    for policy in DEFAULT_DETECTOR_POLICIES.values():
        assert policy.window_seconds > 0
        assert policy.max_keys > 0
        assert policy.max_events_per_key > 0
        assert policy.max_distinct_values_per_key > 0
