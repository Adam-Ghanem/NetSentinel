from app.detector_policies import DEFAULT_DETECTOR_POLICIES, DetectorKind


def test_default_detector_policies_define_bounded_windows():
    assert set(DEFAULT_DETECTOR_POLICIES) == {
        DetectorKind.SCAN,
        DetectorKind.FLOOD,
        DetectorKind.BEACON,
    }
    for policy in DEFAULT_DETECTOR_POLICIES.values():
        assert policy.window.max_events > 0
        assert policy.window.max_distinct_values_per_key > 0


def test_default_detector_policies_use_distinct_state_budgets():
    scan = DEFAULT_DETECTOR_POLICIES[DetectorKind.SCAN]
    flood = DEFAULT_DETECTOR_POLICIES[DetectorKind.FLOOD]
    beacon = DEFAULT_DETECTOR_POLICIES[DetectorKind.BEACON]

    assert scan.window.max_distinct_values_per_key <= scan.window.max_events
    assert flood.window.max_distinct_values_per_key <= flood.window.max_events
    assert beacon.window.max_distinct_values_per_key <= beacon.window.max_events
