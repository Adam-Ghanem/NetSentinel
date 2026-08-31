import pytest
from pydantic import ValidationError

from app.beacon_policy import BeaconPolicy


def test_defaults_define_conservative_periodicity_detection():
    policy = BeaconPolicy()

    assert policy.min_connections == 5
    assert policy.window_seconds == 600.0
    assert policy.min_interval_seconds == 10.0
    assert policy.max_interval_variance == 4.0
    assert policy.max_flows == 10_000
    assert policy.max_events_per_flow == 100


def test_policy_is_immutable():
    policy = BeaconPolicy()

    with pytest.raises(ValidationError, match="frozen"):
        policy.min_connections = 8


def test_connection_threshold_requires_enough_observations():
    with pytest.raises(ValidationError, match="min_connections"):
        BeaconPolicy(min_connections=2)


def test_event_capacity_must_cover_connection_threshold():
    with pytest.raises(ValidationError, match="max_events_per_flow"):
        BeaconPolicy(min_connections=6, max_events_per_flow=5)


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError, match="extra"):
        BeaconPolicy(track_forever=True)
