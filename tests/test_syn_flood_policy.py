import pytest
from pydantic import ValidationError

from app.syn_flood_policy import SynFloodPolicy


def test_defaults_are_bounded_and_operational():
    policy = SynFloodPolicy()

    assert policy.threshold == 100
    assert policy.window_seconds == 10.0
    assert policy.max_flows == 10_000
    assert policy.max_events_per_flow == 1_000


def test_policy_is_immutable():
    policy = SynFloodPolicy()

    with pytest.raises(ValidationError, match="frozen"):
        policy.threshold = 200


def test_threshold_must_represent_multiple_syn_packets():
    with pytest.raises(ValidationError, match="threshold"):
        SynFloodPolicy(threshold=1)


def test_event_capacity_must_cover_threshold():
    with pytest.raises(ValidationError, match="max_events_per_flow"):
        SynFloodPolicy(threshold=10, max_events_per_flow=9)


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError, match="extra"):
        SynFloodPolicy(unbounded=True)
