from datetime import datetime, timezone

import pytest

from app.contracts import PacketMetadata
from app.syn_flood_detector import SynFloodDetector


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def packet(
    *,
    destination_port: int = 443,
    flags: str = "S",
    source: str = "10.0.0.10",
    destination: str = "10.0.0.20",
) -> PacketMetadata:
    return PacketMetadata(
        timestamp=datetime.now(timezone.utc),
        source_ip=source,
        dest_ip=destination,
        protocol="TCP",
        source_port=40000,
        dest_port=destination_port,
        packet_size=60,
        tcp_flags=flags,
    )


def test_detector_matches_when_syn_threshold_is_reached():
    detector = SynFloodDetector(threshold=3)

    assert detector.observe(packet()) is None
    assert detector.observe(packet()) is None

    match = detector.observe(packet())

    assert match is not None
    assert match.source_ip == "10.0.0.10"
    assert match.destination_ip == "10.0.0.20"
    assert match.destination_port == 443
    assert match.syn_packets == 3


def test_syn_ack_and_non_tcp_packets_are_ignored():
    detector = SynFloodDetector(threshold=2)

    assert detector.observe(packet(flags="SA")) is None
    udp = packet(destination_port=53).model_copy(
        update={"protocol": "UDP", "tcp_flags": None}
    )
    assert detector.observe(udp) is None
    assert detector.snapshot().tracked_events == 0


def test_flows_are_isolated_by_destination_and_port():
    detector = SynFloodDetector(threshold=2)

    assert detector.observe(packet(destination_port=443)) is None
    assert detector.observe(packet(destination_port=8443)) is None
    assert detector.observe(packet(destination_port=443)) is not None


def test_expired_syn_events_do_not_contribute_to_threshold():
    clock = FakeClock()
    detector = SynFloodDetector(threshold=3, window_seconds=5, clock=clock)

    detector.observe(packet())
    detector.observe(packet())
    clock.advance(6)

    assert detector.observe(packet()) is None
    assert detector.snapshot().expired_events == 2


def test_state_is_bounded_by_flow_capacity():
    detector = SynFloodDetector(threshold=2, max_flows=1)

    detector.observe(packet(source="10.0.0.1"))
    detector.observe(packet(source="10.0.0.2"))

    snapshot = detector.snapshot()
    assert snapshot.tracked_keys == 1
    assert snapshot.evicted_keys == 1


def test_invalid_capacity_is_rejected():
    with pytest.raises(ValueError, match="threshold"):
        SynFloodDetector(threshold=1)

    with pytest.raises(ValueError, match="max_events_per_flow"):
        SynFloodDetector(threshold=5, max_events_per_flow=4)
