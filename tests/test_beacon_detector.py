from datetime import datetime, timezone

import pytest

from app.beacon_detector import BeaconDetector
from app.contracts import PacketMetadata


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def packet(
    *,
    flags: str = "S",
    source: str = "10.0.0.10",
    destination: str = "198.51.100.20",
    destination_port: int = 443,
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


def test_detector_matches_regular_connection_intervals():
    clock = FakeClock()
    detector = BeaconDetector(
        min_connections=5,
        min_interval_seconds=10,
        max_interval_variance=0.01,
        clock=clock,
    )

    for _ in range(4):
        assert detector.observe(packet()) is None
        clock.advance(30)

    match = detector.observe(packet())

    assert match is not None
    assert match.source_ip == "10.0.0.10"
    assert match.destination_ip == "198.51.100.20"
    assert match.destination_port == 443
    assert match.connections == 5
    assert match.mean_interval_seconds == pytest.approx(30.0)
    assert match.interval_variance == pytest.approx(0.0)


def test_irregular_connection_intervals_do_not_match():
    clock = FakeClock()
    detector = BeaconDetector(
        min_connections=5,
        min_interval_seconds=5,
        max_interval_variance=1.0,
        clock=clock,
    )

    intervals = (10, 40, 12, 60)
    for interval in intervals:
        assert detector.observe(packet()) is None
        clock.advance(interval)

    assert detector.observe(packet()) is None


def test_fast_bursts_are_not_classified_as_beaconing():
    clock = FakeClock()
    detector = BeaconDetector(
        min_connections=4,
        min_interval_seconds=10,
        max_interval_variance=0.01,
        clock=clock,
    )

    for _ in range(3):
        assert detector.observe(packet()) is None
        clock.advance(1)

    assert detector.observe(packet()) is None


def test_syn_ack_and_non_tcp_packets_are_ignored():
    detector = BeaconDetector(min_connections=3)

    assert detector.observe(packet(flags="SA")) is None
    udp = packet(destination_port=53).model_copy(
        update={"protocol": "UDP", "tcp_flags": None}
    )
    assert detector.observe(udp) is None
    assert detector.snapshot().tracked_events == 0


def test_expiry_and_flow_bounds_are_enforced():
    clock = FakeClock()
    detector = BeaconDetector(
        min_connections=3,
        window_seconds=5,
        max_flows=1,
        clock=clock,
    )

    detector.observe(packet(source="10.0.0.1"))
    clock.advance(6)
    detector.observe(packet(source="10.0.0.2"))

    snapshot = detector.snapshot()
    assert snapshot.expired_events == 1
    assert snapshot.tracked_keys == 1


def test_invalid_configuration_is_rejected():
    with pytest.raises(ValueError, match="min_connections"):
        BeaconDetector(min_connections=2)

    with pytest.raises(ValueError, match="max_events_per_flow"):
        BeaconDetector(min_connections=5, max_events_per_flow=4)
