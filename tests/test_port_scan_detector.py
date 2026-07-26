from datetime import datetime, timezone

import pytest

from app.contracts import PacketMetadata
from app.port_scan_detector import UniquePortScanDetector


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def packet(*, port: int, flags: str = "S", source: str = "10.0.0.10") -> PacketMetadata:
    return PacketMetadata(
        timestamp=datetime.now(timezone.utc),
        source_ip=source,
        dest_ip="10.0.0.20",
        protocol="TCP",
        source_port=40000,
        dest_port=port,
        packet_size=60,
        tcp_flags=flags,
    )


def test_detector_matches_once_at_unique_port_threshold():
    clock = FakeClock()
    detector = UniquePortScanDetector(threshold=3, clock=clock)

    assert detector.observe(packet(port=22)) is None
    assert detector.observe(packet(port=80)) is None

    match = detector.observe(packet(port=443))

    assert match is not None
    assert match.unique_ports == 3
    assert match.source_ip == "10.0.0.10"
    assert detector.observe(packet(port=8080)) is None


def test_duplicate_ports_do_not_increase_unique_count():
    detector = UniquePortScanDetector(threshold=3)

    assert detector.observe(packet(port=22)) is None
    assert detector.observe(packet(port=22)) is None
    assert detector.observe(packet(port=80)) is None
    assert detector.observe(packet(port=443)) is not None


def test_expired_ports_do_not_contribute_to_match():
    clock = FakeClock()
    detector = UniquePortScanDetector(threshold=3, window_seconds=5, clock=clock)

    detector.observe(packet(port=22))
    detector.observe(packet(port=80))
    clock.advance(6)

    assert detector.observe(packet(port=443)) is None
    assert detector.snapshot().expired_events == 2


def test_syn_ack_and_non_tcp_packets_are_ignored():
    detector = UniquePortScanDetector(threshold=2)

    assert detector.observe(packet(port=22, flags="SA")) is None
    udp = packet(port=53).model_copy(update={"protocol": "UDP", "tcp_flags": None})
    assert detector.observe(udp) is None
    assert detector.snapshot().tracked_events == 0


def test_sources_are_isolated_and_state_is_bounded():
    detector = UniquePortScanDetector(threshold=2, max_sources=1)

    detector.observe(packet(port=22, source="10.0.0.1"))
    detector.observe(packet(port=80, source="10.0.0.2"))

    snapshot = detector.snapshot()
    assert snapshot.tracked_keys == 1
    assert snapshot.evicted_keys == 1


def test_invalid_configuration_is_rejected():
    with pytest.raises(ValueError, match="threshold"):
        UniquePortScanDetector(threshold=1)

    with pytest.raises(ValueError, match="max_events_per_source"):
        UniquePortScanDetector(threshold=5, max_events_per_source=4)
