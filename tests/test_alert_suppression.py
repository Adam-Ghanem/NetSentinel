from datetime import datetime, timezone

import pytest

from app.alert_suppression import AlertSuppressor
from app.contracts import DetectionRule, PacketMetadata
from app.detection_engine import DetectionEngine

TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


class MutableClock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class StubRulesEngine:
    def evaluate_rules(self, parsed_packet, connections, traffic_stats):
        assert isinstance(parsed_packet, PacketMetadata)
        return [
            DetectionRule(
                name="Repeated port rule",
                description="Detect repeated traffic to a selected port.",
                severity="High",
                protocol="TCP",
                dest_port=443,
                mitre_attack="T1046",
            )
        ]


class CapturingDatabase:
    def __init__(self) -> None:
        self.alerts = []

    def insert_alert(self, alert_data) -> None:
        self.alerts.append(alert_data)


def packet_data(source_ip: str = "192.0.2.10") -> dict:
    return {
        "timestamp": TIMESTAMP,
        "source_ip": source_ip,
        "dest_ip": "198.51.100.20",
        "protocol": "TCP",
        "source_port": 51515,
        "dest_port": 443,
        "packet_size": 128,
    }


def test_suppressor_rejects_invalid_limits():
    with pytest.raises(ValueError, match="cooldown_seconds"):
        AlertSuppressor(cooldown_seconds=0)

    with pytest.raises(ValueError, match="max_entries"):
        AlertSuppressor(max_entries=0)


def test_duplicate_is_suppressed_until_cooldown_expires():
    clock = MutableClock()
    suppressor = AlertSuppressor(cooldown_seconds=30, clock=clock)

    assert suppressor.evaluate("rule|source").emit is True
    clock.value = 29.9
    assert suppressor.evaluate("rule|source").emit is False

    clock.value = 30
    decision = suppressor.evaluate("rule|source")
    assert decision.emit is True
    assert decision.reason == "new-or-expired"


def test_state_is_bounded_by_maximum_entries():
    clock = MutableClock()
    suppressor = AlertSuppressor(
        cooldown_seconds=300,
        max_entries=2,
        clock=clock,
    )

    suppressor.evaluate("first")
    clock.value = 1
    suppressor.evaluate("second")
    clock.value = 2
    suppressor.evaluate("third")

    assert suppressor.tracked_entries == 2
    assert suppressor.evaluate("first").emit is True


def test_detection_engine_suppresses_duplicate_persistence(monkeypatch):
    monkeypatch.setattr("app.detection_engine.ThreatIntel.sync_otx", lambda self: None)
    monkeypatch.setattr(
        "app.detection_engine.ThreatIntel.check_ip",
        lambda self, value: False,
    )
    clock = MutableClock()
    database = CapturingDatabase()
    suppressor = AlertSuppressor(cooldown_seconds=60, clock=clock)
    engine = DetectionEngine(
        StubRulesEngine(),
        database,
        alert_suppressor=suppressor,
        now=lambda: TIMESTAMP,
    )

    engine.run_detections(packet_data(), {}, {})
    engine.run_detections(packet_data(), {}, {})

    assert len(database.alerts) == 1
    assert database.alerts[0]["timestamp"] == TIMESTAMP


def test_suppression_key_keeps_distinct_sources_independent(monkeypatch):
    monkeypatch.setattr("app.detection_engine.ThreatIntel.sync_otx", lambda self: None)
    monkeypatch.setattr(
        "app.detection_engine.ThreatIntel.check_ip",
        lambda self, value: False,
    )
    database = CapturingDatabase()
    engine = DetectionEngine(
        StubRulesEngine(),
        database,
        alert_suppressor=AlertSuppressor(cooldown_seconds=60),
    )

    engine.run_detections(packet_data("192.0.2.10"), {}, {})
    engine.run_detections(packet_data("192.0.2.11"), {}, {})

    assert len(database.alerts) == 2
