from datetime import datetime, timezone

from app.beacon_detector import BeaconDetector
from app.detection_engine import DetectionEngine
from app.syn_flood_detector import SynFloodDetector

TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class EmptyRulesEngine:
    def evaluate_rules(self, parsed_packet, connections, traffic_stats):
        return []


class CapturingDatabase:
    def __init__(self) -> None:
        self.alerts = []

    def insert_alert(self, alert_data) -> None:
        self.alerts.append(alert_data)


def syn_packet(*, destination_port: int = 443):
    return {
        "timestamp": TIMESTAMP,
        "source_ip": "192.0.2.10",
        "dest_ip": "198.51.100.20",
        "protocol": "TCP",
        "source_port": 51515,
        "dest_port": destination_port,
        "tcp_flags": "S",
        "packet_size": 64,
    }


def disable_threat_intel(monkeypatch) -> None:
    monkeypatch.setattr("app.detection_engine.ThreatIntel.sync_otx", lambda self: None)
    monkeypatch.setattr(
        "app.detection_engine.ThreatIntel.check_ip", lambda self, value: False
    )


def test_engine_persists_syn_flood_alert_at_threshold(monkeypatch):
    disable_threat_intel(monkeypatch)
    database = CapturingDatabase()
    engine = DetectionEngine(
        EmptyRulesEngine(),
        database,
        syn_flood_detector=SynFloodDetector(threshold=3, window_seconds=10),
        beacon_detector=BeaconDetector(min_connections=10),
        now=lambda: TIMESTAMP,
    )

    for _ in range(3):
        engine.run_detections(syn_packet(), {}, {})

    alerts = [alert for alert in database.alerts if alert["alert_type"] == "TCP SYN Flood"]
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["severity"] == "High"
    assert alert["source_ip"] == "192.0.2.10"
    assert alert["dest_ip"] == "198.51.100.20"
    assert alert["mitre_attack"] == "T1498"
    assert "3 TCP SYN packets" in alert["description"]


def test_engine_persists_periodic_beacon_alert(monkeypatch):
    disable_threat_intel(monkeypatch)
    clock = FakeClock()
    database = CapturingDatabase()
    engine = DetectionEngine(
        EmptyRulesEngine(),
        database,
        syn_flood_detector=SynFloodDetector(threshold=100),
        beacon_detector=BeaconDetector(
            min_connections=4,
            min_interval_seconds=10,
            max_interval_variance=0.01,
            clock=clock,
        ),
        now=lambda: TIMESTAMP,
    )

    for index in range(4):
        engine.run_detections(syn_packet(), {}, {})
        if index < 3:
            clock.advance(30)

    alerts = [
        alert for alert in database.alerts if alert["alert_type"] == "Periodic Network Beacon"
    ]
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["severity"] == "High"
    assert alert["source_ip"] == "192.0.2.10"
    assert alert["dest_ip"] == "198.51.100.20"
    assert alert["mitre_attack"] == "T1071"
    assert "30" in alert["description"]


def test_engine_does_not_alert_before_stateful_thresholds(monkeypatch):
    disable_threat_intel(monkeypatch)
    clock = FakeClock()
    database = CapturingDatabase()
    engine = DetectionEngine(
        EmptyRulesEngine(),
        database,
        syn_flood_detector=SynFloodDetector(threshold=4),
        beacon_detector=BeaconDetector(
            min_connections=4,
            min_interval_seconds=10,
            max_interval_variance=0.01,
            clock=clock,
        ),
        now=lambda: TIMESTAMP,
    )

    for _ in range(3):
        engine.run_detections(syn_packet(), {}, {})
        clock.advance(30)

    assert database.alerts == []
