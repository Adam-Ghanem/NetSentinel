from datetime import datetime, timezone

from app.detection_engine import DetectionEngine
from app.port_scan_detector import UniquePortScanDetector

TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


class EmptyRulesEngine:
    def evaluate_rules(self, parsed_packet, connections, traffic_stats):
        return []


class CapturingDatabase:
    def __init__(self):
        self.alerts = []

    def insert_alert(self, alert_data):
        self.alerts.append(alert_data)


def syn_packet(destination_port: int, *, source_ip: str = "192.0.2.10"):
    return {
        "timestamp": TIMESTAMP,
        "source_ip": source_ip,
        "dest_ip": "198.51.100.20",
        "protocol": "TCP",
        "source_port": 51515,
        "dest_port": destination_port,
        "tcp_flags": "S",
        "packet_size": 64,
    }


def build_engine(monkeypatch, *, threshold=3):
    monkeypatch.setattr("app.detection_engine.ThreatIntel.sync_otx", lambda self: None)
    monkeypatch.setattr("app.detection_engine.ThreatIntel.check_ip", lambda self, value: False)
    database = CapturingDatabase()
    detector = UniquePortScanDetector(threshold=threshold, window_seconds=10.0)
    engine = DetectionEngine(
        EmptyRulesEngine(),
        database,
        port_scan_detector=detector,
        now=lambda: TIMESTAMP,
    )
    return engine, database


def test_engine_persists_typed_port_scan_alert_at_threshold(monkeypatch):
    engine, database = build_engine(monkeypatch)

    engine.run_detections(syn_packet(22), {}, {})
    engine.run_detections(syn_packet(80), {}, {})
    engine.run_detections(syn_packet(443), {}, {})

    assert len(database.alerts) == 1
    alert = database.alerts[0]
    assert alert["alert_type"] == "Unique Destination Port Scan"
    assert alert["severity"] == "High"
    assert alert["source_ip"] == "192.0.2.10"
    assert alert["dest_ip"] == "198.51.100.20"
    assert alert["mitre_attack"] == "T1046"
    assert "3 unique destination ports" in alert["description"]
    assert alert["timestamp"] == TIMESTAMP


def test_engine_does_not_persist_before_threshold(monkeypatch):
    engine, database = build_engine(monkeypatch)

    engine.run_detections(syn_packet(22), {}, {})
    engine.run_detections(syn_packet(80), {}, {})

    assert database.alerts == []


def test_engine_does_not_count_duplicate_ports(monkeypatch):
    engine, database = build_engine(monkeypatch)

    engine.run_detections(syn_packet(22), {}, {})
    engine.run_detections(syn_packet(22), {}, {})
    engine.run_detections(syn_packet(80), {}, {})

    assert database.alerts == []


def test_injected_detector_keeps_sources_isolated(monkeypatch):
    engine, database = build_engine(monkeypatch, threshold=2)

    engine.run_detections(syn_packet(22, source_ip="192.0.2.10"), {}, {})
    engine.run_detections(syn_packet(80, source_ip="192.0.2.11"), {}, {})

    assert database.alerts == []
