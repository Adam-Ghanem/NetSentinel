from datetime import datetime, timezone

from app.contracts import DetectionRule, PacketMetadata
from app.detection_engine import DetectionEngine

TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


class StubRulesEngine:
    def evaluate_rules(self, parsed_packet, connections, traffic_stats):
        assert isinstance(parsed_packet, PacketMetadata)
        return [
            DetectionRule(
                name="Typed port rule",
                description="Detect a selected destination port.",
                severity="High",
                protocol="TCP",
                dest_port=443,
                mitre_attack="T1046",
                recommended_action="Investigate the endpoint.",
            )
        ]


class CapturingDatabase:
    def __init__(self):
        self.alerts = []

    def insert_alert(self, alert_data):
        self.alerts.append(alert_data)


def packet_data():
    return {
        "timestamp": TIMESTAMP,
        "source_ip": "192.0.2.10",
        "dest_ip": "198.51.100.20",
        "protocol": "TCP",
        "source_port": 51515,
        "dest_port": 443,
        "packet_size": 128,
    }


def test_detection_engine_persists_validated_alert_payload(monkeypatch):
    monkeypatch.setattr("app.detection_engine.ThreatIntel.sync_otx", lambda self: None)
    monkeypatch.setattr("app.detection_engine.ThreatIntel.check_ip", lambda self, value: False)
    database = CapturingDatabase()
    engine = DetectionEngine(StubRulesEngine(), database)

    engine.run_detections(packet_data(), {}, {})

    assert len(database.alerts) == 1
    alert = database.alerts[0]
    assert alert["alert_type"] == "Typed port rule"
    assert alert["severity"] == "High"
    assert alert["source_ip"] == "192.0.2.10"
    assert alert["dest_ip"] == "198.51.100.20"
    assert alert["mitre_attack"] == "T1046"
    assert alert["recommended_action"] == "Investigate the endpoint."
    assert alert["timestamp"].tzinfo is timezone.utc
