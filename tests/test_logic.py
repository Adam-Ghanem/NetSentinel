import json
import time

from app.case_manager import CaseManager
from app.database import DatabaseManager
from app.detection_engine import DetectionEngine, KNOWN_JA3_HASHES
from app.enrichment import Enrichment
from app.rules_engine import RulesEngine


class EmptyRules:
    def evaluate_rules(self, parsed_packet, connections, traffic_stats):
        return []


class EmptyIntel:
    def check_ip(self, ip_address):
        return False


class EmptyConfig:
    ABUSEIPDB_API_KEY = ""
    VIRUSTOTAL_API_KEY = ""


def test_case_manager_create_and_update():
    database = DatabaseManager(db_url="sqlite:///:memory:")
    manager = CaseManager(database)
    case = manager.create_case_from_alert(
        {"alert_id": None, "severity": "High"},
        "Review suspicious connection",
    )

    updated = manager.update_case_status(case.case_id, "Closed")

    assert updated is not None
    assert updated.status == "Closed"


def test_ioc_enrichment_is_cached_without_external_calls():
    database = DatabaseManager(db_url="sqlite:///:memory:")
    enrichment = Enrichment(database, config=EmptyConfig())

    first = enrichment.enrich_ip_address("8.8.8.8")
    cached = database.get_ioc_cache("8.8.8.8")
    second = enrichment.enrich_ip_address("8.8.8.8")

    assert first == second
    assert json.loads(cached.data)["indicator"] == "8.8.8.8"


def test_stateful_rule_does_not_match_without_recent_stats(tmp_path):
    engine = RulesEngine(rules_dir=str(tmp_path / "rules"))
    engine.rules = [
        {
            "name": "Port scan",
            "protocol": "TCP",
            "min_unique_ports": 3,
            "severity": "High",
        }
    ]

    triggered = engine.evaluate_rules(
        {"protocol": "TCP", "source_ip": "10.0.0.5", "dest_port": 443},
        {},
        {},
    )

    assert triggered == []


def test_stateful_rule_matches_recent_unique_ports(tmp_path):
    engine = RulesEngine(rules_dir=str(tmp_path / "rules"))
    engine.rules = [
        {
            "name": "Port scan",
            "protocol": "TCP",
            "min_unique_ports": 3,
            "time_window_seconds": 10,
            "severity": "High",
        }
    ]
    now = time.time()
    traffic_stats = {
        "10.0.0.5": {
            "recent_packets": [
                {"timestamp": now, "dest_port": 22},
                {"timestamp": now, "dest_port": 80},
                {"timestamp": now, "dest_port": 443},
            ]
        }
    }

    triggered = engine.evaluate_rules(
        {"protocol": "TCP", "source_ip": "10.0.0.5", "dest_port": 443},
        {},
        traffic_stats,
    )

    assert len(triggered) == 1


def test_ja3_hash_matches_listed_signature():
    database = DatabaseManager(db_url="sqlite:///:memory:")
    engine = DetectionEngine(
        EmptyRules(),
        database,
        threat_intel=EmptyIntel(),
    )
    ja3_hash = next(iter(KNOWN_JA3_HASHES))

    engine.run_detections(
        {
            "source_ip": "10.0.0.5",
            "dest_ip": "10.0.0.8",
            "ja3_hash": ja3_hash,
        },
        {},
        {},
    )

    alerts = database.get_alerts()
    assert len(alerts) == 1
    assert alerts[0].alert_type == "Malware JA3 Fingerprint"
