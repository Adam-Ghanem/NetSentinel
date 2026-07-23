from datetime import datetime, timezone

from app.contracts import DetectionRule, PacketMetadata, Severity
from app.rules_engine import RulesEngine

TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


def packet(**overrides):
    values = {
        "timestamp": TIMESTAMP,
        "source_ip": "192.0.2.10",
        "dest_ip": "8.8.8.8",
        "protocol": "TCP",
        "source_port": 51515,
        "dest_port": 31337,
        "packet_size": 128,
        "tcp_flags": "S",
    }
    values.update(overrides)
    return PacketMetadata(**values)


def test_rule_loader_accepts_valid_rules_and_skips_invalid_entries(tmp_path):
    (tmp_path / "rules.yaml").write_text(
        """
- name: Valid unusual port
  description: Detect a selected suspicious destination port.
  severity: High
  protocol: TCP
  unusual_ports: [31337]
  mitre_attack: T1090
- name: Invalid severity
  description: This rule should be rejected.
  severity: Urgent
  protocol: TCP
""".strip(),
        encoding="utf-8",
    )

    engine = RulesEngine(tmp_path)

    assert len(engine.rules) == 1
    assert engine.rules[0].name == "Valid unusual port"
    assert engine.rules[0].severity is Severity.HIGH


def test_rule_evaluation_returns_typed_rules(tmp_path):
    engine = RulesEngine(tmp_path)
    engine.rules = [
        DetectionRule(
            name="Suspicious port",
            description="Detect a selected suspicious destination port.",
            severity="Medium",
            protocol="TCP",
            unusual_ports=(31337,),
            mitre_attack="T1090",
        )
    ]

    triggered = engine.evaluate_rules(packet().model_dump(), {}, {})

    assert len(triggered) == 1
    assert isinstance(triggered[0], DetectionRule)
    assert triggered[0].name == "Suspicious port"


def test_rule_evaluation_rejects_non_matching_protocol(tmp_path):
    engine = RulesEngine(tmp_path)
    engine.rules = [
        DetectionRule(
            name="DNS volume",
            description="Detect elevated DNS query volume.",
            severity="High",
            protocol="UDP",
            dest_port=53,
            min_dns_queries=10,
        )
    ]

    assert engine.evaluate_rules(packet(), {}, {}) == []


def test_rule_evaluation_applies_stateful_thresholds(tmp_path):
    engine = RulesEngine(tmp_path)
    engine.rules = [
        DetectionRule(
            name="SYN threshold",
            description="Detect elevated SYN volume.",
            severity="High",
            protocol="TCP",
            tcp_flags="S",
            min_syn_packets=5,
        )
    ]

    assert engine.evaluate_rules(packet(), {}, {"192.0.2.10": {"syn_packets": 4}}) == []
    assert len(
        engine.evaluate_rules(packet(), {}, {"192.0.2.10": {"syn_packets": 5}})
    ) == 1
