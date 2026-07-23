from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.contracts import AlertRecord, DetectionRule, PacketMetadata, Severity

TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


def packet_metadata(**overrides):
    values = {
        "timestamp": TIMESTAMP,
        "source_ip": "192.0.2.10",
        "dest_ip": "198.51.100.20",
        "protocol": "tcp",
        "source_port": 51515,
        "dest_port": 443,
        "packet_size": 128,
    }
    values.update(overrides)
    return PacketMetadata(**values)


def test_packet_metadata_normalizes_protocol_and_addresses():
    packet = packet_metadata()

    assert packet.protocol == "TCP"
    assert packet.source_ip == "192.0.2.10"
    assert packet.dest_ip == "198.51.100.20"


def test_packet_metadata_rejects_invalid_network_values():
    with pytest.raises(ValidationError):
        packet_metadata(source_ip="not-an-ip")

    with pytest.raises(ValidationError):
        packet_metadata(dest_port=70000)

    with pytest.raises(ValidationError):
        packet_metadata(packet_size=-1)


def test_detection_rule_normalizes_severity_protocol_and_mitre_id():
    rule = DetectionRule(
        name="External TLS connection",
        description="Detect outbound TLS metadata.",
        severity="High",
        protocol="tls",
        is_external_ip=True,
        mitre_attack="t1071.001",
    )

    assert rule.severity is Severity.HIGH
    assert rule.protocol == "TLS"
    assert rule.mitre_attack == "T1071.001"


def test_detection_rule_rejects_invalid_regex_and_empty_conditions():
    with pytest.raises(ValidationError, match="valid regular expression"):
        DetectionRule(
            name="Invalid regex",
            description="Invalid test rule.",
            severity="Low",
            payload_pattern="[",
        )

    with pytest.raises(ValidationError, match="supported condition"):
        DetectionRule(
            name="No condition",
            description="This rule cannot trigger.",
            severity="Low",
        )


def test_detection_rule_rejects_unimplemented_arp_state_condition():
    with pytest.raises(ValidationError, match="mac_ip_mismatch is not supported"):
        DetectionRule(
            name="ARP mismatch",
            description="Requires bounded ARP state before it can be evaluated safely.",
            severity="Critical",
            protocol="ARP",
            arp_op="is-at",
            mac_ip_mismatch=True,
        )


def test_detection_rule_deduplicates_unusual_ports():
    rule = DetectionRule(
        name="Unusual ports",
        description="Detect selected destination ports.",
        severity="Medium",
        unusual_ports=(1337, 1337, 31337),
    )

    assert rule.unusual_ports == (1337, 31337)


def test_alert_record_emits_existing_persistence_shape():
    alert = AlertRecord(
        alert_id="alert-1",
        timestamp=TIMESTAMP,
        source_ip="192.0.2.10",
        dest_ip="198.51.100.20",
        alert_type="Validated rule",
        severity=Severity.CRITICAL,
        description="A validated alert payload.",
        mitre_attack="T1046",
    )

    persisted = alert.to_persistence_dict()

    assert persisted["severity"] == "Critical"
    assert persisted["timestamp"] == TIMESTAMP
    assert persisted["mitre_attack"] == "T1046"
