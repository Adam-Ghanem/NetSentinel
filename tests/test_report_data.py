from types import SimpleNamespace

from app.report_data import build_report_data


def packet(**overrides):
    values = {
        "source_ip": "10.0.0.10",
        "dest_ip": "10.0.0.20",
        "protocol": "TCP",
        "packet_size": 120,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def alert(**overrides):
    values = {
        "timestamp": "2026-09-03T08:00:00+00:00",
        "source_ip": "10.0.0.10",
        "dest_ip": "10.0.0.20",
        "alert_type": "Port Scan",
        "severity": "High",
        "mitre_attack": "T1046",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_build_report_data_aggregates_packet_and_alert_evidence():
    packets = [
        packet(),
        packet(protocol="UDP", packet_size=80),
        packet(source_ip="10.0.0.30", packet_size=40),
    ]
    alerts = [
        alert(),
        alert(severity="Medium", alert_type="Beacon", mitre_attack="T1071"),
    ]

    report = build_report_data(packets, alerts)

    assert report["protocol_stats"] == {"TCP": 2, "UDP": 1}
    assert report["severity_distribution"] == {"High": 1, "Medium": 1}
    assert report["traffic_stats"]["10.0.0.10"] == {
        "total_packets": 2,
        "total_bytes": 200,
    }
    assert report["traffic_stats"]["10.0.0.30"] == {
        "total_packets": 1,
        "total_bytes": 40,
    }
    assert report["top_talkers"]["10.0.0.10"]["total_packets"] == 2
    assert [item["alert_type"] for item in report["top_alerts"]] == ["Port Scan", "Beacon"]
    assert report["mitre_attack_mapping"]["T1046"]["count"] == 1
    assert report["mitre_attack_mapping"]["T1071"]["count"] == 1


def test_build_report_data_handles_missing_optional_evidence():
    packets = [packet(source_ip=None, protocol=None, packet_size=None)]
    alerts = [alert(mitre_attack=None, severity=None)]

    report = build_report_data(packets, alerts)

    assert report["protocol_stats"] == {"Unknown": 1}
    assert report["severity_distribution"] == {"Unknown": 1}
    assert report["traffic_stats"] == {}
    assert report["mitre_attack_mapping"] == {}
