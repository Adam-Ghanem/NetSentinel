from collections import Counter, defaultdict


ATTACK_TECHNIQUE_NAMES = {
    "T1046": "Network Service Scanning",
    "T1498": "Network Denial of Service",
    "T1071": "Application Layer Protocol",
    "T1071.004": "DNS",
}


def _value(item, name, default=None):
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def _safe_size(packet):
    size = _value(packet, "packet_size", 0)
    if size is None:
        return 0
    try:
        return max(0, int(size))
    except (TypeError, ValueError):
        return 0


def build_report_data(packets, alerts):
    """Build deterministic report evidence from stored packet and alert records."""
    protocol_counts = Counter()
    severity_counts = Counter()
    traffic = defaultdict(lambda: {"total_packets": 0, "total_bytes": 0})
    top_alerts = []
    attack_counts = Counter()

    for packet in packets:
        protocol = _value(packet, "protocol") or "Unknown"
        protocol_counts[str(protocol)] += 1

        source_ip = _value(packet, "source_ip")
        if source_ip:
            source_key = str(source_ip)
            traffic[source_key]["total_packets"] += 1
            traffic[source_key]["total_bytes"] += _safe_size(packet)

    for alert in alerts:
        severity = _value(alert, "severity") or "Unknown"
        severity_counts[str(severity)] += 1

        technique_id = _value(alert, "mitre_attack")
        if technique_id:
            attack_counts[str(technique_id)] += 1

        top_alerts.append(
            {
                "timestamp": _value(alert, "timestamp", "N/A") or "N/A",
                "source_ip": _value(alert, "source_ip", "N/A") or "N/A",
                "dest_ip": _value(alert, "dest_ip", "N/A") or "N/A",
                "alert_type": _value(alert, "alert_type", "N/A") or "N/A",
                "severity": severity,
            }
        )

    traffic_stats = dict(traffic)
    top_talkers = dict(
        sorted(
            traffic_stats.items(),
            key=lambda item: (
                item[1]["total_packets"],
                item[1]["total_bytes"],
                item[0],
            ),
            reverse=True,
        )[:10]
    )
    mitre_attack_mapping = {
        technique_id: {
            "name": ATTACK_TECHNIQUE_NAMES.get(technique_id, "ATT&CK technique"),
            "count": count,
        }
        for technique_id, count in sorted(attack_counts.items())
    }

    packet_count = sum(protocol_counts.values())
    alert_count = sum(severity_counts.values())
    return {
        "executive_summary": (
            f"NetSentinel summarized {packet_count} stored packet records and "
            f"{alert_count} stored security alerts for analyst review."
        ),
        "traffic_overview": (
            "Traffic statistics are derived from the bounded stored metadata snapshot "
            "selected by the dashboard at report-generation time."
        ),
        "traffic_stats": traffic_stats,
        "protocol_stats": dict(protocol_counts),
        "top_talkers": top_talkers,
        "top_alerts": top_alerts[:25],
        "severity_distribution": dict(severity_counts),
        "mitre_attack_mapping": mitre_attack_mapping,
        "recommendations": [
            "Validate high-severity alerts against asset and operational context.",
            "Review repeated or correlated evidence before escalating an incident.",
        ],
        "appendix": (
            "This report contains a bounded snapshot of stored metadata and alerts; "
            "it does not embed packet payloads or credentials."
        ),
    }
