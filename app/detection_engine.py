import uuid
from app.utils import get_timestamp

class DetectionEngine:
    def __init__(self, rules_engine, database_manager):
        self.rules_engine = rules_engine
        self.database_manager = database_manager
        self.alerts = []

    def run_detections(self, parsed_packet, connections, traffic_stats):
        # Run rules from the rules engine
        triggered_rules = self.rules_engine.evaluate_rules(parsed_packet, connections, traffic_stats)
        for rule in triggered_rules:
            alert = self._create_alert(parsed_packet, rule)
            self.alerts.append(alert)
            self.database_manager.insert_alert(alert)
        return self.alerts

    def _create_alert(self, packet_data, rule):
        alert_id = str(uuid.uuid4())
        timestamp = get_timestamp()
        source_ip = packet_data.get("source_ip")
        dest_ip = packet_data.get("dest_ip")

        # Default values, can be overridden by rule
        severity = rule.get("severity", "Medium")
        description = rule.get("description", "Suspicious activity detected.")
        recommended_action = rule.get("recommended_action", "Investigate further.")
        mitre_attack = rule.get("mitre_attack", None)

        return {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "alert_type": rule["name"],
            "severity": severity,
            "description": description,
            "recommended_action": recommended_action,
            "mitre_attack": mitre_attack
        }

    def get_alerts(self):
        return self.alerts


# Dummy DatabaseManager for testing
class DummyDatabaseManager:
    def insert_alert(self, alert):
        print(f"[DB] Inserting alert: {alert["alert_type"]} from {alert["source_ip"]}")

# Dummy RulesEngine for testing
class DummyRulesEngine:
    def evaluate_rules(self, parsed_packet, connections, traffic_stats):
        triggered = []
        # Example: Simple port scan detection
        if parsed_packet.get("protocol") == "TCP" and parsed_packet.get("tcp_flags") == "S":
            # This is a very basic example, real detection would involve stateful tracking
            if parsed_packet.get("dest_port") in [21, 22, 23, 80, 443, 3389]: # Common ports
                triggered.append({
                    "name": "Possible Port Scan",
                    "severity": "High",
                    "description": f"SYN packet to common port {parsed_packet["dest_port"]}",
                    "recommended_action": "Check for multiple SYN packets from source IP to different ports.",
                    "mitre_attack": "T1046"
                })
        return triggered

if __name__ == '__main__':
    # Example usage
    db_manager = DummyDatabaseManager()
    rules_engine = DummyRulesEngine()
    detection_engine = DetectionEngine(rules_engine, db_manager)

    sample_packet = {
        "timestamp": get_timestamp(), "source_ip": "192.168.1.100", "dest_ip": "10.0.0.1",
        "protocol": "TCP", "source_port": 12345, "dest_port": 22, "packet_size": 60,
        "tcp_flags": "S", "dns_query": None, "http_host": None, "http_path": None
    }

    alerts = detection_engine.run_detections(sample_packet, {}, {})
    print("\nGenerated Alerts:")
    for alert in alerts:
        print(alert)

    sample_packet_udp = {
        "timestamp": get_timestamp(), "source_ip": "192.168.1.101", "dest_ip": "10.0.0.2",
        "protocol": "UDP", "source_port": 50000, "dest_port": 53, "packet_size": 80,
        "tcp_flags": None, "dns_query": "example.com", "http_host": None, "http_path": None
    }
    alerts_udp = detection_engine.run_detections(sample_packet_udp, {}, {})
    print("\nGenerated Alerts (UDP - none expected):")
    for alert in alerts_udp:
        print(alert)
