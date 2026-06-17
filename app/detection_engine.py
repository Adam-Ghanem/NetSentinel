import uuid
from app.utils import get_timestamp

class DetectionEngine:
    def __init__(self, rules_engine, database_manager):
        self.rules_engine = rules_engine
        self.database_manager = database_manager

    def run_detections(self, parsed_packet, connections, traffic_stats):
        triggered_rules = self.rules_engine.evaluate_rules(parsed_packet, connections, traffic_stats)
        alerts = []
        for rule in triggered_rules:
            alert = self._create_alert(parsed_packet, rule)
            self.database_manager.insert_alert(alert)
            alerts.append(alert)
        return alerts

    def _create_alert(self, packet_data, rule):
        alert_id = str(uuid.uuid4())
        
        # Default values from rule
        severity = rule.get("severity", "Medium")
        description = rule.get("description", "Suspicious activity detected.")
        recommended_action = rule.get("recommended_action", "Investigate further.")
        mitre_attack = rule.get("mitre_attack", None)

        return {
            "alert_id": alert_id,
            "source_ip": packet_data.get("source_ip"),
            "dest_ip": packet_data.get("dest_ip"),
            "alert_type": rule.get("name", "Generic Alert"),
            "severity": severity,
            "description": description,
            "recommended_action": recommended_action,
            "mitre_attack": mitre_attack
        }
