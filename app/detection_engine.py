import uuid
import datetime
from app.utils import get_logger
from app.intel import ThreatIntel

logger = get_logger(__name__)

class DetectionEngine:
    """
    Elite Detection Engine (5+ Years Exp Architecture).
    Integrates Signature-based, Behavioral, JA3, and Threat Intel detections.
    """
    def __init__(self, rules_engine, database_manager):
        self.rules_engine = rules_engine
        self.db = database_manager
        self.intel = ThreatIntel()
        self.intel.sync_otx() # Initial sync

    def run_detections(self, parsed_packet, connections, traffic_stats):
        """
        Main detection entry point.
        """
        # 1. Threat Intel Check (Elite)
        self._check_threat_intel(parsed_packet)

        # 2. JA3 Malware Fingerprinting (Elite)
        self._check_ja3_malware(parsed_packet)

        # 3. Signature & Behavioral Rules
        triggered_rules = self.rules_engine.evaluate_rules(parsed_packet, connections, traffic_stats)
        for rule in triggered_rules:
            self._create_alert(
                alert_type=rule["name"],
                severity=rule["severity"],
                description=rule["description"],
                source_ip=parsed_packet.get("source_ip"),
                dest_ip=parsed_packet.get("dest_ip"),
                mitre_attack=rule.get("mitre_attack"),
                recommended_action=rule.get("recommended_action")
            )

    def _check_threat_intel(self, packet):
        src_ip = packet.get("source_ip")
        dst_ip = packet.get("dest_ip")
        
        if self.intel.check_ip(src_ip):
            self._create_alert(
                alert_type="Threat Intel Match",
                severity="Critical",
                description=f"Inbound traffic from known malicious IP: {src_ip}",
                source_ip=src_ip,
                dest_ip=dst_ip,
                mitre_attack="T1071"
            )
        
        if self.intel.check_ip(dst_ip):
            self._create_alert(
                alert_type="Threat Intel Match",
                severity="Critical",
                description=f"Outbound connection to known malicious C2: {dst_ip}",
                source_ip=src_ip,
                dest_ip=dst_ip,
                mitre_attack="T1071"
            )

    def _check_ja3_malware(self, packet):
        ja3 = packet.get("ja3_hash")
        if not ja3:
            return
            
        # Known Malicious JA3s (Demo purposes)
        malicious_ja3s = {
            "771,49192-49191-49200-49199-49188-49187-49196-49195-49162-49161-49172-49171-157-156-61-60-53-47-10,0-11-13,23-24-25,0": "Metasploit Meterpreter",
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-21,29-23-24,0": "Cobalt Strike Beacon"
        }
        
        if ja3 in malicious_ja3s:
            self._create_alert(
                alert_type="Malware JA3 Fingerprint",
                severity="Critical",
                description=f"TLS fingerprint matches known malware: {malicious_ja3s[ja3]}",
                source_ip=packet.get("source_ip"),
                dest_ip=packet.get("dest_ip"),
                mitre_attack="T1573"
            )

    def _create_alert(self, alert_type, severity, description, source_ip, dest_ip, mitre_attack=None, recommended_action=None):
        alert_data = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": datetime.datetime.now(datetime.timezone.utc),
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "alert_type": alert_type,
            "severity": severity,
            "description": description,
            "mitre_attack": mitre_attack,
            "recommended_action": recommended_action
        }
        try:
            self.db.insert_alert(alert_data)
            logger.warning(f"ALERT: [{severity}] {alert_type} - {description}")
        except Exception as e:
            logger.error(f"Failed to insert alert: {e}")
