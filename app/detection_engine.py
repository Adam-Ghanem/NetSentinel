from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Protocol

from app.contracts import AlertRecord, DetectionRule, PacketMetadata, Severity
from app.intel import ThreatIntel
from app.utils import get_logger

logger = get_logger(__name__)


class AlertDatabase(Protocol):
    def insert_alert(self, alert_data: dict[str, Any]) -> Any: ...


class DetectionRules(Protocol):
    def evaluate_rules(
        self,
        parsed_packet: PacketMetadata | Mapping[str, Any],
        connections: Mapping[str, Any],
        traffic_stats: Mapping[str, Mapping[str, Any]],
    ) -> list[DetectionRule]: ...


class DetectionEngine:
    """Coordinate threat intelligence, fingerprints, and validated detection rules."""

    def __init__(self, rules_engine: DetectionRules, database_manager: AlertDatabase) -> None:
        self.rules_engine = rules_engine
        self.db = database_manager
        self.intel = ThreatIntel()
        self.intel.sync_otx()

    def run_detections(
        self,
        parsed_packet: PacketMetadata | Mapping[str, Any],
        connections: Mapping[str, Any],
        traffic_stats: Mapping[str, Mapping[str, Any]],
    ) -> None:
        packet = (
            parsed_packet
            if isinstance(parsed_packet, PacketMetadata)
            else PacketMetadata.model_validate(parsed_packet)
        )

        self._check_threat_intel(packet)
        self._check_ja3_malware(packet)

        for rule in self.rules_engine.evaluate_rules(packet, connections, traffic_stats):
            self._create_alert(
                alert_type=rule.name,
                severity=rule.severity,
                description=rule.description,
                source_ip=packet.source_ip,
                dest_ip=packet.dest_ip,
                mitre_attack=rule.mitre_attack,
                recommended_action=rule.recommended_action,
            )

    def _check_threat_intel(self, packet: PacketMetadata) -> None:
        if packet.source_ip and self.intel.check_ip(packet.source_ip):
            self._create_alert(
                alert_type="Threat Intel Match",
                severity=Severity.CRITICAL,
                description=f"Inbound traffic from known malicious IP: {packet.source_ip}",
                source_ip=packet.source_ip,
                dest_ip=packet.dest_ip,
                mitre_attack="T1071",
            )

        if packet.dest_ip and self.intel.check_ip(packet.dest_ip):
            self._create_alert(
                alert_type="Threat Intel Match",
                severity=Severity.CRITICAL,
                description=f"Outbound connection to known malicious C2: {packet.dest_ip}",
                source_ip=packet.source_ip,
                dest_ip=packet.dest_ip,
                mitre_attack="T1071",
            )

    def _check_ja3_malware(self, packet: PacketMetadata) -> None:
        if not packet.ja3_hash:
            return

        meterpreter_ja3 = (
            "771,49192-49191-49200-49199-49188-49187-49196-49195-49162-49161-"
            "49172-49171-157-156-61-60-53-47-10,0-11-13,23-24-25,0"
        )
        cobalt_strike_ja3 = (
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49162-49161-"
            "49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-21,"
            "29-23-24,0"
        )
        malicious_ja3s = {
            meterpreter_ja3: "Metasploit Meterpreter",
            cobalt_strike_ja3: "Cobalt Strike Beacon",
        }

        malware_name = malicious_ja3s.get(packet.ja3_hash)
        if malware_name:
            self._create_alert(
                alert_type="Malware JA3 Fingerprint",
                severity=Severity.CRITICAL,
                description=f"TLS fingerprint matches known malware: {malware_name}",
                source_ip=packet.source_ip,
                dest_ip=packet.dest_ip,
                mitre_attack="T1573",
            )

    def _create_alert(
        self,
        *,
        alert_type: str,
        severity: Severity | str,
        description: str,
        source_ip: str | None,
        dest_ip: str | None,
        mitre_attack: str | None = None,
        recommended_action: str | None = None,
    ) -> None:
        alert = AlertRecord(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            source_ip=source_ip,
            dest_ip=dest_ip,
            alert_type=alert_type,
            severity=severity,
            description=description,
            mitre_attack=mitre_attack,
            recommended_action=recommended_action,
        )
        try:
            self.db.insert_alert(alert.to_persistence_dict())
            logger.warning(
                "ALERT: [%s] %s - %s",
                alert.severity.value,
                alert.alert_type,
                alert.description,
            )
        except Exception:
            logger.exception("Failed to persist validated alert %s", alert.alert_id)
