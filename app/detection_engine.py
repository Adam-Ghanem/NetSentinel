from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any, Protocol

from app.alert_suppression import AlertSuppressor
from app.beacon_detector import BeaconDetector, BeaconMatch
from app.contracts import AlertRecord, DetectionRule, PacketMetadata, Severity
from app.detection_observability import DetectionMetricsSnapshot, DetectionObservability
from app.intel import ThreatIntel
from app.port_scan_detector import PortScanMatch, UniquePortScanDetector
from app.syn_flood_detector import SynFloodDetector, SynFloodMatch
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
    """Coordinate intelligence, stateful detectors, validated rules, and suppression."""

    def __init__(
        self,
        rules_engine: DetectionRules,
        database_manager: AlertDatabase,
        *,
        alert_suppressor: AlertSuppressor | None = None,
        port_scan_detector: UniquePortScanDetector | None = None,
        syn_flood_detector: SynFloodDetector | None = None,
        beacon_detector: BeaconDetector | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.rules_engine = rules_engine
        self.db = database_manager
        self.alert_suppressor = alert_suppressor or AlertSuppressor()
        self.port_scan_detector = port_scan_detector or UniquePortScanDetector()
        self.syn_flood_detector = syn_flood_detector or SynFloodDetector()
        self.beacon_detector = beacon_detector or BeaconDetector()
        self._now = now or (lambda: datetime.now(timezone.utc))
        self.observability = DetectionObservability(
            self.alert_suppressor,
            port_scan_snapshot=self.port_scan_detector.snapshot,
            now=self._now,
        )
        self.intel = ThreatIntel()
        self.intel.sync_otx()

    def metrics_snapshot(self) -> DetectionMetricsSnapshot:
        """Return sanitized process-local detection metrics for read-only consumers."""

        return self.observability.snapshot()

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
        self._check_unique_port_scan(packet)
        self._check_syn_flood(packet)
        self._check_beacon(packet)

        for rule in self.rules_engine.evaluate_rules(packet, connections, traffic_stats):
            self._create_alert(
                alert_type=rule.name,
                severity=rule.severity,
                description=rule.description,
                source_ip=packet.source_ip,
                dest_ip=packet.dest_ip,
                mitre_attack=rule.mitre_attack,
                recommended_action=rule.recommended_action,
                suppression_seconds=rule.suppression_seconds,
            )

    def _check_unique_port_scan(self, packet: PacketMetadata) -> None:
        match = self.port_scan_detector.observe(packet)
        if match is None:
            return

        self._create_port_scan_alert(match)

    def _create_port_scan_alert(self, match: PortScanMatch) -> None:
        description = (
            f"Observed TCP SYN activity across {match.unique_ports} unique destination "
            f"ports within {match.window_seconds:g} seconds."
        )
        self._create_alert(
            alert_type="Unique Destination Port Scan",
            severity=Severity.HIGH,
            description=description,
            source_ip=match.source_ip,
            dest_ip=match.destination_ip,
            mitre_attack="T1046",
            recommended_action=(
                "Validate whether the source is an approved scanner and inspect the "
                "destination for reconnaissance activity."
            ),
            suppression_seconds=60.0,
        )

    def _check_syn_flood(self, packet: PacketMetadata) -> None:
        match = self.syn_flood_detector.observe(packet)
        if match is None:
            return

        self._create_syn_flood_alert(match)

    def _create_syn_flood_alert(self, match: SynFloodMatch) -> None:
        self._create_alert(
            alert_type="TCP SYN Flood",
            severity=Severity.HIGH,
            description=(
                f"Observed {match.syn_packets} TCP SYN packets from {match.source_ip} "
                f"to {match.destination_ip}:{match.destination_port} within "
                f"{match.window_seconds:g} seconds."
            ),
            source_ip=match.source_ip,
            dest_ip=match.destination_ip,
            mitre_attack="T1498",
            recommended_action=(
                "Validate whether the burst is expected, inspect upstream connection "
                "rates, and apply rate limiting or filtering if availability is at risk."
            ),
            suppression_seconds=60.0,
        )

    def _check_beacon(self, packet: PacketMetadata) -> None:
        match = self.beacon_detector.observe(packet)
        if match is None:
            return

        self._create_beacon_alert(match)

    def _create_beacon_alert(self, match: BeaconMatch) -> None:
        self._create_alert(
            alert_type="Periodic Network Beacon",
            severity=Severity.HIGH,
            description=(
                f"Observed {match.connections} periodic TCP SYN connections from "
                f"{match.source_ip} to {match.destination_ip}:{match.destination_port} "
                f"with a mean interval of {match.mean_interval_seconds:g} seconds "
                f"within a {match.window_seconds:g}-second window."
            ),
            source_ip=match.source_ip,
            dest_ip=match.destination_ip,
            mitre_attack="T1071",
            recommended_action=(
                "Confirm whether the destination and cadence belong to approved software; "
                "otherwise inspect the endpoint and destination for command-and-control activity."
            ),
            suppression_seconds=300.0,
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
        suppression_seconds: float | None = None,
    ) -> None:
        suppression_key = self._suppression_key(
            alert_type=alert_type,
            source_ip=source_ip,
            dest_ip=dest_ip,
            mitre_attack=mitre_attack,
        )
        decision = self.alert_suppressor.evaluate(
            suppression_key,
            cooldown_seconds=suppression_seconds,
        )
        if not decision.emit:
            logger.info("Suppressed duplicate alert %s: %s", alert_type, decision.reason)
            return

        alert = AlertRecord(
            alert_id=str(uuid.uuid4()),
            timestamp=self._now(),
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

    @staticmethod
    def _suppression_key(
        *,
        alert_type: str,
        source_ip: str | None,
        dest_ip: str | None,
        mitre_attack: str | None,
    ) -> str:
        components = (
            alert_type,
            source_ip or "-",
            dest_ip or "-",
            mitre_attack or "-",
        )
        return "\x1f".join(components)
