from __future__ import annotations

import re
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from app.contracts import DetectionRule, PacketMetadata
from app.utils import get_logger, is_public_ip

logger = get_logger(__name__)


class RulesEngine:
    """Load validated YAML rules and evaluate them against packet metadata."""

    def __init__(self, rules_dir: str | Path = "rules") -> None:
        self.rules_dir = Path(rules_dir)
        self.rules = self._load_rules()

    def _load_rules(self) -> list[DetectionRule]:
        rules: list[DetectionRule] = []
        self.rules_dir.mkdir(parents=True, exist_ok=True)

        for filepath in sorted(self.rules_dir.glob("*.y*ml")):
            try:
                loaded = yaml.safe_load(filepath.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError) as exc:
                logger.error("Unable to load detection rule file %s: %s", filepath, exc)
                continue

            candidates = loaded if isinstance(loaded, list) else [loaded]
            for index, candidate in enumerate(candidates, start=1):
                if not isinstance(candidate, dict):
                    logger.error("Skipping non-object rule %s[%d]", filepath, index)
                    continue
                try:
                    rules.append(DetectionRule.model_validate(candidate))
                except ValidationError as exc:
                    logger.error(
                        "Skipping invalid detection rule %s[%d]: %s",
                        filepath,
                        index,
                        exc,
                    )

        logger.info("Loaded %d validated detection rules.", len(rules))
        return rules

    def evaluate_rules(
        self,
        parsed_packet: PacketMetadata | Mapping[str, Any],
        connections: Mapping[str, Any],
        traffic_stats: Mapping[str, Mapping[str, Any]],
    ) -> list[DetectionRule]:
        packet = (
            parsed_packet
            if isinstance(parsed_packet, PacketMetadata)
            else PacketMetadata.model_validate(parsed_packet)
        )
        return [
            rule
            for rule in self.rules
            if self._check_rule(rule, packet, connections, traffic_stats)
        ]

    def _check_rule(
        self,
        rule: DetectionRule,
        packet: PacketMetadata,
        _connections: Mapping[str, Any],
        traffic_stats: Mapping[str, Mapping[str, Any]],
    ) -> bool:
        if rule.protocol and packet.protocol != rule.protocol:
            return False
        if rule.dest_port is not None and packet.dest_port != rule.dest_port:
            return False
        if rule.source_ip and packet.source_ip != rule.source_ip:
            return False
        if rule.tcp_flags and packet.tcp_flags != rule.tcp_flags:
            return False
        if rule.arp_op and packet.arp_op != rule.arp_op:
            return False

        if rule.payload_pattern:
            if not packet.payload_printable:
                return False
            if not re.search(rule.payload_pattern, packet.payload_printable):
                return False

        if rule.dns_query_pattern:
            if not packet.dns_query:
                return False
            if not re.search(rule.dns_query_pattern, packet.dns_query):
                return False

        stats = traffic_stats.get(packet.source_ip, {}) if packet.source_ip else {}
        current_time = time.time()

        if stats:
            if rule.min_unique_ports is not None:
                if len(stats.get("dest_ports", {})) < rule.min_unique_ports:
                    return False

            if rule.min_syn_packets is not None:
                if stats.get("syn_packets", 0) < rule.min_syn_packets:
                    return False

            if rule.min_dns_queries is not None:
                if stats.get("dns_queries", 0) < rule.min_dns_queries:
                    return False

            if rule.min_bytes_per_second is not None:
                duration = max(1, current_time - stats.get("start_time", current_time))
                if (stats.get("total_bytes", 0) / duration) < rule.min_bytes_per_second:
                    return False

            if rule.min_connections is not None:
                if stats.get("connections", 0) < rule.min_connections:
                    return False

            if rule.interval_variance_threshold is not None:
                history = stats.get("connection_history", [])
                if len(history) < 5:
                    return False
                intervals = [history[index] - history[index - 1] for index in range(1, len(history))]
                average = sum(intervals) / len(intervals)
                variance = sum((interval - average) ** 2 for interval in intervals) / len(intervals)
                if variance > rule.interval_variance_threshold:
                    return False

            if rule.syn_ack_ratio_threshold is not None:
                syn_packets = stats.get("syn_packets", 0)
                syn_ack_packets = stats.get("syn_ack_packets", 0)
                if syn_packets <= 0:
                    return False
                if (syn_ack_packets / syn_packets) > rule.syn_ack_ratio_threshold:
                    return False

        if rule.is_external_ip:
            if not packet.dest_ip or not is_public_ip(packet.dest_ip):
                return False

        if rule.unusual_ports and packet.dest_port not in rule.unusual_ports:
            return False

        return True
