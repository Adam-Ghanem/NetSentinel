import yaml
import os
import re
import time
from app.utils import get_logger, is_public_ip

logger = get_logger(__name__)

class RulesEngine:
    def __init__(self, rules_dir="rules"):
        self.rules_dir = rules_dir
        self.rules = self._load_rules()

    def _load_rules(self):
        rules = []
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            return rules
            
        for filename in os.listdir(self.rules_dir):
            if filename.endswith((".yaml", ".yml")):
                filepath = os.path.join(self.rules_dir, filename)
                with open(filepath, "r") as f:
                    try:
                        loaded_rules = yaml.safe_load(f)
                        if isinstance(loaded_rules, list):
                            rules.extend(loaded_rules)
                        elif isinstance(loaded_rules, dict):
                            rules.append(loaded_rules)
                    except yaml.YAMLError as e:
                        logger.error(f"Error loading YAML rule file {filepath}: {e}")
        logger.info(f"Loaded {len(rules)} detection rules.")
        return rules

    def evaluate_rules(self, parsed_packet, connections, traffic_stats):
        triggered_rules = []
        for rule in self.rules:
            if self._check_rule(rule, parsed_packet, connections, traffic_stats):
                triggered_rules.append(rule)
        return triggered_rules

    def _check_rule(self, rule, parsed_packet, connections, traffic_stats):
        if rule.get("protocol") and parsed_packet.get("protocol") != rule["protocol"]:
            return False
        if rule.get("dest_port") and parsed_packet.get("dest_port") != rule["dest_port"]:
            return False
        if rule.get("source_ip") and parsed_packet.get("source_ip") != rule["source_ip"]:
            return False
        if rule.get("tcp_flags") and parsed_packet.get("tcp_flags") != rule["tcp_flags"]:
            return False
        if rule.get("arp_op") and parsed_packet.get("arp_op") != rule["arp_op"]:
            return False

        if rule.get("payload_pattern"):
            payload = parsed_packet.get("payload_printable")
            if not payload:
                return False
            if not re.search(rule["payload_pattern"], payload):
                return False

        if rule.get("dns_query_pattern") and parsed_packet.get("dns_query"):
            if not re.search(rule["dns_query_pattern"], parsed_packet["dns_query"]):
                return False
        elif rule.get("dns_query_pattern") and not parsed_packet.get("dns_query"):
            return False

        src_ip = parsed_packet.get("source_ip")
        stats = traffic_stats.get(src_ip, {}) if src_ip else {}
        current_time = time.time()
        window_seconds = max(1, int(rule.get("time_window_seconds", 600)))
        recent_packets = [
            item
            for item in stats.get("recent_packets", [])
            if current_time - item.get("timestamp", 0) <= window_seconds
        ]

        stateful_fields = {
            "min_unique_ports",
            "min_syn_packets",
            "min_dns_queries",
            "min_bytes_per_second",
            "min_connections",
            "syn_ack_ratio_threshold",
            "interval_variance_threshold",
        }
        if any(field in rule for field in stateful_fields) and not recent_packets:
            return False

        if "min_unique_ports" in rule:
            unique_ports = {item["dest_port"] for item in recent_packets if item.get("dest_port")}
            if len(unique_ports) < rule["min_unique_ports"]:
                return False

        syn_packets = sum(item.get("tcp_flags") == "S" for item in recent_packets)
        if "min_syn_packets" in rule and syn_packets < rule["min_syn_packets"]:
            return False

        if "min_dns_queries" in rule:
            dns_queries = sum(bool(item.get("dns_query")) for item in recent_packets)
            if dns_queries < rule["min_dns_queries"]:
                return False

        if "min_connections" in rule:
            connection_packets = recent_packets
            destination_ip = parsed_packet.get("dest_ip")
            if rule.get("is_external_ip") and destination_ip:
                connection_packets = [
                    item for item in recent_packets if item.get("dest_ip") == destination_ip
                ]
            if len(connection_packets) < rule["min_connections"]:
                return False

        if "min_bytes_per_second" in rule:
            total_bytes = sum(item.get("packet_size", 0) for item in recent_packets)
            first_seen = min(item["timestamp"] for item in recent_packets)
            duration = max(1, current_time - first_seen)
            if total_bytes / duration < rule["min_bytes_per_second"]:
                return False

        if "syn_ack_ratio_threshold" in rule:
            syn_ack_packets = sum(item.get("tcp_flags") == "SA" for item in recent_packets)
            ratio = syn_ack_packets / max(1, syn_packets)
            if ratio >= rule["syn_ack_ratio_threshold"]:
                return False

        if "interval_variance_threshold" in rule:
            history = [item["timestamp"] for item in recent_packets]
            if len(history) < 5:
                return False
            intervals = [history[index] - history[index - 1] for index in range(1, len(history))]
            average = sum(intervals) / len(intervals)
            variance = sum((value - average) ** 2 for value in intervals) / len(intervals)
            if variance > rule["interval_variance_threshold"]:
                return False

        if rule.get("is_external_ip"):
            dst_ip = parsed_packet.get("dest_ip")
            if not dst_ip or not is_public_ip(dst_ip):
                return False

        if rule.get("unusual_ports"):
            dst_port = parsed_packet.get("dest_port")
            if dst_port not in rule["unusual_ports"]:
                return False

        return True
