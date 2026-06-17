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
        # 1. Basic Filters
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

        # 2. DNS Pattern
        if rule.get("dns_query_pattern") and parsed_packet.get("dns_query"):
            if not re.search(rule["dns_query_pattern"], parsed_packet["dns_query"]):
                return False
        elif rule.get("dns_query_pattern") and not parsed_packet.get("dns_query"):
            return False

        # 3. Stateful / Traffic Stats Checks
        src_ip = parsed_packet.get("source_ip")
        stats = traffic_stats.get(src_ip, {}) if src_ip else {}
        
        time_window = rule.get("time_window_seconds", 60)
        current_time = time.time()

        # Filter stats for time window if possible (simplified here)
        if stats:
            # Port Scan Detection
            if rule.get("min_unique_ports"):
                if len(stats.get("dest_ports", {})) < rule["min_unique_ports"]:
                    return False

            # High SYN Packet Count
            if rule.get("min_syn_packets"):
                if stats.get("syn_packets", 0) < rule["min_syn_packets"]:
                    return False

            # DNS Flood
            if rule.get("min_dns_queries"):
                if stats.get("dns_queries", 0) < rule["min_dns_queries"]:
                    return False

            # High Traffic Volume
            if rule.get("min_bytes_per_second"):
                duration = max(1, current_time - stats.get("start_time", current_time))
                if (stats.get("total_bytes", 0) / duration) < rule["min_bytes_per_second"]:
                    return False

            # Beaconing Detection (simplified interval variance check)
            if rule.get("interval_variance_threshold"):
                history = stats.get("connection_history", [])
                if len(history) < 5:
                    return False
                intervals = [history[i] - history[i-1] for i in range(1, len(history))]
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                if variance > rule["interval_variance_threshold"]:
                    return False

        # 4. External IP Check
        if rule.get("is_external_ip"):
            dst_ip = parsed_packet.get("dest_ip")
            if not dst_ip or not is_public_ip(dst_ip):
                return False

        # 5. Unusual Ports
        if rule.get("unusual_ports"):
            dst_port = parsed_packet.get("dest_port")
            if dst_port not in rule["unusual_ports"]:
                return False

        return True
