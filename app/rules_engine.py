import yaml
import os
import re
from datetime import datetime, timedelta

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
                        print(f"Error loading YAML rule file {filepath}: {e}")
        print(f"Loaded {len(rules)} detection rules.")
        return rules

    def evaluate_rules(self, parsed_packet, connections, traffic_stats):
        triggered_rules = []
        for rule in self.rules:
            if self._check_rule(rule, parsed_packet, connections, traffic_stats):
                triggered_rules.append(rule)
        return triggered_rules

    def _check_rule(self, rule, parsed_packet, connections, traffic_stats):
        # 1. Protocol Match
        if rule.get("protocol") and parsed_packet.get("protocol") != rule["protocol"]:
            return False

        # 2. Destination Port Match
        if rule.get("dest_port") and parsed_packet.get("dest_port") != rule["dest_port"]:
            return False

        # 3. Source IP Match
        if rule.get("source_ip") and parsed_packet.get("source_ip") != rule["source_ip"]:
            return False

        # 4. TCP Flags Match
        if rule.get("tcp_flags") and parsed_packet.get("tcp_flags") != rule["tcp_flags"]:
            return False

        # 5. DNS Query Pattern (Regex)
        if rule.get("dns_query_pattern") and parsed_packet.get("dns_query"):
            if not re.search(rule["dns_query_pattern"], parsed_packet["dns_query"]):
                return False
        elif rule.get("dns_query_pattern") and not parsed_packet.get("dns_query"):
            return False

        # 6. Stateful / Traffic Stats Checks
        source_ip = parsed_packet.get("source_ip")
        if source_ip and traffic_stats.get(source_ip):
            stats = traffic_stats[source_ip]
            
            # High Traffic Volume
            if rule.get("min_packets") and stats.get("total_packets", 0) < rule["min_packets"]:
                return False
            
            # Port Scan (Multiple unique destination ports)
            if rule.get("min_unique_ports"):
                unique_ports = len(stats.get("dest_ports", {}))
                if unique_ports < rule["min_unique_ports"]:
                    return False

        # 7. Unusual Ports
        if rule.get("unusual_ports") and parsed_packet.get("dest_port"):
            if parsed_packet["dest_port"] not in rule["unusual_ports"]:
                return False

        return True

if __name__ == '__main__':
    # Simple test
    re_engine = RulesEngine()
    test_packet = {"protocol": "TCP", "dest_port": 80, "source_ip": "1.2.3.4"}
    rule = {"name": "Test", "protocol": "TCP", "dest_port": 80}
    print(f"Match: {re_engine._check_rule(rule, test_packet, {}, {})}")
