import yaml
import os

class RulesEngine:
    def __init__(self, rules_dir="rules"):
        self.rules_dir = rules_dir
        self.rules = self._load_rules()

    def _load_rules(self):
        rules = []
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
        # This is a placeholder for actual rule evaluation logic.
        # Rules will be defined in YAML and can check various packet/connection/traffic attributes.
        # For now, a very basic example:
        if rule.get("protocol") and parsed_packet.get("protocol") == rule["protocol"]:
            if rule.get("dest_port") and parsed_packet.get("dest_port") == rule["dest_port"]:
                return True
            if rule.get("source_ip") and parsed_packet.get("source_ip") == rule["source_ip"]:
                return True
        # Add more complex rule matching logic here based on rule structure
        return False

if __name__ == '__main__':
    # Create a dummy rules directory and a sample rule file for testing
    if not os.path.exists("rules"):
        os.makedirs("rules")
    
    sample_rule_content = """
- name: "High Port Scan Detection"
  protocol: "TCP"
  tcp_flags: "S"
  description: "Multiple SYN packets to different ports from a single source IP."
  severity: "High"
  recommended_action: "Block source IP, investigate host."
  mitre_attack: "T1046"
- name: "Suspicious DNS Query"
  protocol: "UDP"
  dest_port: 53
  dns_query_pattern: ".onion$"
  description: "DNS query for a .onion domain, possibly related to Tor."
  severity: "Medium"
  recommended_action: "Investigate client for Tor usage."
  mitre_attack: "T1071.004"
"""
    with open("rules/default_rules.yaml", "w") as f:
        f.write(sample_rule_content)

    rules_engine = RulesEngine()
    
    # Test with a packet that should trigger the DNS rule
    test_packet_dns = {
        "protocol": "UDP",
        "dest_port": 53,
        "dns_query": "example.onion"
    }
    triggered = rules_engine.evaluate_rules(test_packet_dns, {}, {})
    print("\nTriggered rules for DNS packet:")
    for rule in triggered:
        print(rule["name"])

    # Test with a packet that should trigger the Port Scan rule (simplified)
    test_packet_tcp = {
        "protocol": "TCP",
        "tcp_flags": "S",
        "dest_port": 80, # This won't trigger the rule as written, needs more logic
        "source_ip": "192.168.1.10"
    }
    triggered_tcp = rules_engine.evaluate_rules(test_packet_tcp, {}, {})
    print("\nTriggered rules for TCP packet:")
    for rule in triggered_tcp:
        print(rule["name"])

    # Clean up dummy file
    os.remove("rules/default_rules.yaml")
    os.rmdir("rules")
