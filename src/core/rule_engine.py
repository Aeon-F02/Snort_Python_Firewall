import json  

class RuleEngine:
    def __init__(self, rules_file="src/core/configs/default_rules.json"):
        self.rules_file = rules_file
        self.rules = []  # Initialize rules as a list
        self.load_rules()

    def load_rules(self):
        try:
            with open(self.rules_file, "r") as file:
                data = json.load(file)
                
                # If rules are inside a dictionary, extract them
                if isinstance(data, dict):
                    self.rules = data.get("rules", [])
                elif isinstance(data, list):
                    self.rules = data  # If it's already a list, use it directly

            print("Rules loaded successfully.")
        except FileNotFoundError:
            print("Rules file not found. Starting with no rules.")
        except json.JSONDecodeError:
            print("Error parsing rules file. Ensure it's a valid JSON file.")

    def save_rules(self):
        try:
            with open(self.rules_file, "w") as file:
                json.dump({"rules": self.rules}, file, indent=4)  # Wrap the rules in a dictionary
            print(f"Rules saved to {self.rules_file}.")
        except Exception as e:
            print(f"Error saving rules: {e}")

    def add_rule(self, rule):
        self.rules.append(rule)  # This should work if self.rules is a list
        print(f"Added rule: {rule}")
        self.save_rules()  # Ensure rule is saved

    def remove_rule(self, rule):
        print(f"Current rules before removal: {self.rules}")  # Debugging line
        if rule in self.rules:
            self.rules.remove(rule)
            print(f"Removed rule: {rule}")
            self.save_rules()  # Ensure rule is saved after removal
        else:
            print("Rule not found.")
    

    def check_packet(self, packet):
        """
        Checks if the given packet matches any rule.
        Returns "ALLOW" if no rule matches, or "BLOCK" if a rule matches.
        """
        if not self.rules:
            return "ALLOW"  # No rules mean the packet is allowed by default

        for rule in self.rules:
            if rule.get("src") and packet.get("ip", {}).get("src") != rule["src"]:
                continue
            if rule.get("dst") and packet.get("ip", {}).get("dst") != rule["dst"]:
                continue
            if rule.get("protocol") and packet.get("protocol") != rule["protocol"]:
                continue

            return "ALLOW"  # Packet matches a rule

        return "BLOCK"  # No rules matched, allow the packet
 

    
    def test_check_packet_allow(self):
        packet = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1"}  # Adjust structure
        result = self.engine.check_packet(packet)
        self.assertEqual(result, "ALLOW")  # No rule matches this packet

    def test_check_packet_block(self):
        self.engine.add_rule({"src_ip": "192.168.1.100", "action": "BLOCK"})
        packet = {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.1"}
        result = self.engine.check_packet(packet)
        self.assertEqual(result, "BLOCK")  # Blocked by the rule

