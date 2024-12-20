import argparse
import logging
from src.core.packet_sniffer import PacketSniffer
from src.core.rule_engine import RuleEngine
from src.core.packet_filter import PacketFilter
from src.core.logger import Logger
from src.core.connection_tracker import ConnectionTracker
from src.utils.traffic_monitor import get_traffic_statistics
from src.utils.helpers import Helper
from src.utils.ip_utils import IpUtils
from src.tests.test_firewall import run_all_tests
import unittest
import json


def initialize_firewall():
    """
    Initializes the firewall components, including rules, sniffer, and logger.
    """
    print("Initializing Firewall...")
    # Set up logging
    logger = Logger("logs/firewall.log")
    logger.log("Firewall initialized", level="INFO")
    
    # Initialize rule engine
    rule_engine = RuleEngine()
    try:
        if not rule_engine.rules:  # Load rules only if not already loaded
            rule_engine.load_rules()
            logger.log("Rules loaded successfully", level="INFO")
    except Exception as e:
        logger.log(f"Error loading rules: {e}", level="ERROR")
    
    # Initialize packet filter and connection tracker
    packet_filter = PacketFilter(rule_engine)  # Pass RuleEngine instance
    connection_tracker = ConnectionTracker()

    return packet_filter, logger, connection_tracker


def add_ip_rule(ip, subnet):
    """Example function to add a rule based on IP validation and subnet check."""
    if IpUtils.is_valid_ip(ip):
        if IpUtils.is_ip_in_subnet(ip, subnet):
            print(f"IP {ip} is valid and belongs to the subnet {subnet}.")
            # Proceed with adding the rule
        else:
            print(f"IP {ip} does not belong to the subnet {subnet}. Rule not added.")
    else:
        print(f"Invalid IP address: {ip}. Rule not added.")


def start_sniffer(packet_filter, logger):
    print("Starting Packet Sniffer...")
    sniffer = PacketSniffer(
        interface="wlan0", 
        packet_filter=packet_filter,  # Pass the PacketFilter instance
        logger=logger
    )
    sniffer.start()


def main():
    """
    Main function to provide CLI for the firewall.
    """
    # Initialize firewall components
    packet_filter, logger, connection_tracker = initialize_firewall()

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Python Firewall CLI")
    parser.add_argument("-s", "--start", action="store_true", help="Start the firewall")
    parser.add_argument("-a", "--add-rule", type=str, help="Add a firewall rule (JSON format)")
    parser.add_argument("-r", "--remove-rule", type=str, help="Remove a firewall rule (JSON format)")
    parser.add_argument("-l", "--list-rules", action="store_true", help="List all firewall rules")
    parser.add_argument("-c", "--track-connections", action="store_true", help="Track active connections")
    parser.add_argument("-m", "--monitor-traffic", action="store_true", help="Monitor network traffic")
    parser.add_argument("-u", "--run-tests", action="store_true", help="Run unit tests for the firewall")
    parser.add_argument("-i", "--add-ip-rule", type=str, help="Add a rule for a specific IP (format: ip,subnet)")
    args = parser.parse_args()

    # Handle commands
    if args.start:
        start_sniffer(packet_filter, logger)
    elif args.add_rule:
        try:
            rule = json.loads(args.add_rule)  # Parse the rule from JSON
            packet_filter.rule_engine.add_rule(rule)  # Add the rule
            logger.log(f"Rule added: {rule}", level="INFO")
            print(f"Rule added successfully: {rule}")  # Print feedback to console
        except Exception as e:
            logger.log(f"Error adding rule: {e}", level="ERROR")
            print(f"Error adding rule: {e}")  # Print the error to console

    elif args.remove_rule:
        try:
            rule = json.loads(args.remove_rule)
            packet_filter.rule_engine.remove_rule(rule)
            logger.log(f"Rule removed: {rule}", level="INFO")
        except Exception as e:
            logger.log(f"Error removing rule: {e}", level="ERROR")
    elif args.list_rules:
        rules = packet_filter.rule_engine.rules
        print("Current Firewall Rules:")
        for rule in rules:
            print(rule)
    elif args.track_connections:
        print("Active Connections:")
        active_connections = connection_tracker.get_active_connections()
        if active_connections:
            for conn in active_connections:
                print(conn)
        else:
            print("No active connections found.")
    elif args.monitor_traffic:
        stats = get_traffic_statistics()
        print("Network Traffic Statistics:")
        print(f"Total Packets Captured: {stats['packets']}")
        print(f"Total Data Transferred: {stats['data']} bytes")
    elif args.add_ip_rule:
        ip, subnet = args.add_ip_rule.split(",")
        add_ip_rule(ip, subnet)
    elif args.run_tests:
        print("Running unit tests...")
        run_all_tests()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
