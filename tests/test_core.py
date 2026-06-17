import pytest
import os
from app.parser import parse_packet
from app.rules_engine import RulesEngine
from app.database import DatabaseManager
from app.sniffer import PacketSniffer
from app.analyzer import PacketAnalyzer
from app.detection_engine import DetectionEngine
from scapy.all import IP, TCP, Ether

def test_packet_parser():
    pkt = Ether()/IP(src="1.1.1.1", dst="2.2.2.2")/TCP(sport=1234, dport=80, flags="S")
    parsed = parse_packet(pkt, "2023-01-01T00:00:00")
    
    assert parsed["source_ip"] == "1.1.1.1"
    assert parsed["dest_ip"] == "2.2.2.2"
    assert parsed["protocol"] == "TCP"
    assert parsed["dest_port"] == 80
    assert parsed["tcp_flags"] == "S"

def test_rules_engine_basic():
    re = RulesEngine()
    rule = {"name": "Test Port 80", "protocol": "TCP", "dest_port": 80}
    re.rules = [rule]
    
    packet = {"protocol": "TCP", "dest_port": 80}
    triggered = re.evaluate_rules(packet, {}, {})
    assert len(triggered) == 1
    assert triggered[0]["name"] == "Test Port 80"

def test_db_user_auth():
    db = DatabaseManager(db_url="sqlite:///:memory:")
    db.create_user("testuser", "password123", role="Analyst")
    
    user = db.authenticate_user("testuser", "password123")
    assert user is not None
    assert user.username == "testuser"
    assert user.role == "Analyst"
    
    invalid_user = db.authenticate_user("testuser", "wrongpassword")
    assert invalid_user is None

def test_pcap_processing():
    db = DatabaseManager(db_url="sqlite:///:memory:")
    analyzer = PacketAnalyzer(db)
    re = RulesEngine()
    # Add a port scan rule to trigger on the sample pcap
    re.rules = [{
        "name": "Port Scan Detected",
        "protocol": "TCP",
        "min_unique_ports": 3,
        "severity": "High"
    }]
    de = DetectionEngine(re, db)
    sniffer = PacketSniffer(db, analyzer, de)
    
    pcap_path = "tests/sample.pcap"
    if os.path.exists(pcap_path):
        count = sniffer.process_pcap(pcap_path)
        assert count > 0
        
        # Check if packets were saved
        packets = db.get_packets()
        assert len(packets) > 0
        
        # Check if alerts were generated (the sample pcap has 5 unique ports from 10.0.0.5)
        alerts = db.get_alerts()
        assert len(alerts) > 0
        assert any(a.alert_type == "Port Scan Detected" for a in alerts)
