from datetime import datetime, timezone

from app.parser import parse_packet
from scapy.all import ARP, DNS, DNSQR, Ether, IP, Raw, TCP, UDP

TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_parse_http_request_extracts_network_and_application_metadata():
    packet = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=51515, dport=80, flags="PA")
        / Raw(load=b"GET /health HTTP/1.1\r\nHost: sensor.example\r\n\r\n")
    )

    result = parse_packet(packet, TIMESTAMP)

    assert result["timestamp"] == TIMESTAMP
    assert result["source_mac"] == "00:11:22:33:44:55"
    assert result["dest_mac"] == "66:77:88:99:aa:bb"
    assert result["source_ip"] == "192.0.2.10"
    assert result["dest_ip"] == "198.51.100.20"
    assert result["protocol"] == "TCP"
    assert result["source_port"] == 51515
    assert result["dest_port"] == 80
    assert result["tcp_flags"] == "PA"
    assert result["http_host"] == "sensor.example"
    assert result["http_path"] == "/health"
    assert result["payload_raw"] == packet[Raw].load.hex()


def test_parse_dns_query_normalizes_trailing_dot():
    packet = (
        Ether()
        / IP(src="192.0.2.15", dst="192.0.2.53")
        / UDP(sport=53000, dport=53)
        / DNS(qr=0, qd=DNSQR(qname="updates.example."))
    )

    result = parse_packet(packet, TIMESTAMP)

    assert result["protocol"] == "UDP"
    assert result["source_port"] == 53000
    assert result["dest_port"] == 53
    assert result["dns_query"] == "updates.example"


def test_parse_arp_packet_extracts_addresses_without_ip_layer():
    packet = Ether() / ARP(psrc="192.0.2.1", pdst="192.0.2.2")

    result = parse_packet(packet, TIMESTAMP)

    assert result["protocol"] == "ARP"
    assert result["source_ip"] == "192.0.2.1"
    assert result["dest_ip"] == "192.0.2.2"
    assert result["source_port"] is None
    assert result["dest_port"] is None


def test_parse_unknown_ip_protocol_preserves_numeric_protocol_value():
    packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.1", proto=99)

    result = parse_packet(packet, TIMESTAMP)

    assert result["protocol"] == "99"
    assert result["source_ip"] == "192.0.2.1"
    assert result["dest_ip"] == "198.51.100.1"
