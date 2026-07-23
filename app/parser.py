from datetime import datetime
from typing import Any

from scapy.all import ARP, DNS, Ether, ICMP, IP, Raw, TCP, UDP

from app.contracts import PacketMetadata
from app.ja3 import generate_ja3

try:
    from scapy.layers.tls.all import TLSClientHello
except ImportError:
    TLSClientHello = None


def parse_packet(packet: Any, timestamp: datetime) -> dict[str, Any]:
    """Extract and validate packet metadata used by the dashboard and detection engine."""

    packet_data: dict[str, Any] = {
        "timestamp": timestamp,
        "source_mac": None,
        "dest_mac": None,
        "source_ip": None,
        "dest_ip": None,
        "protocol": "UNKNOWN",
        "source_port": None,
        "dest_port": None,
        "packet_size": len(packet),
        "tcp_flags": None,
        "arp_op": None,
        "dns_query": None,
        "http_host": None,
        "http_path": None,
        "payload_raw": None,
        "payload_printable": None,
        "tls_version": None,
        "ja3_hash": None,
    }

    if Ether in packet:
        packet_data["source_mac"] = packet[Ether].src
        packet_data["dest_mac"] = packet[Ether].dst

    if IP in packet:
        packet_data["source_ip"] = packet[IP].src
        packet_data["dest_ip"] = packet[IP].dst

        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        packet_data["protocol"] = proto_map.get(packet[IP].proto, str(packet[IP].proto))

        if TCP in packet:
            packet_data["source_port"] = packet[TCP].sport
            packet_data["dest_port"] = packet[TCP].dport
            packet_data["tcp_flags"] = str(packet[TCP].flags)

            if TLSClientHello is not None and packet.haslayer(TLSClientHello):
                ja3_data = generate_ja3(packet)
                if ja3_data:
                    packet_data["protocol"] = "TLS"
                    packet_data["ja3_hash"] = ja3_data.get("ja3_hash")
                    tls_layer = packet.getlayer(TLSClientHello)
                    packet_data["tls_version"] = str(getattr(tls_layer, "version", ""))

            if Raw in packet:
                payload = packet[Raw].load
                packet_data["payload_raw"] = payload.hex()
                decoded = payload.decode("utf-8", errors="ignore")
                packet_data["payload_printable"] = decoded

                if any(verb in decoded for verb in ["GET", "POST", "HTTP/"]):
                    headers = decoded.split("\r\n")
                    if headers:
                        request_parts = headers[0].split(" ")
                        if len(request_parts) > 1:
                            packet_data["http_path"] = request_parts[1]
                        for header in headers:
                            if header.lower().startswith("host:"):
                                packet_data["http_host"] = header.split(":", 1)[1].strip()
                                break

        elif UDP in packet:
            packet_data["source_port"] = packet[UDP].sport
            packet_data["dest_port"] = packet[UDP].dport
            if DNS in packet and packet[DNS].qr == 0 and packet[DNS].qd:
                packet_data["dns_query"] = packet[DNS].qd.qname.decode(
                    "utf-8", errors="ignore"
                ).rstrip(".")

        elif ICMP in packet:
            packet_data["protocol"] = "ICMP"

    elif ARP in packet:
        packet_data["protocol"] = "ARP"
        packet_data["source_ip"] = packet[ARP].psrc
        packet_data["dest_ip"] = packet[ARP].pdst
        packet_data["arp_op"] = "who-has" if packet[ARP].op == 1 else "is-at"

    return PacketMetadata.model_validate(packet_data).model_dump(mode="python")
