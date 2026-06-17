from scapy.all import Ether, ARP, IP, TCP, UDP, ICMP, DNS, Raw
import re
import datetime

def parse_packet(packet, timestamp):
    """
    Extracts comprehensive metadata and payload from raw packets for Deep Packet Inspection (DPI).
    """
    packet_data = {
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
        "dns_query": None,
        "http_host": None,
        "http_path": None,
        "payload_raw": None,
        "payload_printable": None
    }

    if Ether in packet:
        packet_data["source_mac"] = packet[Ether].src
        packet_data["dest_mac"] = packet[Ether].dst

    if IP in packet:
        packet_data["source_ip"] = packet[IP].src
        packet_data["dest_ip"] = packet[IP].dst
        
        # Protocol Mapping
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        packet_data["protocol"] = proto_map.get(packet[IP].proto, str(packet[IP].proto))

        if TCP in packet:
            packet_data["protocol"] = "TCP"
            packet_data["source_port"] = packet[TCP].sport
            packet_data["dest_port"] = packet[TCP].dport
            packet_data["tcp_flags"] = str(packet[TCP].flags)
            
            if Raw in packet:
                payload = packet[Raw].load
                packet_data["payload_raw"] = payload.hex()
                try:
                    decoded = payload.decode('utf-8', errors='ignore')
                    packet_data["payload_printable"] = decoded
                    
                    # Enhanced HTTP Parsing
                    if any(verb in decoded for verb in ["GET", "POST", "PUT", "DELETE", "HTTP/"]):
                        headers = decoded.split("\r\n")
                        if headers:
                            request_parts = headers[0].split(" ")
                            if len(request_parts) > 1:
                                packet_data["http_path"] = request_parts[1]
                            
                            for header in headers:
                                if header.lower().startswith("host:"):
                                    packet_data["http_host"] = header.split(":", 1)[1].strip()
                                    break
                except:
                    pass

        elif UDP in packet:
            packet_data["protocol"] = "UDP"
            packet_data["source_port"] = packet[UDP].sport
            packet_data["dest_port"] = packet[UDP].dport

            if DNS in packet and packet[DNS].qr == 0 and packet[DNS].qd:
                packet_data["dns_query"] = packet[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip(".")
                
            if Raw in packet:
                payload = packet[Raw].load
                packet_data["payload_raw"] = payload.hex()
                try:
                    packet_data["payload_printable"] = payload.decode('utf-8', errors='ignore')
                except:
                    pass

        elif ICMP in packet:
            packet_data["protocol"] = "ICMP"

    elif ARP in packet:
        packet_data["protocol"] = "ARP"
        packet_data["source_ip"] = packet[ARP].psrc
        packet_data["dest_ip"] = packet[ARP].pdst

    return packet_data
