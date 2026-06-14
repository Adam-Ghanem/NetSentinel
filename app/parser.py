from scapy.all import Ether, ARP, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
import datetime


def parse_packet(packet, timestamp):
    """Extract relevant metadata from a Scapy packet."""
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
    }

    if Ether in packet:
        packet_data["source_mac"] = packet[Ether].src
        packet_data["dest_mac"] = packet[Ether].dst

    if IP in packet:
        packet_data["source_ip"] = packet[IP].src
        packet_data["dest_ip"] = packet[IP].dst
        packet_data["protocol"] = packet[IP].proto

        if TCP in packet:
            packet_data["protocol"] = "TCP"
            packet_data["source_port"] = packet[TCP].sport
            packet_data["dest_port"] = packet[TCP].dport
            packet_data["tcp_flags"] = str(packet[TCP].flags)

            # Basic HTTP host/path extraction (metadata only)
            if (packet[TCP].dport == 80 or packet[TCP].sport == 80) and Raw in packet:
                try:
                    http_payload = packet[Raw].load.decode("utf-8", errors="ignore")
                    if http_payload.startswith(("GET", "POST")):
                        headers = http_payload.split("\r\n")
                        if headers:
                            request_parts = headers[0].split(" ")
                            if len(request_parts) > 1:
                                packet_data["http_path"] = request_parts[1]

                        for header in headers:
                            if header.lower().startswith("host:"):
                                packet_data["http_host"] = header.split(":", 1)[1].strip()
                                break
                except UnicodeDecodeError:
                    pass

        elif UDP in packet:
            packet_data["protocol"] = "UDP"
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

    return packet_data


if __name__ == "__main__":
    # Example usage with a dummy HTTP packet
    dummy_packet = (
        Ether()
        / IP(src="192.168.1.1", dst="192.168.1.100")
        / TCP(sport=12345, dport=80, flags="S")
        / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )

    parsed = parse_packet(dummy_packet, datetime.datetime.now().isoformat())
    print("Parsed Packet:")
    for key, value in parsed.items():
        print(f"  {key}: {value}")

    # Example usage with a dummy DNS packet
    dummy_dns_packet = (
        Ether()
        / IP(src="192.168.1.1", dst="8.8.8.8")
        / UDP(sport=12345, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="www.google.com"))
    )

    parsed_dns = parse_packet(dummy_dns_packet, datetime.datetime.now().isoformat())
    print("\nParsed DNS Packet:")
    for key, value in parsed_dns.items():
        print(f"  {key}: {value}")
