from scapy.all import wrpcap, Ether, IP, TCP, UDP
import os

def generate_sample_pcap(filename="tests/sample.pcap"):
    packets = []
    
    # HTTP Traffic
    packets.append(Ether()/IP(src="192.168.1.10", dst="93.184.216.34")/TCP(sport=12345, dport=80, flags="S"))
    packets.append(Ether()/IP(src="93.184.216.34", dst="192.168.1.10")/TCP(sport=80, dport=12345, flags="SA"))
    
    # DNS Traffic
    packets.append(Ether()/IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=54321, dport=53))
    
    # Potential Port Scan (Multiple SYNs)
    for port in [21, 22, 23, 25, 443]:
        packets.append(Ether()/IP(src="10.0.0.5", dst="192.168.1.10")/TCP(sport=5555, dport=port, flags="S"))

    wrpcap(filename, packets)
    print(f"Generated {len(packets)} packets in {filename}")

if __name__ == "__main__":
    if not os.path.exists("tests"):
        os.makedirs("tests")
    generate_sample_pcap()
