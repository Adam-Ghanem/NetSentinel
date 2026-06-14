import collections
import time
from app.utils import get_timestamp

class PacketAnalyzer:
    def __init__(self):
        self.connections = {}
        self.connection_timeout = 300  # 5 minutes for connection timeout
        self.traffic_stats = collections.defaultdict(lambda: {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': collections.defaultdict(int),
            'dest_ports': collections.defaultdict(int),
            'last_seen': 0
        })

    def analyze_packet(self, parsed_packet):
        self._update_connections(parsed_packet)
        self._update_traffic_stats(parsed_packet)
        # Further analysis can be added here
        return parsed_packet

    def _update_connections(self, packet_data):
        # Create a unique connection identifier (5-tuple)
        if packet_data['source_ip'] and packet_data['dest_ip'] and packet_data['protocol']:
            # Ensure consistent order for connection ID
            if packet_data['source_ip'] < packet_data['dest_ip']:
                conn_key = (
                    packet_data['source_ip'], packet_data['source_port'],
                    packet_data['dest_ip'], packet_data['dest_port'],
                    packet_data['protocol']
                )
            else:
                conn_key = (
                    packet_data['dest_ip'], packet_data['dest_port'],
                    packet_data['source_ip'], packet_data['source_port'],
                    packet_data['protocol']
                )

            current_time = time.time()

            if conn_key not in self.connections:
                self.connections[conn_key] = {
                    'conn_id': f"C{hash(conn_key)}", # Simple hash for connection ID
                    'source_ip': packet_data['source_ip'],
                    'dest_ip': packet_data['dest_ip'],
                    'source_port': packet_data['source_port'],
                    'dest_port': packet_data['dest_port'],
                    'protocol': packet_data['protocol'],
                    'start_time': current_time,
                    'last_seen': current_time,
                    'bytes_sent': 0,
                    'bytes_received': 0,
                    'packet_count': 0,
                    'state': 'ESTABLISHED' # Simplified state
                }
            
            conn = self.connections[conn_key]
            conn['last_seen'] = current_time
            conn['packet_count'] += 1

            # Update bytes sent/received based on direction
            if packet_data['source_ip'] == conn['source_ip']:
                conn['bytes_sent'] += packet_data['packet_size']
            else:
                conn['bytes_received'] += packet_data['packet_size']

            # Clean up old connections
            self._cleanup_old_connections(current_time)

    def _cleanup_old_connections(self, current_time):
        keys_to_delete = []
        for conn_key, conn_data in self.connections.items():
            if current_time - conn_data['last_seen'] > self.connection_timeout:
                # Finalize connection data before deletion (e.g., calculate duration)
                conn_data['duration'] = conn_data['last_seen'] - conn_data['start_time']
                # Here you would typically save the finalized connection to the database
                # For now, just print it
                # print(f"Finalized Connection: {conn_data}")
                keys_to_delete.append(conn_key)
        for key in keys_to_delete:
            del self.connections[key]

    def _update_traffic_stats(self, packet_data):
        src_ip = packet_data['source_ip']
        if src_ip:
            self.traffic_stats[src_ip]['total_packets'] += 1
            self.traffic_stats[src_ip]['total_bytes'] += packet_data['packet_size']
            self.traffic_stats[src_ip]['protocols'][packet_data['protocol']] += 1
            if packet_data['dest_port']:
                self.traffic_stats[src_ip]['dest_ports'][packet_data['dest_port']] += 1
            self.traffic_stats[src_ip]['last_seen'] = time.time()

    def get_connections(self):
        # Return active connections, also finalize old ones before returning
        self._cleanup_old_connections(time.time())
        return list(self.connections.values())

    def get_traffic_stats(self):
        return self.traffic_stats

if __name__ == '__main__':
    analyzer = PacketAnalyzer()
    
    # Simulate some packets
    sample_packet1 = {
        "timestamp": get_timestamp(), "source_mac": "00:11:22:33:44:55", "dest_mac": "AA:BB:CC:DD:EE:FF",
        "source_ip": "192.168.1.10", "dest_ip": "8.8.8.8", "protocol": "UDP",
        "source_port": 50000, "dest_port": 53, "packet_size": 100, "tcp_flags": None,
        "dns_query": "example.com", "http_host": None, "http_path": None
    }
    analyzer.analyze_packet(sample_packet1)
    time.sleep(1)

    sample_packet2 = {
        "timestamp": get_timestamp(), "source_mac": "00:11:22:33:44:55", "dest_mac": "AA:BB:CC:DD:EE:FF",
        "source_ip": "192.168.1.10", "dest_ip": "8.8.8.8", "protocol": "UDP",
        "source_port": 50001, "dest_port": 53, "packet_size": 120, "tcp_flags": None,
        "dns_query": "google.com", "http_host": None, "http_path": None
    }
    analyzer.analyze_packet(sample_packet2)
    time.sleep(1)

    sample_packet3 = {
        "timestamp": get_timestamp(), "source_mac": "AA:BB:CC:DD:EE:FF", "dest_mac": "00:11:22:33:44:55",
        "source_ip": "8.8.8.8", "dest_ip": "192.168.1.10", "protocol": "UDP",
        "source_port": 53, "dest_port": 50000, "packet_size": 80, "tcp_flags": None,
        "dns_query": None, "http_host": None, "http_path": None
    }
    analyzer.analyze_packet(sample_packet3)

    print("\nActive Connections:")
    for conn in analyzer.get_connections():
        print(conn)

    print("\nTraffic Stats:")
    for ip, stats in analyzer.get_traffic_stats().items():
        print(f"IP: {ip}, Stats: {stats}")

    # Simulate connection timeout
    print("\nSimulating connection timeout...")
    analyzer.connection_timeout = 1 # Set a short timeout for testing
    time.sleep(2)
    analyzer._cleanup_old_connections(time.time())
    print("Connections after cleanup:", analyzer.get_connections())
