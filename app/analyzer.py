import time
import hashlib
import numpy as np
from app.utils import get_logger

logger = get_logger(__name__)

class PacketAnalyzer:
    def __init__(self, db_manager=None):
        self.db = db_manager
        self.connections = {}  # (src_ip, dst_ip, src_port, dst_port, proto) -> connection_data
        self.traffic_stats = {} # src_ip -> stats_data
        self.last_cleanup = time.time()

    def analyze_packet(self, parsed_packet):
        src_ip = parsed_packet.get("source_ip")
        if not src_ip:
            return

        # 1. Update Traffic Stats
        self._update_traffic_stats(src_ip, parsed_packet)

        # 2. Update Connection Tracking
        self._update_connections(parsed_packet)

        # 3. Detect Advanced Patterns (Beaconing, Shells)
        self._detect_advanced_patterns(src_ip)

        # 4. Periodic Cleanup
        if time.time() - self.last_cleanup > 300:
            self._cleanup_old_connections()
            self.last_cleanup = time.time()

    def _update_traffic_stats(self, src_ip, packet):
        if src_ip not in self.traffic_stats:
            self.traffic_stats[src_ip] = {
                "total_packets": 0,
                "total_bytes": 0,
                "protocols": {},
                "dest_ports": {},
                "last_seen": time.time(),
                "start_time": time.time(),
                "dns_queries": 0,
                "syn_packets": 0,
                "connection_history": [],
                "payload_sizes": [],
                "is_suspicious": False,
                "threat_score": 0
            }
        
        stats = self.traffic_stats[src_ip]
        stats["total_packets"] += 1
        stats["total_bytes"] += packet.get("packet_size", 0)
        stats["last_seen"] = time.time()
        
        proto = packet.get("protocol")
        if proto:
            stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1
        
        dst_port = packet.get("dest_port")
        if dst_port:
            stats["dest_ports"][dst_port] = stats["dest_ports"].get(dst_port, 0) + 1
            
        if packet.get("dns_query"):
            stats["dns_queries"] += 1
            
        if packet.get("tcp_flags") == "S":
            stats["syn_packets"] += 1
            
        stats["connection_history"].append(time.time())
        stats["payload_sizes"].append(packet.get("packet_size", 0))
        
        # Keep sliding window
        if len(stats["connection_history"]) > 200:
            stats["connection_history"].pop(0)
            stats["payload_sizes"].pop(0)

    def _update_connections(self, packet):
        src_ip = packet.get("source_ip")
        dst_ip = packet.get("dest_ip")
        src_port = packet.get("source_port")
        dst_port = packet.get("dest_port")
        proto = packet.get("protocol")

        if not all([src_ip, dst_ip, proto]):
            return

        conn_key = (src_ip, dst_ip, src_port, dst_port, proto)
        
        if conn_key not in self.connections:
            conn_id = hashlib.md5(f"{src_ip}{dst_ip}{src_port}{dst_port}{proto}{time.time()}".encode()).hexdigest()
            self.connections[conn_key] = {
                "conn_id": conn_id,
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "source_port": src_port,
                "dest_port": dst_port,
                "protocol": proto,
                "start_time": time.time(),
                "last_seen": time.time(),
                "bytes_sent": 0,
                "bytes_received": 0,
                "packets": 0,
                "state": "ESTABLISHED",
                "history": []
            }
        
        conn = self.connections[conn_key]
        conn["last_seen"] = time.time()
        conn["packets"] += 1
        conn["bytes_sent"] += packet.get("packet_size", 0)
        conn["history"].append(time.time())

    def _detect_advanced_patterns(self, src_ip):
        stats = self.traffic_stats.get(src_ip)
        if not stats or len(stats["connection_history"]) < 10:
            return

        # 1. Beaconing Detection (Interval Variance)
        history = stats["connection_history"]
        intervals = np.diff(history)
        if len(intervals) > 5:
            std_dev = np.std(intervals)
            if std_dev < 0.5: # Very consistent timing
                stats["threat_score"] += 20
                logger.info(f"Potential Beaconing detected from {src_ip} (StdDev: {std_dev:.4f})")

        # 2. Reverse Shell Detection (Small, frequent payloads)
        payloads = stats["payload_sizes"]
        if len(payloads) > 20:
            avg_size = np.mean(payloads)
            if 40 < avg_size < 150: # Typical command/response size
                stats["threat_score"] += 15
                logger.info(f"Suspicious payload pattern from {src_ip} (Avg Size: {avg_size:.2f})")

    def _cleanup_old_connections(self, timeout=3600):
        current_time = time.time()
        to_delete = [key for key, conn in self.connections.items() if current_time - conn["last_seen"] > timeout]
        for key in to_delete:
            del self.connections[key]
        if to_delete:
            logger.info(f"Cleaned up {len(to_delete)} stale connections.")

    def get_traffic_stats(self, src_ip):
        return self.traffic_stats.get(src_ip, {})

    def get_all_traffic_stats(self):
        return self.traffic_stats

    def get_connections(self):
        return list(self.connections.values())
