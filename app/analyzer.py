import time
import hashlib
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

        # 3. Periodic Cleanup (every 5 minutes)
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
                "connection_history": [] # list of timestamps for interval analysis
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
        # Keep only last 100 connections for analysis
        if len(stats["connection_history"]) > 100:
            stats["connection_history"].pop(0)

    def _update_connections(self, packet):
        src_ip = packet.get("source_ip")
        dst_ip = packet.get("dest_ip")
        src_port = packet.get("source_port")
        dst_port = packet.get("dest_port")
        proto = packet.get("protocol")

        if not all([src_ip, dst_ip, proto]):
            return

        # Build 5-tuple key
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
                "state": "ESTABLISHED"
            }
        
        conn = self.connections[conn_key]
        conn["last_seen"] = time.time()
        conn["packets"] += 1
        conn["bytes_sent"] += packet.get("packet_size", 0)
        
        # In a real NDR, we'd handle TCP state machine here
        if packet.get("tcp_flags") == "F" or packet.get("tcp_flags") == "R":
            conn["state"] = "CLOSED"

    def _cleanup_old_connections(self, timeout=3600):
        current_time = time.time()
        to_delete = []
        for key, conn in self.connections.items():
            if current_time - conn["last_seen"] > timeout:
                # Optionally persist finalized connection to DB here
                to_delete.append(key)
        
        for key in to_delete:
            del self.connections[key]
        
        logger.info(f"Cleaned up {len(to_delete)} stale connections.")

    def get_traffic_stats(self, src_ip):
        return self.traffic_stats.get(src_ip, {})

    def get_all_traffic_stats(self):
        return self.traffic_stats

    def get_connections(self):
        return list(self.connections.values())
