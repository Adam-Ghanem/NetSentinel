import time

from app.utils import get_logger
from app.ml_engine import MLEngine

logger = get_logger(__name__)

class PacketAnalyzer:
    """Track recent traffic statistics and connection state."""

    def __init__(self, db_manager=None):
        self.db = db_manager
        self.connections = {}
        self.traffic_stats = {}
        self.ml_engine = MLEngine()
        self.last_cleanup = time.time()
        self.last_train = time.time()

    def analyze_packet(self, parsed_packet):
        src_ip = parsed_packet.get("source_ip")
        if not src_ip:
            return

        self._update_traffic_stats(src_ip, parsed_packet)
        self._update_connections(parsed_packet)
        self._run_ml_check(src_ip)
        if time.time() - self.last_cleanup > 300:
            self._cleanup_old_connections()
            self.last_cleanup = time.time()

    def _update_traffic_stats(self, src_ip, packet):
        now = time.time()
        if src_ip not in self.traffic_stats:
            self.traffic_stats[src_ip] = {
                "total_packets": 0, "total_bytes": 0, "protocols": {},
                "dest_ports": {}, "last_seen": now, "start_time": now,
                "dns_queries": 0, "syn_packets": 0, "connection_history": [],
                "syn_ack_packets": 0, "recent_packets": [], "threat_score": 0
            }
        
        stats = self.traffic_stats[src_ip]
        stats["total_packets"] += 1
        stats["total_bytes"] += packet.get("packet_size", 0)
        stats["last_seen"] = now
        
        if packet.get("protocol"):
            stats["protocols"][packet["protocol"]] = stats["protocols"].get(packet["protocol"], 0) + 1
        if packet.get("dest_port"):
            stats["dest_ports"][packet["dest_port"]] = stats["dest_ports"].get(packet["dest_port"], 0) + 1
        if packet.get("dns_query"):
            stats["dns_queries"] += 1
        if packet.get("tcp_flags") == "S":
            stats["syn_packets"] += 1
        if packet.get("tcp_flags") == "SA":
            stats["syn_ack_packets"] += 1

        stats["connection_history"].append(now)
        stats["recent_packets"].append(
            {
                "timestamp": now,
                "dest_port": packet.get("dest_port"),
                "tcp_flags": packet.get("tcp_flags"),
                "dns_query": packet.get("dns_query"),
                "packet_size": packet.get("packet_size", 0),
                "dest_ip": packet.get("dest_ip"),
            }
        )
        cutoff = now - 600
        stats["connection_history"] = [
            timestamp for timestamp in stats["connection_history"] if timestamp >= cutoff
        ][-500:]
        stats["recent_packets"] = [
            item for item in stats["recent_packets"] if item["timestamp"] >= cutoff
        ][-2000:]

    def _update_connections(self, packet):
        src_ip, dst_ip = packet.get("source_ip"), packet.get("dest_ip")
        src_p, dst_p = packet.get("source_port"), packet.get("dest_port")
        proto = packet.get("protocol")

        if not all([src_ip, dst_ip, proto]):
            return

        conn_key = (src_ip, dst_ip, src_p, dst_p, proto)
        if conn_key not in self.connections:
            self.connections[conn_key] = {
                "source_ip": src_ip, "dest_ip": dst_ip, "protocol": proto,
                "start_time": time.time(), "last_seen": time.time(), "packets": 0
            }
        self.connections[conn_key]["packets"] += 1
        self.connections[conn_key]["last_seen"] = time.time()

    def _run_ml_check(self, src_ip):
        if time.time() - self.last_train > 600:
            self.ml_engine.train_model(self.traffic_stats)
            self.last_train = time.time()

        if self.ml_engine.is_trained:
            stats = self.traffic_stats.get(src_ip)
            if stats and self.ml_engine.predict_anomaly(stats):
                stats["threat_score"] += 50
                logger.warning(f"ML Anomaly detected for {src_ip}")

    def _cleanup_old_connections(self):
        current = time.time()
        self.connections = {k: v for k, v in self.connections.items() if current - v["last_seen"] < 3600}

    def get_traffic_stats(self, src_ip):
        return self.traffic_stats.get(src_ip, {})

    def get_all_traffic_stats(self):
        return self.traffic_stats

    def get_connections(self):
        return list(self.connections.values())
