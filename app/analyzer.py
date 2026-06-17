import time
import hashlib
import numpy as np
from app.utils import get_logger
from app.ml_engine import MLEngine
from app.carver import FileCarver

logger = get_logger(__name__)

class PacketAnalyzer:
    """
    Ultra-Expert Packet Analyzer (5+ Years Exp).
    Integrates Connection Tracking, Behavioral Stats, ML Anomaly Detection, and File Carving.
    """
    def __init__(self, db_manager=None):
        self.db = db_manager
        self.connections = {}
        self.traffic_stats = {}
        self.ml_engine = MLEngine()
        self.carver = FileCarver()
        self.last_cleanup = time.time()
        self.last_train = time.time()

    def analyze_packet(self, parsed_packet):
        src_ip = parsed_packet.get("source_ip")
        if not src_ip:
            return

        # 1. Update Traffic Stats
        self._update_traffic_stats(src_ip, parsed_packet)

        # 2. Update Connection Tracking
        self._update_connections(parsed_packet)

        # 3. ML Anomaly Detection (Periodic Training & Prediction)
        self._run_ml_check(src_ip)

        # 4. File Carving (DPI)
        if parsed_packet.get("payload_raw"):
            self.carver.carve_http_payload(parsed_packet["payload_raw"], src_ip)

        # 5. Periodic Cleanup
        if time.time() - self.last_cleanup > 300:
            self._cleanup_old_connections()
            self.last_cleanup = time.time()

    def _update_traffic_stats(self, src_ip, packet):
        if src_ip not in self.traffic_stats:
            self.traffic_stats[src_ip] = {
                "total_packets": 0, "total_bytes": 0, "protocols": {},
                "dest_ports": {}, "last_seen": time.time(), "start_time": time.time(),
                "dns_queries": 0, "syn_packets": 0, "connection_history": [],
                "payload_sizes": [], "threat_score": 0
            }
        
        stats = self.traffic_stats[src_ip]
        stats["total_packets"] += 1
        stats["total_bytes"] += packet.get("packet_size", 0)
        stats["last_seen"] = time.time()
        
        if packet.get("protocol"):
            stats["protocols"][packet["protocol"]] = stats["protocols"].get(packet["protocol"], 0) + 1
        if packet.get("dest_port"):
            stats["dest_ports"][packet["dest_port"]] = stats["dest_ports"].get(packet["dest_port"], 0) + 1
        if packet.get("dns_query"):
            stats["dns_queries"] += 1
        if packet.get("tcp_flags") == "S":
            stats["syn_packets"] += 1
            
        stats["connection_history"].append(time.time())
        if len(stats["connection_history"]) > 500: stats["connection_history"].pop(0)

    def _update_connections(self, packet):
        src_ip, dst_ip = packet.get("source_ip"), packet.get("dest_ip")
        src_p, dst_p = packet.get("source_port"), packet.get("dest_port")
        proto = packet.get("protocol")

        if not all([src_ip, dst_ip, proto]): return

        conn_key = (src_ip, dst_ip, src_p, dst_p, proto)
        if conn_key not in self.connections:
            self.connections[conn_key] = {
                "source_ip": src_ip, "dest_ip": dst_ip, "protocol": proto,
                "start_time": time.time(), "last_seen": time.time(), "packets": 0
            }
        self.connections[conn_key]["packets"] += 1
        self.connections[conn_key]["last_seen"] = time.time()

    def _run_ml_check(self, src_ip):
        # Periodic Retraining every 10 mins
        if time.time() - self.last_train > 600:
            self.ml_engine.train_model(self.traffic_stats)
            self.last_train = time.time()

        # Predict anomaly
        if self.ml_engine.is_trained:
            stats = self.traffic_stats.get(src_ip)
            if stats and self.ml_engine.predict_anomaly(stats):
                stats["threat_score"] += 50
                logger.warning(f"ML Anomaly detected for {src_ip}")

    def _cleanup_old_connections(self):
        current = time.time()
        self.connections = {k: v for k, v in self.connections.items() if current - v["last_seen"] < 3600}

    def get_traffic_stats(self, src_ip): return self.traffic_stats.get(src_ip, {})
    def get_all_traffic_stats(self): return self.traffic_stats
    def get_connections(self): return list(self.connections.values())
