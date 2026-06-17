from scapy.all import sniff, Ether, ARP, IP, TCP, UDP, ICMP, DNS
import datetime
import threading
from app.parser import parse_packet

class PacketSniffer:
    def __init__(self, db_manager, detection_engine=None):
        self.db = db_manager
        self.detection_engine = detection_engine
        self.stop_sniffing_event = threading.Event()
        self.sniff_thread = None

    def _packet_handler(self, packet):
        timestamp = datetime.datetime.now()
        parsed = parse_packet(packet, timestamp.isoformat())
        
        # 1. Save to DB
        self.db.add_packet({
            "timestamp": timestamp,
            "source_mac": parsed.get("source_mac"),
            "dest_mac": parsed.get("dest_mac"),
            "source_ip": parsed.get("source_ip"),
            "dest_ip": parsed.get("dest_ip"),
            "protocol": parsed.get("protocol"),
            "source_port": parsed.get("source_port"),
            "dest_port": parsed.get("dest_port"),
            "packet_size": parsed.get("packet_size"),
            "tcp_flags": parsed.get("tcp_flags"),
            "dns_query": parsed.get("dns_query"),
            "http_host": parsed.get("http_host"),
            "http_path": parsed.get("http_path")
        })

        # 2. Run Detections
        if self.detection_engine:
            # Note: For real stateful detection, we'd pass traffic_stats here
            self.detection_engine.run_detections(parsed, {}, {})

    def start_sniffing(self, iface=None, count=0):
        self.stop_sniffing_event.clear()
        self.sniff_thread = threading.Thread(target=self._sniff_loop, args=(iface, count))
        self.sniff_thread.start()

    def _sniff_loop(self, iface, count):
        try:
            sniff(prn=self._packet_handler, iface=iface, store=0, stop_filter=self._stop_filter, count=count)
        except Exception as e:
            print(f"Error during sniffing: {e}")

    def _stop_filter(self, packet):
        return self.stop_sniffing_event.is_set()

    def stop_sniffing(self):
        self.stop_sniffing_event.set()
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=5)
