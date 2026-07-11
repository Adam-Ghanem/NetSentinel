from scapy.all import sniff, rdpcap
import datetime
import threading
import os
from app.parser import parse_packet
from app.utils import get_logger

logger = get_logger(__name__)

class PacketSniffer:
    def __init__(self, db_manager, analyzer, detection_engine):
        self.db = db_manager
        self.analyzer = analyzer
        self.detection_engine = detection_engine
        self.stop_sniffing_event = threading.Event()
        self.sniff_thread = None

    def _packet_handler(self, packet):
        try:
            timestamp = datetime.datetime.now()
            parsed = parse_packet(packet, timestamp.isoformat())
            
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
                "arp_op": parsed.get("arp_op"),
                "dns_query": parsed.get("dns_query"),
                "http_host": parsed.get("http_host"),
                "http_path": parsed.get("http_path"),
                "payload_raw": parsed.get("payload_raw"),
                "payload_printable": parsed.get("payload_printable"),
                "tls_version": parsed.get("tls_version"),
                "ja3_hash": parsed.get("ja3_hash"),
            })

            self.analyzer.analyze_packet(parsed)
            src_ip = parsed.get("source_ip")
            stats = self.analyzer.get_traffic_stats(src_ip) if src_ip else {}
            self.detection_engine.run_detections(parsed, self.analyzer.connections, {src_ip: stats} if src_ip else {})

        except Exception as e:
            logger.error(f"Error in packet handler: {e}")

    def start_sniffing(self, iface=None, count=0):
        if self.sniff_thread and self.sniff_thread.is_alive():
            return
        self.stop_sniffing_event.clear()
        self.sniff_thread = threading.Thread(target=self._sniff_loop, args=(iface, count))
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def _sniff_loop(self, iface, count):
        try:
            sniff(prn=self._packet_handler, iface=iface, store=0, stop_filter=self._stop_filter, count=count)
        except Exception as e:
            logger.error(f"Error during sniffing: {e}")

    def _stop_filter(self, packet):
        return self.stop_sniffing_event.is_set()

    def stop_sniffing(self):
        self.stop_sniffing_event.set()
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=2)

    def process_pcap(self, pcap_path):
        if not os.path.exists(pcap_path):
            return 0
        try:
            packets = rdpcap(pcap_path)
            for packet in packets:
                self._packet_handler(packet)
            return len(packets)
        except Exception as e:
            logger.error(f"Error processing PCAP: {e}")
            return 0
