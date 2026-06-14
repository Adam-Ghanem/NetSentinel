from scapy.all import sniff, Ether, ARP, IP, TCP, UDP, ICMP, DNS
import datetime
import threading
import time

class PacketSniffer:
    def __init__(self, packet_callback):
        self.packet_callback = packet_callback
        self.stop_sniffing = threading.Event()
        self.sniff_thread = None

    def _packet_handler(self, packet):
        timestamp = datetime.datetime.now().isoformat()
        self.packet_callback(packet, timestamp)

    def start_sniffing(self, iface=None, count=0):
        print(f"Starting sniffing on interface {iface if iface else 'all'}...")
        self.stop_sniffing.clear()
        self.sniff_thread = threading.Thread(target=self._sniff_loop, args=(iface, count))
        self.sniff_thread.start()

    def _sniff_loop(self, iface, count):
        try:
            sniff(prn=self._packet_handler, iface=iface, store=0, stop_filter=self._stop_filter, count=count)
        except Exception as e:
            print(f"Error during sniffing: {e}")

    def _stop_filter(self, packet):
        return self.stop_sniffing.is_set()

    def stop_sniffing(self):
        print("Stopping sniffing...")
        self.stop_sniffing.set()
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=5) # Wait for the thread to finish
            if self.sniff_thread.is_alive():
                print("Sniffing thread did not terminate gracefully.")

if __name__ == '__main__':
    # Example usage:
    def print_packet_info(packet, timestamp):
        if IP in packet:
            print(f"[{timestamp}] IP Packet: {packet[IP].src} -> {packet[IP].dst}")
        elif ARP in packet:
            print(f"[{timestamp}] ARP Packet: {packet[ARP].psrc} -> {packet[ARP].pdst}")
        else:
            print(f"[{timestamp}] Other Packet: {packet.summary()}")

    sniffer = PacketSniffer(print_packet_info)
    sniffer.start_sniffing(count=10) # Sniff 10 packets
    time.sleep(2) # Give it some time to sniff
    sniffer.stop_sniffing()
    print("Sniffing example finished.")
