import argparse
import time
from app.database import DatabaseManager
from app.sniffer import PacketSniffer
from app.analyzer import PacketAnalyzer
from app.detection_engine import DetectionEngine
from app.rules_engine import RulesEngine

def main():
    parser = argparse.ArgumentParser(description="NetSentinel network metadata CLI")
    parser.add_argument("--mode", choices=["sniff", "intel"], default="sniff", help="Operational mode")
    parser.add_argument("--iface", help="Network interface to monitor")
    parser.add_argument("--pcap", help="PCAP file to analyze")
    
    args = parser.parse_args()
    
    db = DatabaseManager()
    rules_engine = RulesEngine()
    analyzer = PacketAnalyzer(db)
    detection_engine = DetectionEngine(rules_engine, db)
    sniffer = PacketSniffer(db, analyzer, detection_engine)
    
    print("NETSENTINEL | NETWORK METADATA CLI")
    print("-" * 55)
    
    if args.mode == "intel":
        count = detection_engine.intel.sync_otx()
        print(f"[+] Threat-intel indicators received: {count}")
        return 0
        
    if args.pcap:
        print(f"[*] Analyzing PCAP: {args.pcap}...")
        count = sniffer.process_pcap(args.pcap)
        print(f"[+] Analysis complete. {count} packets processed.")
        
    else:
        print(f"[*] Starting authorized local capture on {args.iface or 'default interface'}...")
        try:
            sniffer.start_sniffing(iface=args.iface)
            while True:
                time.sleep(1)
                alerts = db.get_alerts(limit=5)
                if alerts:
                    for a in alerts:
                        print(f"[{a.severity}] {a.alert_type} from {a.source_ip}")
        except KeyboardInterrupt:
            sniffer.stop_sniffing()
            print("\n[!] Capture stopped.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
