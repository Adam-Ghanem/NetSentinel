import argparse
import sys
import asyncio
import time
from app.database import DatabaseManager
from app.sniffer import PacketSniffer
from app.analyzer import PacketAnalyzer
from app.detection_engine import DetectionEngine
from app.rules_engine import RulesEngine

def main():
    parser = argparse.ArgumentParser(description="NetSentinel Elite CLI - Enterprise NDR")
    parser.add_argument("--mode", choices=["sniff", "analyze", "intel"], default="sniff", help="Operational mode")
    parser.add_argument("--iface", help="Network interface to monitor")
    parser.add_argument("--pcap", help="PCAP file to analyze")
    parser.add_argument("--sync", action="store_true", help="Sync Threat Intel feeds")
    
    args = parser.parse_args()
    
    db = DatabaseManager()
    re = RulesEngine()
    analyzer = PacketAnalyzer(db)
    de = DetectionEngine(re, db)
    sniffer = PacketSniffer(db, analyzer, de)
    
    print("🛡️ NETSENTINEL ELITE | ENTERPRISE COMMAND LINE INTERFACE")
    print("-" * 55)
    
    if args.sync:
        de.intel.sync_otx()
        print("[+] Threat Intel Synchronized.")
        
    if args.pcap:
        print(f"[*] Analyzing PCAP: {args.pcap}...")
        count = sniffer.process_pcap(args.pcap)
        print(f"[+] DPI Complete. {count} packets processed.")
        
    elif args.mode == "sniff":
        print(f"[*] Starting Live Intercept on {args.iface or 'default interface'}...")
        try:
            sniffer.start_sniffing(iface=args.iface)
            while True:
                time.sleep(1)
                alerts = db.get_alerts(limit=5)
                if alerts:
                    for a in alerts:
                        print(f"🚨 [{a.severity}] {a.alert_type} from {a.source_ip}")
        except KeyboardInterrupt:
            sniffer.stop_sniffing()
            print("\n[!] Operation Terminated by Operator.")

if __name__ == "__main__":
    main()
