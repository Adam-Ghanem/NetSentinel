import requests
import json
import os
from app.utils import get_logger

logger = get_logger(__name__)

class ThreatIntel:
    """
    Elite Threat Intelligence Module.
    Syncs Indicators of Compromise (IOCs) from external sources.
    """
    def __init__(self, cache_file="rules/intel_cache.json"):
        self.cache_file = cache_file
        self.iocs = self._load_cache()

    def _load_cache(self):
        if os.path.exists(self.cache_file):
            with open(self.cache_file, "r") as f:
                return json.load(f)
        return {"ips": [], "domains": [], "hashes": []}

    def sync_otx(self, api_key=None):
        """
        Simulates syncing with AlienVault OTX or similar professional intel feeds.
        """
        logger.info("Syncing with Threat Intel feeds...")
        # In a real 5-year exp project, we'd use the OTXv2 SDK
        # For demo purposes, we populate with some known malicious patterns
        new_iocs = {
            "ips": ["185.220.101.1", "103.212.69.114", "45.146.164.110"],
            "domains": ["malware-c2.com", "phishing-login.net", "update-service.xyz"],
            "hashes": ["5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"]
        }
        self.iocs.update(new_iocs)
        self._save_cache()
        logger.info(f"Threat Intel sync complete. {len(self.iocs['ips'])} IPs tracked.")

    def _save_cache(self):
        with open(self.cache_file, "w") as f:
            json.dump(self.iocs, f)

    def check_ip(self, ip):
        return ip in self.iocs.get("ips", [])

    def check_domain(self, domain):
        return domain in self.iocs.get("domains", [])
