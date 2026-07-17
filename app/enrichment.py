import json

import requests

from app.config import Config, Settings
from app.utils import get_timestamp, is_private_ip, is_public_ip


class Enrichment:
    def __init__(self, database_manager, config: Settings = Config):
        self.db = database_manager
        self.config = config

    def enrich_ip_address(self, ip_address):
        cached = self.db.get_ioc_cache(ip_address)
        if cached:
            return json.loads(cached.data)

        enrichment_data = {
            "indicator": ip_address,
            "type": "IP",
            "is_private": is_private_ip(ip_address),
            "is_public": is_public_ip(ip_address),
            "threat_intel": {},
            "checked_at": get_timestamp(),
        }

        if enrichment_data["is_public"]:
            if self.config.ABUSEIPDB_API_KEY:
                intel = self._query_abuseipdb(ip_address)
                if intel:
                    enrichment_data["threat_intel"]["abuseipdb"] = intel

            if self.config.VIRUSTOTAL_API_KEY:
                intel = self._query_virustotal(ip_address)
                if intel:
                    enrichment_data["threat_intel"]["virustotal"] = intel

        self.db.insert_ioc_cache(
            {
                "indicator": ip_address,
                "type": "IP",
                "data": json.dumps(enrichment_data),
            }
        )

        return enrichment_data

    def _query_abuseipdb(self, ip_address):
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
        headers = {"Accept": "application/json", "Key": self.config.ABUSEIPDB_API_KEY}
        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                return response.json().get("data")
        except requests.RequestException:
            return None
        return None

    def _query_virustotal(self, ip_address):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": self.config.VIRUSTOTAL_API_KEY}
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                return response.json().get("data")
        except requests.RequestException:
            return None
        return None
