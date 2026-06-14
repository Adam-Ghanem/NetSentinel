import requests
import json
from app.utils import is_private_ip, is_public_ip, get_timestamp
from app.config import Config

class Enrichment:
    def __init__(self, database_manager):
        self.database_manager = database_manager
        self.abuseipdb_api_key = Config.ABUSEIPDB_API_KEY
        self.virustotal_api_key = Config.VIRUSTOTAL_API_KEY

    def enrich_ip_address(self, ip_address):
        enrichment_data = {
            "ip_address": ip_address,
            "is_private": is_private_ip(ip_address),
            "is_public": is_public_ip(ip_address),
            "abuseipdb_data": None,
            "virustotal_data": None
        }

        # Check local cache first
        cached_data = self.database_manager.get_ioc_cache(ip_address, "ip")
        if cached_data:
            enrichment_data.update(json.loads(cached_data["data"]))
            return enrichment_data

        if self.abuseipdb_api_key and enrichment_data["is_public"]:
            abuse_data = self._query_abuseipdb(ip_address)
            if abuse_data:
                enrichment_data["abuseipdb_data"] = abuse_data

        if self.virustotal_api_key and enrichment_data["is_public"]:
            vt_data = self._query_virustotal(ip_address)
            if vt_data:
                enrichment_data["virustotal_data"] = vt_data

        # Cache the results
        self.database_manager.insert_ioc_cache(ip_address, "ip", json.dumps(enrichment_data))
        
        return enrichment_data

    def _query_abuseipdb(self, ip_address):
        if not self.abuseipdb_api_key:
            return None
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90"
        headers = {
            "Accept": "application/json",
            "Key": self.abuseipdb_api_key
        }
        try:
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            return response.json()["data"]
        except requests.exceptions.RequestException as e:
            print(f"Error querying AbuseIPDB for {ip_address}: {e}")
            return None

    def _query_virustotal(self, ip_address):
        if not self.virustotal_api_key:
            return None
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {
            "x-apikey": self.virustotal_api_key
        }
        try:
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            return response.json()["data"]
        except requests.exceptions.RequestException as e:
            print(f"Error querying VirusTotal for {ip_address}: {e}")
            return None

if __name__ == '__main__':
    # Dummy DatabaseManager for testing
    class MockDatabaseManager:
        def __init__(self):
            self.cache = {}

        def get_ioc_cache(self, indicator, type):
            return self.cache.get((indicator, type))

        def insert_ioc_cache(self, indicator, type, data):
            self.cache[(indicator, type)] = {"indicator": indicator, "type": type, "last_checked": get_timestamp(), "data": data}
            print(f"[Mock DB] Cached {indicator}")

    mock_db = MockDatabaseManager()
    enricher = Enrichment(mock_db)

    # Test private IP
    private_ip = "192.168.1.1"
    print(f"\nEnriching private IP: {private_ip}")
    result_private = enricher.enrich_ip_address(private_ip)
    print(json.dumps(result_private, indent=2))

    # Test public IP (without API keys)
    public_ip = "8.8.8.8"
    print(f"\nEnriching public IP: {public_ip}")
    result_public = enricher.enrich_ip_address(public_ip)
    print(json.dumps(result_public, indent=2))

    # Test with cached data
    print(f"\nEnriching public IP again (should use cache): {public_ip}")
    result_public_cached = enricher.enrich_ip_address(public_ip)
    print(json.dumps(result_public_cached, indent=2))

    # To test with actual API keys, set them as environment variables before running:
    # export ABUSEIPDB_API_KEY="YOUR_ABUSEIPDB_KEY"
    # export VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_KEY"
    # Then run this script.
