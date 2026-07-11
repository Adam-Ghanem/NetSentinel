import requests
import json
import os

from app.config import Config
from app.utils import get_logger

logger = get_logger(__name__)

class ThreatIntel:
    """Store local indicators and optionally sync subscribed AlienVault OTX pulses."""

    def __init__(self, cache_file="rules/intel_cache.json"):
        self.cache_file = cache_file
        self.iocs = self._load_cache()

    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as handle:
                    cached = json.load(handle)
                return {
                    "ips": list(cached.get("ips", [])),
                    "domains": list(cached.get("domains", [])),
                    "hashes": list(cached.get("hashes", [])),
                }
            except (OSError, ValueError, TypeError) as error:
                logger.warning("Unable to load threat-intel cache: %s", error)
        return {"ips": [], "domains": [], "hashes": []}

    def sync_otx(self, api_key=None):
        """Sync indicators from OTX when an API key is configured."""
        token = api_key or Config.OTX_API_KEY
        if not token:
            logger.warning("OTX sync skipped because OTX_API_KEY is not configured.")
            return 0

        response = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers={"X-OTX-API-KEY": token},
            params={"limit": 50},
            timeout=10,
        )
        response.raise_for_status()

        collected = {"ips": set(), "domains": set(), "hashes": set()}
        for pulse in response.json().get("results", []):
            for indicator in pulse.get("indicators", []):
                value = str(indicator.get("indicator", "")).strip()
                indicator_type = str(indicator.get("type", ""))
                if not value:
                    continue
                if indicator_type in {"IPv4", "IPv6"}:
                    collected["ips"].add(value)
                elif indicator_type in {"domain", "hostname"}:
                    collected["domains"].add(value.lower())
                elif indicator_type.startswith("FileHash-"):
                    collected["hashes"].add(value.lower())

        for category, values in collected.items():
            self.iocs[category] = sorted(set(self.iocs.get(category, [])) | values)
        self._save_cache()
        added_count = sum(len(values) for values in collected.values())
        logger.info("OTX sync complete: %s indicators received.", added_count)
        return added_count

    def _save_cache(self):
        parent = os.path.dirname(self.cache_file)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(self.cache_file, "w", encoding="utf-8") as handle:
            json.dump(self.iocs, handle, indent=2, sort_keys=True)

    def check_ip(self, ip):
        return bool(ip) and ip in self.iocs.get("ips", [])

    def check_domain(self, domain):
        return bool(domain) and domain.lower() in self.iocs.get("domains", [])
