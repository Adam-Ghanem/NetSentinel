from types import SimpleNamespace

from app.enrichment import Enrichment


class FakeDatabase:
    def __init__(self):
        self.cached = None
        self.inserted = []

    def get_ioc_cache(self, indicator):
        return self.cached

    def insert_ioc_cache(self, record):
        self.inserted.append(record)


def config(**overrides):
    values = {
        "ABUSEIPDB_API_KEY": None,
        "VIRUSTOTAL_API_KEY": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_private_ip_enrichment_records_local_provenance_without_external_queries():
    database = FakeDatabase()
    result = Enrichment(database, config()).enrich_ip_address("192.0.2.10")

    assert result["is_private"] is True
    assert result["threat_intel"] == {}
    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["provider"] == "netsentinel"
    assert result["evidence"][0]["source"] == "ip_classification"
    assert result["evidence"][0]["status"] == "success"
    assert database.inserted[0]["indicator"] == "192.0.2.10"


def test_cached_enrichment_preserves_existing_payload_shape():
    database = FakeDatabase()
    database.cached = SimpleNamespace(
        data='{"indicator":"198.51.100.20","type":"IP","threat_intel":{}}'
    )

    result = Enrichment(database, config()).enrich_ip_address("198.51.100.20")

    assert result["indicator"] == "198.51.100.20"
    assert "evidence" not in result
    assert database.inserted == []
