from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.contracts import EnrichmentEvidence

TIMESTAMP = datetime(2026, 8, 8, 7, 0, tzinfo=timezone.utc)


def test_enrichment_evidence_normalizes_labels_and_preserves_confidence():
    evidence = EnrichmentEvidence(
        provider=" AbuseIPDB ",
        source=" Public IP reputation ",
        queried_at=TIMESTAMP,
        status=" SUCCESS ",
        confidence=0.85,
        reference="https://example.invalid/report/203.0.113.10",
    )

    assert evidence.provider == "abuseipdb"
    assert evidence.source == "public ip reputation"
    assert evidence.status == "success"
    assert evidence.confidence == 0.85


def test_enrichment_evidence_requires_timezone_aware_timestamp():
    with pytest.raises(ValidationError, match="timezone-aware"):
        EnrichmentEvidence(
            provider="virustotal",
            source="ip reputation",
            queried_at=datetime(2026, 8, 8, 7, 0),
            status="success",
        )


def test_enrichment_evidence_rejects_invalid_confidence():
    for value in (-0.01, 1.01):
        with pytest.raises(ValidationError):
            EnrichmentEvidence(
                provider="virustotal",
                source="ip reputation",
                queried_at=TIMESTAMP,
                status="success",
                confidence=value,
            )


def test_enrichment_evidence_rejects_empty_labels_and_unknown_fields():
    with pytest.raises(ValidationError):
        EnrichmentEvidence(
            provider="   ",
            source="ip reputation",
            queried_at=TIMESTAMP,
            status="success",
        )

    with pytest.raises(ValidationError):
        EnrichmentEvidence(
            provider="virustotal",
            source="ip reputation",
            queried_at=TIMESTAMP,
            status="success",
            unexpected="value",
        )
