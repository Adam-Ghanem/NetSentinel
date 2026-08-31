from pathlib import Path

import pytest

from app.pcap_ingestion import PcapIngestionPolicy


def test_pcap_ingestion_service_uses_streaming_reader():
    source = Path("app/pcap_ingestion.py").read_text(encoding="utf-8")

    assert "PcapReader" in source
    assert "rdpcap" not in source


@pytest.mark.parametrize(
    "field_name",
    ["max_upload_bytes", "max_packets", "max_parse_errors", "batch_size"],
)
def test_pcap_ingestion_policy_rejects_non_positive_bounds(field_name):
    values = {
        "max_upload_bytes": 1024,
        "max_packets": 100,
        "max_parse_errors": 5,
        "batch_size": 10,
    }
    values[field_name] = 0

    with pytest.raises(ValueError, match="greater than zero"):
        PcapIngestionPolicy(**values)


@pytest.mark.parametrize(
    "field_name",
    ["max_upload_bytes", "max_packets", "max_parse_errors", "batch_size"],
)
def test_pcap_ingestion_policy_rejects_boolean_bounds(field_name):
    values = {
        "max_upload_bytes": 1024,
        "max_packets": 100,
        "max_parse_errors": 5,
        "batch_size": 10,
    }
    values[field_name] = True

    with pytest.raises(TypeError, match="must be an integer"):
        PcapIngestionPolicy(**values)


def test_batch_size_may_exceed_smaller_packet_budget():
    policy = PcapIngestionPolicy(
        max_upload_bytes=1024,
        max_packets=10,
        max_parse_errors=5,
    )

    assert policy.max_packets == 10
    assert policy.batch_size == 500
