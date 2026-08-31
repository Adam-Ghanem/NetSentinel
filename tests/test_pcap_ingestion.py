from types import SimpleNamespace

import pytest

import app.pcap_ingestion as ingestion
from app.pcap_ingestion import PcapIngestionError, PcapIngestionPolicy, ingest_pcap_file


class CapturingDatabase:
    def __init__(self):
        self.packets = []

    def add_packet(self, packet_data):
        self.packets.append(packet_data)


class FakeReader:
    packets = []

    def __init__(self, _path):
        self._packets = list(type(self).packets)

    def __enter__(self):
        return iter(self._packets)

    def __exit__(self, exc_type, exc, tb):
        return False


def packet(timestamp=1.0):
    return SimpleNamespace(time=timestamp)


def test_ingestion_rejects_missing_capture(tmp_path):
    missing = tmp_path / "missing.pcap"

    with pytest.raises(PcapIngestionError, match="regular file"):
        ingest_pcap_file(missing, CapturingDatabase())


def test_ingestion_rejects_directory_path(tmp_path):
    with pytest.raises(PcapIngestionError, match="regular file"):
        ingest_pcap_file(tmp_path, CapturingDatabase())


def test_ingestion_rejects_capture_above_upload_limit(tmp_path):
    capture = tmp_path / "large.pcap"
    capture.write_bytes(b"x" * 11)

    with pytest.raises(PcapIngestionError, match="upload limit"):
        ingest_pcap_file(
            capture,
            CapturingDatabase(),
            policy=PcapIngestionPolicy(max_upload_bytes=10, max_packets=5, max_parse_errors=2),
        )


def test_packet_budget_counts_every_packet_seen(monkeypatch, tmp_path):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap")
    FakeReader.packets = [packet(1), packet(2), packet(3)]
    monkeypatch.setattr(ingestion, "PcapReader", FakeReader)

    calls = 0

    def parser(_packet, timestamp):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ValueError("malformed")
        return {"timestamp": timestamp}

    database = CapturingDatabase()
    result = ingest_pcap_file(
        capture,
        database,
        policy=PcapIngestionPolicy(max_upload_bytes=100, max_packets=2, max_parse_errors=2),
        parser=parser,
    )

    assert calls == 2
    assert len(database.packets) == 1
    assert result.processed_packets == 2
    assert result.stored_packets == 1
    assert result.parse_errors == 1
    assert result.truncated is True


def test_parse_error_budget_fails_closed(monkeypatch, tmp_path):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap")
    FakeReader.packets = [packet(1), packet(2)]
    monkeypatch.setattr(ingestion, "PcapReader", FakeReader)

    def parser(_packet, _timestamp):
        raise ValueError("malformed")

    with pytest.raises(PcapIngestionError, match="parse-error budget"):
        ingest_pcap_file(
            capture,
            CapturingDatabase(),
            policy=PcapIngestionPolicy(max_upload_bytes=100, max_packets=10, max_parse_errors=1),
            parser=parser,
        )
