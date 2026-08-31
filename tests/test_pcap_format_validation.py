import pytest

import app.pcap_ingestion as ingestion
from app.pcap_ingestion import PcapIngestionError, ingest_pcap_file


class EmptyReader:
    def __init__(self, _path):
        pass

    def __enter__(self):
        return iter(())

    def __exit__(self, exc_type, exc, tb):
        return False


class NoopDatabase:
    def add_packet(self, _packet_data):
        raise AssertionError("empty capture fixture should not persist packets")


@pytest.mark.parametrize(
    "magic",
    [
        bytes.fromhex("a1b2c3d4"),
        bytes.fromhex("d4c3b2a1"),
        bytes.fromhex("a1b23c4d"),
        bytes.fromhex("4d3cb2a1"),
        bytes.fromhex("0a0d0d0a"),
    ],
)
def test_ingestion_accepts_known_capture_magic(monkeypatch, tmp_path, magic):
    capture = tmp_path / "capture.bin"
    capture.write_bytes(magic + b"fixture")
    monkeypatch.setattr(ingestion, "PcapReader", EmptyReader)

    result = ingest_pcap_file(capture, NoopDatabase())

    assert result.processed_packets == 0
    assert result.stored_packets == 0


def test_ingestion_rejects_unknown_capture_magic(monkeypatch, tmp_path):
    capture = tmp_path / "not-a-capture.pcap"
    capture.write_bytes(b"NOPE" + b"fixture")
    reader_called = False

    class TrackingReader:
        def __init__(self, _path):
            nonlocal reader_called
            reader_called = True

    monkeypatch.setattr(ingestion, "PcapReader", TrackingReader)

    with pytest.raises(PcapIngestionError, match="capture format"):
        ingest_pcap_file(capture, NoopDatabase())

    assert reader_called is False


def test_ingestion_rejects_truncated_capture_header(tmp_path):
    capture = tmp_path / "short.pcap"
    capture.write_bytes(b"\xd4\xc3")

    with pytest.raises(PcapIngestionError, match="capture format"):
        ingest_pcap_file(capture, NoopDatabase())
