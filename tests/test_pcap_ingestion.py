from datetime import timezone
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.pcap_ingestion as ingestion
from app.pcap_ingestion import PcapIngestionError, PcapIngestionPolicy, ingest_pcap_file

PCAP_MAGIC = bytes.fromhex("d4c3b2a1")


class CapturingDatabase:
    def __init__(self):
        self.packets = []

    def add_packet(self, packet_data):
        self.packets.append(packet_data)


class BatchDatabase:
    def __init__(self):
        self.batches = []

    def add_packets(self, packet_batch):
        self.batches.append(list(packet_batch))

    def add_packet(self, _packet_data):
        raise AssertionError("batch-capable databases should not use per-packet writes")


class FailingDatabase:
    def add_packet(self, _packet_data):
        raise ValueError("database write failed")


class FakeReader:
    packets = []

    def __init__(self, _path):
        self._packets = list(type(self).packets)

    def __enter__(self):
        return iter(self._packets)

    def __exit__(self, exc_type, exc, tb):
        return False


class TrackingUpload(BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.read_sizes = []

    def read(self, size=-1):
        self.read_sizes.append(size)
        return super().read(size)


def packet(timestamp=1.0):
    return SimpleNamespace(time=timestamp)


def write_capture_fixture(path):
    path.write_bytes(PCAP_MAGIC + b"fixture")


def test_uploaded_capture_ingestion_api_exists():
    assert callable(getattr(ingestion, "ingest_uploaded_capture", None))


def test_uploaded_capture_is_staged_in_bounded_chunks_and_cleaned(monkeypatch):
    upload = TrackingUpload(PCAP_MAGIC + b"ab")
    staged_paths = []

    def fake_ingest(path, database, *, policy, parser):
        staged_path = Path(path)
        staged_paths.append(staged_path)
        assert staged_path.read_bytes() == PCAP_MAGIC + b"ab"
        return ingestion.PcapIngestionResult(1, 1, 0, False)

    monkeypatch.setattr(ingestion, "ingest_pcap_file", fake_ingest)
    result = ingestion.ingest_uploaded_capture(
        upload,
        CapturingDatabase(),
        policy=PcapIngestionPolicy(max_upload_bytes=10, max_packets=5, max_parse_errors=2),
        chunk_size=2,
    )

    assert result.stored_packets == 1
    assert upload.read_sizes == [2, 2, 2, 2]
    assert staged_paths and not staged_paths[0].exists()


def test_uploaded_capture_rejects_bytes_beyond_limit(monkeypatch):
    upload = TrackingUpload(PCAP_MAGIC + b"ab")
    called = False

    def fake_ingest(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(ingestion, "ingest_pcap_file", fake_ingest)

    with pytest.raises(PcapIngestionError, match="upload limit"):
        ingestion.ingest_uploaded_capture(
            upload,
            CapturingDatabase(),
            policy=PcapIngestionPolicy(max_upload_bytes=5, max_packets=5, max_parse_errors=2),
            chunk_size=2,
        )

    assert called is False


def test_ingestion_rejects_missing_capture(tmp_path):
    missing = tmp_path / "missing.pcap"

    with pytest.raises(PcapIngestionError, match="regular file"):
        ingest_pcap_file(missing, CapturingDatabase())


def test_ingestion_rejects_directory_path(tmp_path):
    with pytest.raises(PcapIngestionError, match="regular file"):
        ingest_pcap_file(tmp_path, CapturingDatabase())


def test_ingestion_rejects_capture_above_upload_limit(tmp_path):
    capture = tmp_path / "large.pcap"
    capture.write_bytes(PCAP_MAGIC + b"x" * 7)

    with pytest.raises(PcapIngestionError, match="upload limit"):
        ingest_pcap_file(
            capture,
            CapturingDatabase(),
            policy=PcapIngestionPolicy(max_upload_bytes=10, max_packets=5, max_parse_errors=2),
        )


def test_packet_budget_counts_every_packet_seen(monkeypatch, tmp_path):
    capture = tmp_path / "capture.pcap"
    write_capture_fixture(capture)
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


def test_capture_packet_timestamps_are_normalized_to_utc(monkeypatch, tmp_path):
    capture = tmp_path / "capture.pcap"
    write_capture_fixture(capture)
    FakeReader.packets = [packet(1.0)]
    monkeypatch.setattr(ingestion, "PcapReader", FakeReader)

    seen_timestamps = []

    def parser(_packet, timestamp):
        seen_timestamps.append(timestamp)
        return {"timestamp": timestamp}

    ingest_pcap_file(capture, CapturingDatabase(), parser=parser)

    assert len(seen_timestamps) == 1
    assert seen_timestamps[0].tzinfo is timezone.utc
    assert seen_timestamps[0].timestamp() == 1.0


def test_missing_capture_timestamp_uses_utc_aware_clock(monkeypatch, tmp_path):
    capture = tmp_path / "capture.pcap"
    write_capture_fixture(capture)
    FakeReader.packets = [SimpleNamespace(time=None)]
    monkeypatch.setattr(ingestion, "PcapReader", FakeReader)

    seen_timestamps = []

    def parser(_packet, timestamp):
        seen_timestamps.append(timestamp)
        return {"timestamp": timestamp}

    ingest_pcap_file(capture, CapturingDatabase(), parser=parser)

    assert len(seen_timestamps) == 1
    assert seen_timestamps[0].tzinfo is timezone.utc


def test_batch_capable_database_receives_bounded_flushes(monkeypatch, tmp_path):
    capture = tmp_path / "capture.pcap"
    write_capture_fixture(capture)
    FakeReader.packets = [packet(index) for index in range(1, 6)]
    monkeypatch.setattr(ingestion, "PcapReader", FakeReader)

    def parser(_packet, timestamp):
        return {"timestamp": timestamp}

    database = BatchDatabase()
    result = ingest_pcap_file(
        capture,
        database,
        policy=PcapIngestionPolicy(
            max_upload_bytes=100,
            max_packets=10,
            max_parse_errors=2,
            batch_size=2,
        ),
        parser=parser,
    )

    assert [len(batch) for batch in database.batches] == [2, 2, 1]
    assert result.stored_packets == 5


def test_database_write_errors_are_not_misclassified_as_parse_errors(monkeypatch, tmp_path):
    capture = tmp_path / "capture.pcap"
    write_capture_fixture(capture)
    FakeReader.packets = [packet(1)]
    monkeypatch.setattr(ingestion, "PcapReader", FakeReader)

    def parser(_packet, timestamp):
        return {"timestamp": timestamp}

    with pytest.raises(ValueError, match="database write failed"):
        ingest_pcap_file(capture, FailingDatabase(), parser=parser)


def test_parse_error_budget_fails_closed(monkeypatch, tmp_path):
    capture = tmp_path / "capture.pcap"
    write_capture_fixture(capture)
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


def test_parse_error_budget_preserves_parser_failure_as_cause(monkeypatch, tmp_path):
    capture = tmp_path / "capture.pcap"
    write_capture_fixture(capture)
    FakeReader.packets = [packet(1), packet(2)]
    monkeypatch.setattr(ingestion, "PcapReader", FakeReader)

    def parser(_packet, _timestamp):
        raise ValueError("malformed")

    with pytest.raises(PcapIngestionError) as exc_info:
        ingest_pcap_file(
            capture,
            CapturingDatabase(),
            policy=PcapIngestionPolicy(max_upload_bytes=100, max_packets=10, max_parse_errors=1),
            parser=parser,
        )

    assert isinstance(exc_info.value.__cause__, ValueError)
    assert str(exc_info.value.__cause__) == "malformed"
