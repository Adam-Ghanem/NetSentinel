from __future__ import annotations

import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from scapy.all import PcapReader

from app.parser import parse_packet

_CAPTURE_MAGIC = {
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b23c4d"),
    bytes.fromhex("4d3cb2a1"),
    bytes.fromhex("0a0d0d0a"),
}


@dataclass(frozen=True)
class PcapIngestionPolicy:
    max_upload_bytes: int = 64 * 1024 * 1024
    max_packets: int = 100_000
    max_parse_errors: int = 100
    batch_size: int = 500

    def __post_init__(self) -> None:
        for field_name in (
            "max_upload_bytes",
            "max_packets",
            "max_parse_errors",
            "batch_size",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an integer")
            if value <= 0:
                raise ValueError(f"{field_name} must be greater than zero")


DEFAULT_PCAP_INGESTION_POLICY = PcapIngestionPolicy()


@dataclass(frozen=True)
class PcapIngestionResult:
    processed_packets: int
    stored_packets: int
    parse_errors: int
    truncated: bool


class PcapIngestionError(ValueError):
    """Raised when a capture violates a reviewed ingestion boundary."""


def ingest_uploaded_capture(
    upload: BinaryIO,
    database: Any,
    *,
    policy: PcapIngestionPolicy = DEFAULT_PCAP_INGESTION_POLICY,
    parser: Callable[[Any, datetime], dict[str, Any]] = parse_packet,
    chunk_size: int = 1024 * 1024,
) -> PcapIngestionResult:
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise TypeError("chunk_size must be an integer")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    temp_path: str | None = None
    bytes_written = 0

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as temp_file:
            temp_path = temp_file.name
            while True:
                chunk = upload.read(chunk_size)
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > policy.max_upload_bytes:
                    raise PcapIngestionError(
                        f"capture exceeds the {policy.max_upload_bytes}-byte upload limit"
                    )
                temp_file.write(chunk)

        return ingest_pcap_file(
            temp_path,
            database,
            policy=policy,
            parser=parser,
        )
    finally:
        if temp_path is not None:
            try:
                os.remove(temp_path)
            except FileNotFoundError:
                pass


def _validate_capture_format(capture_path: Path) -> None:
    with capture_path.open("rb") as capture_file:
        magic = capture_file.read(4)
    if magic not in _CAPTURE_MAGIC:
        raise PcapIngestionError("unsupported or truncated capture format")


def _persist_packet_batch(database: Any, packet_batch: list[dict[str, Any]]) -> int:
    if not packet_batch:
        return 0

    add_packets = getattr(database, "add_packets", None)
    if callable(add_packets):
        add_packets(packet_batch)
        return len(packet_batch)

    for packet_data in packet_batch:
        database.add_packet(packet_data)
    return len(packet_batch)


def ingest_pcap_file(
    path: str | Path,
    database: Any,
    *,
    policy: PcapIngestionPolicy = DEFAULT_PCAP_INGESTION_POLICY,
    parser: Callable[[Any, datetime], dict[str, Any]] = parse_packet,
) -> PcapIngestionResult:
    capture_path = Path(path)
    if not capture_path.is_file():
        raise PcapIngestionError("capture path must reference a regular file")

    size = capture_path.stat().st_size
    if size > policy.max_upload_bytes:
        raise PcapIngestionError(
            f"capture exceeds the {policy.max_upload_bytes}-byte upload limit"
        )
    _validate_capture_format(capture_path)

    processed_packets = 0
    stored_packets = 0
    parse_errors = 0
    truncated = False
    packet_batch: list[dict[str, Any]] = []

    with PcapReader(str(capture_path)) as reader:
        for packet in reader:
            if processed_packets >= policy.max_packets:
                truncated = True
                break

            processed_packets += 1
            try:
                packet_time = getattr(packet, "time", None)
                timestamp = (
                    datetime.fromtimestamp(float(packet_time), tz=timezone.utc)
                    if packet_time is not None
                    else datetime.now(timezone.utc)
                )
            except (TypeError, ValueError, OverflowError, OSError) as error:
                parse_errors += 1
                if parse_errors > policy.max_parse_errors:
                    raise PcapIngestionError(
                        "capture exceeded the permitted packet parse-error budget"
                    ) from error
                continue

            try:
                packet_data = parser(packet, timestamp)
            except (TypeError, ValueError) as error:
                parse_errors += 1
                if parse_errors > policy.max_parse_errors:
                    raise PcapIngestionError(
                        "capture exceeded the permitted packet parse-error budget"
                    ) from error
                continue

            packet_batch.append(packet_data)
            if len(packet_batch) >= policy.batch_size:
                stored_packets += _persist_packet_batch(database, packet_batch)
                packet_batch = []

    stored_packets += _persist_packet_batch(database, packet_batch)

    return PcapIngestionResult(
        processed_packets=processed_packets,
        stored_packets=stored_packets,
        parse_errors=parse_errors,
        truncated=truncated,
    )
