from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, Callable

from scapy.all import PcapReader

from app.parser import parse_packet


@dataclass(frozen=True)
class PcapIngestionPolicy:
    max_upload_bytes: int = 64 * 1024 * 1024
    max_packets: int = 100_000
    max_parse_errors: int = 100

    def __post_init__(self) -> None:
        for field_name in ("max_upload_bytes", "max_packets", "max_parse_errors"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an integer")
            if value <= 0:
                raise ValueError(f"{field_name} must be greater than zero")


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
    policy: PcapIngestionPolicy = PcapIngestionPolicy(),
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


def ingest_pcap_file(
    path: str | Path,
    database: Any,
    *,
    policy: PcapIngestionPolicy = PcapIngestionPolicy(),
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

    processed_packets = 0
    stored_packets = 0
    parse_errors = 0
    truncated = False

    with PcapReader(str(capture_path)) as reader:
        for packet in reader:
            if processed_packets >= policy.max_packets:
                truncated = True
                break

            processed_packets += 1
            packet_time = getattr(packet, "time", None)
            timestamp = (
                datetime.fromtimestamp(float(packet_time))
                if packet_time is not None
                else datetime.utcnow()
            )

            try:
                packet_data = parser(packet, timestamp)
                database.add_packet(packet_data)
            except (TypeError, ValueError):
                parse_errors += 1
                if parse_errors > policy.max_parse_errors:
                    raise PcapIngestionError(
                        "capture exceeded the permitted packet parse-error budget"
                    )
                continue

            stored_packets += 1

    return PcapIngestionResult(
        processed_packets=processed_packets,
        stored_packets=stored_packets,
        parse_errors=parse_errors,
        truncated=truncated,
    )
