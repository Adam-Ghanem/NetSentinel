from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

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
