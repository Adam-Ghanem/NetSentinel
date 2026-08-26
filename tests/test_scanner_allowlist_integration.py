from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.contracts import PacketMetadata
from app.port_scan_detector import UniquePortScanDetector
from app.scanner_allowlist import (
    ApprovedScannerAllowlist,
    ApprovedScannerEntry,
    ApprovedScannerPolicy,
)

NOW = datetime(2026, 7, 28, 8, 0, tzinfo=timezone.utc)


def packet(port: int, *, source: str = "192.0.2.10") -> PacketMetadata:
    return PacketMetadata(
        timestamp=NOW,
        source_ip=source,
        dest_ip="198.51.100.20",
        protocol="TCP",
        source_port=40000,
        dest_port=port,
        packet_size=60,
        tcp_flags="S",
    )


def allowlist(*, expires_in: int = 3600) -> ApprovedScannerAllowlist:
    policy = ApprovedScannerPolicy(
        entries=(
            ApprovedScannerEntry(
                network="192.0.2.10/32",
                expires_at=NOW + timedelta(seconds=expires_in),
                reason="Approved vulnerability scan",
                reference="CHG-2026-0042",
            ),
        )
    )
    return ApprovedScannerAllowlist(policy, clock=lambda: NOW)


def test_approved_scanner_bypasses_detection_and_state_tracking():
    scanner_allowlist = allowlist()
    detector = UniquePortScanDetector(
        threshold=2,
        scanner_allowlist=scanner_allowlist,
    )

    assert detector.observe(packet(22)) is None
    assert detector.observe(packet(443)) is None
    assert detector.snapshot().tracked_events == 0
    assert detector.allowlist_snapshot().allowed == 2


def test_expired_approval_fails_closed_and_detection_remains_active():
    scanner_allowlist = allowlist(expires_in=-1)
    detector = UniquePortScanDetector(
        threshold=2,
        scanner_allowlist=scanner_allowlist,
    )

    assert detector.observe(packet(22)) is None
    match = detector.observe(packet(443))

    assert match is not None
    assert detector.snapshot().tracked_events == 2
    assert detector.allowlist_snapshot().expired_matches == 2


def test_non_allowlisted_source_is_detected_normally():
    detector = UniquePortScanDetector(
        threshold=2,
        scanner_allowlist=allowlist(),
    )

    assert detector.observe(packet(22, source="203.0.113.9")) is None
    assert detector.observe(packet(443, source="203.0.113.9")) is not None
    assert detector.allowlist_snapshot().allowed == 0
