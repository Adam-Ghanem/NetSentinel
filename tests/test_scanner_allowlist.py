from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.scanner_allowlist import (
    ApprovedScannerAllowlist,
    ApprovedScannerEntry,
    ApprovedScannerPolicy,
)

NOW = datetime(2026, 7, 28, 8, 0, tzinfo=timezone.utc)


def _entry(network: str = "192.0.2.10/32", *, expires_in: int = 3600) -> ApprovedScannerEntry:
    return ApprovedScannerEntry(
        network=network,
        expires_at=NOW + timedelta(seconds=expires_in),
        reason="Approved vulnerability scan",
        reference="CHG-2026-0042",
    )


def test_exact_approved_scanner_is_allowed_before_expiry():
    allowlist = ApprovedScannerAllowlist(
        ApprovedScannerPolicy(entries=(_entry(),)),
        clock=lambda: NOW,
    )

    assert allowlist.allows("192.0.2.10") is True
    assert allowlist.allows("192.0.2.11") is False
    assert allowlist.snapshot().allowed == 1


def test_expired_approval_fails_closed_and_is_counted():
    allowlist = ApprovedScannerAllowlist(
        ApprovedScannerPolicy(entries=(_entry(expires_in=-1),)),
        clock=lambda: NOW,
    )

    assert allowlist.allows("192.0.2.10") is False
    snapshot = allowlist.snapshot()
    assert snapshot.expired_matches == 1
    assert snapshot.allowed == 0


@pytest.mark.parametrize("network", ["0.0.0.0/0", "10.0.0.0/8", "192.0.2.0/24"])
def test_policy_rejects_broad_ipv4_networks(network: str):
    with pytest.raises(ValidationError, match="/28 or narrower"):
        _entry(network)


@pytest.mark.parametrize("network", ["::/0", "2001:db8::/64", "2001:db8::/119"])
def test_policy_rejects_broad_ipv6_networks(network: str):
    with pytest.raises(ValidationError, match="/120 or narrower"):
        _entry(network)


def test_entry_requires_timezone_aware_expiry():
    with pytest.raises(ValidationError, match="timezone-aware"):
        ApprovedScannerEntry(
            network="192.0.2.10/32",
            expires_at=datetime(2026, 7, 28, 9, 0),
            reason="Approved vulnerability scan",
            reference="CHG-2026-0042",
        )


def test_policy_rejects_overlapping_networks():
    with pytest.raises(ValidationError, match="must not overlap"):
        ApprovedScannerPolicy(
            entries=(
                _entry("192.0.2.0/28"),
                _entry("192.0.2.10/32"),
            )
        )


def test_policy_rejects_more_than_sixty_four_entries():
    entries = tuple(
        _entry(f"192.0.2.{index}/32")
        for index in range(65)
    )

    with pytest.raises(ValidationError):
        ApprovedScannerPolicy(entries=entries)


def test_snapshot_contains_only_aggregate_counters():
    allowlist = ApprovedScannerAllowlist(
        ApprovedScannerPolicy(entries=(_entry(),)),
        clock=lambda: NOW,
    )
    allowlist.allows("192.0.2.10")

    snapshot = allowlist.snapshot()
    assert snapshot.configured_entries == 1
    assert not hasattr(snapshot, "networks")
    assert not hasattr(snapshot, "source_ip")
