from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_MAX_ENTRIES = 64
_MIN_IPV4_PREFIX = 28
_MIN_IPV6_PREFIX = 120


class ApprovedScannerEntry(BaseModel):
    """Time-bounded approval for one exact scanner host or small reviewed network."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    expires_at: datetime
    reason: str = Field(min_length=3, max_length=240)
    reference: str = Field(min_length=3, max_length=120)

    @field_validator("network")
    @classmethod
    def validate_network(cls, value: str) -> str:
        network = ip_network(value, strict=True)
        if isinstance(network, IPv4Network) and network.prefixlen < _MIN_IPV4_PREFIX:
            raise ValueError("IPv4 scanner networks must be /28 or narrower")
        if isinstance(network, IPv6Network) and network.prefixlen < _MIN_IPV6_PREFIX:
            raise ValueError("IPv6 scanner networks must be /120 or narrower")
        return str(network)

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        return value.astimezone(timezone.utc)


class ApprovedScannerPolicy(BaseModel):
    """Immutable reviewed scanner allowlist with a strict cardinality limit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entries: tuple[ApprovedScannerEntry, ...] = Field(
        default_factory=tuple,
        max_length=_MAX_ENTRIES,
    )

    @model_validator(mode="after")
    def reject_overlapping_networks(self) -> ApprovedScannerPolicy:
        networks = [ip_network(entry.network) for entry in self.entries]
        for index, network in enumerate(networks):
            if any(network.overlaps(other) for other in networks[index + 1 :]):
                raise ValueError("scanner allowlist networks must not overlap")
        return self


@dataclass(frozen=True, slots=True)
class ScannerAllowlistSnapshot:
    checks: int
    allowed: int
    expired_matches: int
    configured_entries: int


class ApprovedScannerAllowlist:
    """Evaluate approved scanner sources without exposing configured identifiers."""

    def __init__(
        self,
        policy: ApprovedScannerPolicy | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.policy = policy or ApprovedScannerPolicy()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._checks = 0
        self._allowed = 0
        self._expired_matches = 0

    def allows(self, source_ip: str, *, now: datetime | None = None) -> bool:
        self._checks += 1
        address = ip_address(source_ip)
        checked_at = (now or self._clock()).astimezone(timezone.utc)

        for entry in self.policy.entries:
            if address not in ip_network(entry.network):
                continue
            if checked_at >= entry.expires_at:
                self._expired_matches += 1
                return False
            self._allowed += 1
            return True
        return False

    def snapshot(self) -> ScannerAllowlistSnapshot:
        return ScannerAllowlistSnapshot(
            checks=self._checks,
            allowed=self._allowed,
            expired_matches=self._expired_matches,
            configured_entries=len(self.policy.entries),
        )
