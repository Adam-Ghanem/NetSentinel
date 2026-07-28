from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from time import monotonic

from app.contracts import PacketMetadata
from app.event_windows import BoundedEventWindows, WindowSnapshot
from app.port_scan_policy import PortScanPolicy
from app.scanner_allowlist import ApprovedScannerAllowlist, ScannerAllowlistSnapshot


@dataclass(frozen=True, slots=True)
class PortScanMatch:
    """Sanitized evidence for a unique-destination-port scan decision."""

    source_ip: str
    destination_ip: str
    unique_ports: int
    window_seconds: float


class UniquePortScanDetector:
    """Detect TCP SYN scans with bounded, per-source sliding windows."""

    def __init__(
        self,
        *,
        policy: PortScanPolicy | None = None,
        scanner_allowlist: ApprovedScannerAllowlist | None = None,
        threshold: int | None = None,
        window_seconds: float | None = None,
        max_sources: int | None = None,
        max_events_per_source: int | None = None,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if policy is not None and any(
            value is not None
            for value in (
                threshold,
                window_seconds,
                max_sources,
                max_events_per_source,
            )
        ):
            raise ValueError("policy cannot be combined with individual policy overrides")

        self.policy = policy or PortScanPolicy(
            threshold=threshold if threshold is not None else 5,
            window_seconds=(window_seconds if window_seconds is not None else 10.0),
            max_sources=max_sources if max_sources is not None else 10_000,
            max_events_per_source=(
                max_events_per_source if max_events_per_source is not None else 1_000
            ),
        )
        self.threshold = self.policy.threshold
        self.window_seconds = self.policy.window_seconds
        self._scanner_allowlist = scanner_allowlist or ApprovedScannerAllowlist()
        self._clock = clock
        self._windows: BoundedEventWindows[tuple[str, str], int] = BoundedEventWindows(
            window_seconds=self.policy.window_seconds,
            max_keys=self.policy.max_sources,
            max_events_per_key=self.policy.max_events_per_source,
            clock=clock,
        )

    def observe(self, packet: PacketMetadata) -> PortScanMatch | None:
        """Record an eligible SYN packet and return a match at threshold crossing."""

        if not self._is_eligible(packet):
            return None

        assert packet.source_ip is not None
        assert packet.dest_ip is not None
        assert packet.dest_port is not None

        if self._scanner_allowlist.allows(packet.source_ip):
            return None

        key = (packet.source_ip, packet.dest_ip)
        now = self._clock()
        self._windows.add(key, packet.dest_port, observed_at=now)
        unique_ports = len(set(self._windows.values(key, now=now)))

        if unique_ports != self.threshold:
            return None

        return PortScanMatch(
            source_ip=packet.source_ip,
            destination_ip=packet.dest_ip,
            unique_ports=unique_ports,
            window_seconds=self.window_seconds,
        )

    def snapshot(self) -> WindowSnapshot:
        """Return aggregate bounded-state metrics without source identifiers."""
        return self._windows.snapshot()

    def allowlist_snapshot(self) -> ScannerAllowlistSnapshot:
        """Return aggregate scanner-approval decisions without configured networks."""
        return self._scanner_allowlist.snapshot()

    @staticmethod
    def _is_eligible(packet: PacketMetadata) -> bool:
        if packet.protocol != "TCP":
            return False
        if packet.source_ip is None or packet.dest_ip is None or packet.dest_port is None:
            return False
        flags = packet.tcp_flags or ""
        return "S" in flags and "A" not in flags
