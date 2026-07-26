from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from time import monotonic

from app.contracts import PacketMetadata
from app.event_windows import BoundedEventWindows, WindowSnapshot


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
        threshold: int = 5,
        window_seconds: float = 10.0,
        max_sources: int = 10_000,
        max_events_per_source: int = 1_000,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if threshold < 2:
            raise ValueError("threshold must be at least 2")
        if max_events_per_source < threshold:
            raise ValueError("max_events_per_source must be at least threshold")

        self.threshold = threshold
        self.window_seconds = float(window_seconds)
        self._clock = clock
        self._windows: BoundedEventWindows[tuple[str, str], int] = BoundedEventWindows(
            window_seconds=window_seconds,
            max_keys=max_sources,
            max_events_per_key=max_events_per_source,
            clock=clock,
        )

    def observe(self, packet: PacketMetadata) -> PortScanMatch | None:
        """Record an eligible SYN packet and return a match at threshold crossing."""

        if not self._is_eligible(packet):
            return None

        assert packet.source_ip is not None
        assert packet.dest_ip is not None
        assert packet.dest_port is not None

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

    @staticmethod
    def _is_eligible(packet: PacketMetadata) -> bool:
        if packet.protocol != "TCP":
            return False
        if packet.source_ip is None or packet.dest_ip is None or packet.dest_port is None:
            return False
        flags = packet.tcp_flags or ""
        return "S" in flags and "A" not in flags
