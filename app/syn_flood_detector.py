from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from time import monotonic

from app.contracts import PacketMetadata
from app.event_windows import BoundedEventWindows, WindowSnapshot
from app.syn_flood_policy import SynFloodPolicy


@dataclass(frozen=True, slots=True)
class SynFloodMatch:
    """Sanitized evidence for a bounded SYN-flood decision."""

    source_ip: str
    destination_ip: str
    destination_port: int
    syn_packets: int
    window_seconds: float


class SynFloodDetector:
    """Detect repeated TCP SYN packets against one destination flow."""

    def __init__(
        self,
        *,
        policy: SynFloodPolicy | None = None,
        threshold: int | None = None,
        window_seconds: float | None = None,
        max_flows: int | None = None,
        max_events_per_flow: int | None = None,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if policy is not None and any(
            value is not None
            for value in (
                threshold,
                window_seconds,
                max_flows,
                max_events_per_flow,
            )
        ):
            raise ValueError("policy cannot be combined with individual policy overrides")

        self.policy = policy or SynFloodPolicy(
            threshold=threshold if threshold is not None else 100,
            window_seconds=(window_seconds if window_seconds is not None else 10.0),
            max_flows=max_flows if max_flows is not None else 10_000,
            max_events_per_flow=(
                max_events_per_flow if max_events_per_flow is not None else 1_000
            ),
        )
        self.threshold = self.policy.threshold
        self.window_seconds = self.policy.window_seconds
        self._clock = clock
        self._windows: BoundedEventWindows[tuple[str, str, int], int] = (
            BoundedEventWindows(
                window_seconds=self.policy.window_seconds,
                max_keys=self.policy.max_flows,
                max_events_per_key=self.policy.max_events_per_flow,
                clock=clock,
            )
        )

    def observe(self, packet: PacketMetadata) -> SynFloodMatch | None:
        """Record an eligible SYN and return evidence at threshold crossing."""

        if not self._is_eligible(packet):
            return None

        assert packet.source_ip is not None
        assert packet.dest_ip is not None
        assert packet.dest_port is not None

        key = (packet.source_ip, packet.dest_ip, packet.dest_port)
        now = self._clock()
        count = self._windows.add(key, packet.dest_port, observed_at=now)
        if count != self.threshold:
            return None

        return SynFloodMatch(
            source_ip=packet.source_ip,
            destination_ip=packet.dest_ip,
            destination_port=packet.dest_port,
            syn_packets=count,
            window_seconds=self.window_seconds,
        )

    def snapshot(self) -> WindowSnapshot:
        """Return aggregate bounded-state metrics without flow identifiers."""

        return self._windows.snapshot()

    @staticmethod
    def _is_eligible(packet: PacketMetadata) -> bool:
        if packet.protocol != "TCP":
            return False
        if packet.source_ip is None or packet.dest_ip is None or packet.dest_port is None:
            return False
        flags = packet.tcp_flags or ""
        return "S" in flags and "A" not in flags
