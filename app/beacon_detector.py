from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from statistics import fmean, pvariance
from time import monotonic

from app.beacon_policy import BeaconPolicy
from app.contracts import PacketMetadata
from app.event_windows import BoundedEventWindows, WindowSnapshot


@dataclass(frozen=True, slots=True)
class BeaconMatch:
    """Sanitized evidence for a periodic TCP connection pattern."""

    source_ip: str
    destination_ip: str
    destination_port: int
    connections: int
    mean_interval_seconds: float
    interval_variance: float
    window_seconds: float


class BeaconDetector:
    """Detect regular TCP SYN connection intervals with bounded flow state."""

    def __init__(
        self,
        *,
        policy: BeaconPolicy | None = None,
        min_connections: int | None = None,
        window_seconds: float | None = None,
        min_interval_seconds: float | None = None,
        max_interval_variance: float | None = None,
        max_flows: int | None = None,
        max_events_per_flow: int | None = None,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if policy is not None and any(
            value is not None
            for value in (
                min_connections,
                window_seconds,
                min_interval_seconds,
                max_interval_variance,
                max_flows,
                max_events_per_flow,
            )
        ):
            raise ValueError("policy cannot be combined with individual policy overrides")

        self.policy = policy or BeaconPolicy(
            min_connections=min_connections if min_connections is not None else 5,
            window_seconds=(window_seconds if window_seconds is not None else 600.0),
            min_interval_seconds=(
                min_interval_seconds if min_interval_seconds is not None else 10.0
            ),
            max_interval_variance=(
                max_interval_variance if max_interval_variance is not None else 4.0
            ),
            max_flows=max_flows if max_flows is not None else 10_000,
            max_events_per_flow=(
                max_events_per_flow if max_events_per_flow is not None else 100
            ),
        )
        self.min_connections = self.policy.min_connections
        self.window_seconds = self.policy.window_seconds
        self._clock = clock
        self._windows: BoundedEventWindows[tuple[str, str, int], float] = (
            BoundedEventWindows(
                window_seconds=self.policy.window_seconds,
                max_keys=self.policy.max_flows,
                max_events_per_key=self.policy.max_events_per_flow,
                clock=clock,
            )
        )

    def observe(self, packet: PacketMetadata) -> BeaconMatch | None:
        """Record an eligible SYN and return evidence for regular intervals."""

        if not self._is_eligible(packet):
            return None

        assert packet.source_ip is not None
        assert packet.dest_ip is not None
        assert packet.dest_port is not None

        key = (packet.source_ip, packet.dest_ip, packet.dest_port)
        now = self._clock()
        self._windows.add(key, now, observed_at=now)
        observations = self._windows.values(key, now=now)
        if len(observations) < self.min_connections:
            return None

        recent = observations[-self.min_connections :]
        intervals = tuple(
            current - previous
            for previous, current in zip(recent, recent[1:], strict=True)
        )
        if not intervals or min(intervals) < self.policy.min_interval_seconds:
            return None

        interval_variance = pvariance(intervals)
        if interval_variance > self.policy.max_interval_variance:
            return None

        return BeaconMatch(
            source_ip=packet.source_ip,
            destination_ip=packet.dest_ip,
            destination_port=packet.dest_port,
            connections=len(recent),
            mean_interval_seconds=fmean(intervals),
            interval_variance=interval_variance,
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
