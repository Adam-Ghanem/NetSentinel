from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from app.alert_suppression import AlertSuppressor, SuppressionMetrics


@dataclass(frozen=True, slots=True)
class DetectionMetricsSnapshot:
    """Sanitized, read-only detection metrics for operational consumers."""

    generated_at: datetime
    suppression: SuppressionMetrics

    @property
    def total_decisions(self) -> int:
        return self.suppression.emitted + self.suppression.suppressed

    @property
    def suppression_ratio(self) -> float:
        if self.total_decisions == 0:
            return 0.0
        return self.suppression.suppressed / self.total_decisions

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation without sensitive alert keys."""

        return {
            "generated_at": self.generated_at.isoformat(),
            "suppression": asdict(self.suppression),
            "derived": {
                "total_decisions": self.total_decisions,
                "suppression_ratio": self.suppression_ratio,
            },
        }


class DetectionObservability:
    """Expose immutable detection metrics without granting state mutation access."""

    def __init__(
        self,
        alert_suppressor: AlertSuppressor,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._alert_suppressor = alert_suppressor
        self._now = now or (lambda: datetime.now(timezone.utc))

    def snapshot(self) -> DetectionMetricsSnapshot:
        """Capture a point-in-time metrics view from the detection process."""

        generated_at = self._now()
        if generated_at.tzinfo is None or generated_at.utcoffset() is None:
            raise ValueError("observability timestamps must be timezone-aware")

        return DetectionMetricsSnapshot(
            generated_at=generated_at,
            suppression=self._alert_suppressor.metrics(),
        )
