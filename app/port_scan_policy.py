from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator


class PortScanPolicy(BaseModel):
    """Validated, immutable configuration for bounded port-scan detection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    threshold: int = Field(default=5, ge=2, le=65_536)
    window_seconds: float = Field(default=10.0, gt=0, le=86_400)
    max_sources: int = Field(default=10_000, ge=1, le=1_000_000)
    max_events_per_source: int = Field(default=1_000, ge=2, le=1_000_000)

    @model_validator(mode="after")
    def validate_capacity(self) -> PortScanPolicy:
        if self.max_events_per_source < self.threshold:
            raise ValueError("max_events_per_source must be at least threshold")
        return self
