from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator


class BeaconPolicy(BaseModel):
    """Validated, immutable configuration for bounded beaconing detection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    min_connections: int = Field(default=5, ge=3, le=10_000)
    window_seconds: float = Field(default=600.0, gt=0, le=86_400)
    min_interval_seconds: float = Field(default=10.0, gt=0, le=86_400)
    max_interval_variance: float = Field(default=4.0, ge=0, le=1_000_000)
    max_flows: int = Field(default=10_000, ge=1, le=1_000_000)
    max_events_per_flow: int = Field(default=100, ge=3, le=1_000_000)

    @model_validator(mode="after")
    def validate_capacity(self) -> BeaconPolicy:
        if self.max_events_per_flow < self.min_connections:
            raise ValueError("max_events_per_flow must be at least min_connections")
        return self
