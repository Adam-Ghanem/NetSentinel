from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SynFloodPolicy(BaseModel):
    """Validated, immutable configuration for bounded SYN-flood detection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    threshold: int = Field(default=100, ge=2, le=1_000_000)
    window_seconds: float = Field(default=10.0, gt=0, le=86_400)
    max_flows: int = Field(default=10_000, ge=1, le=1_000_000)
    max_events_per_flow: int = Field(default=1_000, ge=2, le=1_000_000)

    @model_validator(mode="after")
    def validate_capacity(self) -> SynFloodPolicy:
        if self.max_events_per_flow < self.threshold:
            raise ValueError("max_events_per_flow must be at least threshold")
        return self
