from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_MITRE_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class Severity(str, Enum):
    """Supported alert severity levels in ascending operational priority."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class PacketMetadata(BaseModel):
    """Validated metadata boundary shared by parsing and detection components."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    timestamp: datetime
    source_mac: str | None = None
    dest_mac: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    protocol: str = "UNKNOWN"
    source_port: int | None = Field(default=None, ge=0, le=65535)
    dest_port: int | None = Field(default=None, ge=0, le=65535)
    packet_size: int = Field(ge=0)
    tcp_flags: str | None = None
    arp_op: str | None = None
    dns_query: str | None = None
    http_host: str | None = None
    http_path: str | None = None
    payload_raw: str | None = None
    payload_printable: str | None = None
    tls_version: str | None = None
    ja3_hash: str | None = None

    @field_validator("source_ip", "dest_ip")
    @classmethod
    def validate_ip_address(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return str(ipaddress.ip_address(value))

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not normalized:
            raise ValueError("protocol must not be empty")
        return normalized


class DetectionRule(BaseModel):
    """Validated representation of one YAML detection rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=2000)
    severity: Severity
    recommended_action: str | None = Field(default=None, max_length=2000)
    mitre_attack: str | None = None

    protocol: str | None = None
    dest_port: int | None = Field(default=None, ge=0, le=65535)
    source_ip: str | None = None
    tcp_flags: str | None = None
    arp_op: str | None = None
    payload_pattern: str | None = None
    dns_query_pattern: str | None = None
    unusual_ports: tuple[int, ...] | None = None
    is_external_ip: bool = False

    min_unique_ports: int | None = Field(default=None, ge=1)
    min_syn_packets: int | None = Field(default=None, ge=1)
    min_dns_queries: int | None = Field(default=None, ge=1)
    min_bytes_per_second: float | None = Field(default=None, gt=0)
    min_connections: int | None = Field(default=None, ge=1)
    interval_variance_threshold: float | None = Field(default=None, ge=0)
    syn_ack_ratio_threshold: float | None = Field(default=None, ge=0, le=1)
    time_window_seconds: int | None = Field(default=None, ge=1)
    mac_ip_mismatch: bool = False

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, value: str | None) -> str | None:
        return value.strip().upper() if value is not None else None

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return str(ipaddress.ip_address(value))

    @field_validator("mitre_attack")
    @classmethod
    def validate_mitre_technique(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().upper()
        if not _MITRE_TECHNIQUE_PATTERN.fullmatch(normalized):
            raise ValueError("mitre_attack must be a MITRE ATT&CK technique ID")
        return normalized

    @field_validator("payload_pattern", "dns_query_pattern")
    @classmethod
    def validate_regular_expression(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError("pattern must be a valid regular expression") from exc
        return value

    @field_validator("unusual_ports")
    @classmethod
    def validate_unusual_ports(cls, value: tuple[int, ...] | None) -> tuple[int, ...] | None:
        if value is None:
            return None
        if not value:
            raise ValueError("unusual_ports must not be empty")
        invalid = [port for port in value if not 0 <= port <= 65535]
        if invalid:
            raise ValueError("unusual_ports contains an invalid port")
        return tuple(dict.fromkeys(value))

    @model_validator(mode="after")
    def validate_supported_conditions(self) -> DetectionRule:
        if self.mac_ip_mismatch:
            raise ValueError(
                "mac_ip_mismatch is not supported until bounded ARP state is implemented"
            )

        condition_fields = (
            self.protocol,
            self.dest_port,
            self.source_ip,
            self.tcp_flags,
            self.arp_op,
            self.payload_pattern,
            self.dns_query_pattern,
            self.unusual_ports,
            self.is_external_ip,
            self.min_unique_ports,
            self.min_syn_packets,
            self.min_dns_queries,
            self.min_bytes_per_second,
            self.min_connections,
            self.interval_variance_threshold,
            self.syn_ack_ratio_threshold,
        )
        if not any(value not in (None, False) for value in condition_fields):
            raise ValueError("detection rule must define at least one supported condition")
        return self


class AlertRecord(BaseModel):
    """Validated alert payload accepted by database persistence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    alert_id: str = Field(min_length=1, max_length=64)
    timestamp: datetime
    source_ip: str | None = None
    dest_ip: str | None = None
    alert_type: str = Field(min_length=1, max_length=160)
    severity: Severity
    description: str = Field(min_length=1, max_length=2000)
    mitre_attack: str | None = None
    recommended_action: str | None = Field(default=None, max_length=2000)

    @field_validator("source_ip", "dest_ip")
    @classmethod
    def validate_ip_address(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return str(ipaddress.ip_address(value))

    @field_validator("mitre_attack")
    @classmethod
    def validate_mitre_technique(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().upper()
        if not _MITRE_TECHNIQUE_PATTERN.fullmatch(normalized):
            raise ValueError("mitre_attack must be a MITRE ATT&CK technique ID")
        return normalized

    def to_persistence_dict(self) -> dict[str, Any]:
        """Return primitive values compatible with the existing database boundary."""

        return self.model_dump(mode="python") | {"severity": self.severity.value}
