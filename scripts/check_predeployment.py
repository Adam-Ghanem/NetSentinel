#!/usr/bin/env python3
"""Run the fail-closed database checks required before deploying NetSentinel."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any, Callable

from app.config import Config
from scripts.check_database_readiness import check_database_readiness
from scripts.check_migration_drift import check_migration_drift

ReadinessChecker = Callable[[str], dict[str, Any]]
DriftChecker = Callable[[str], Any]


@dataclass(frozen=True, slots=True)
class PredeploymentReport:
    status: str
    ready: bool
    checks: dict[str, dict[str, Any]]
    blockers: tuple[str, ...]


def _normalize_drift_report(report: Any) -> dict[str, Any]:
    if is_dataclass(report):
        return asdict(report)
    if isinstance(report, dict):
        return dict(report)
    return {
        "status": "unhealthy",
        "drift_detected": False,
        "detail": "Migration drift verification returned an unsupported result.",
    }


def check_predeployment(
    database_url: str,
    *,
    readiness_checker: ReadinessChecker = check_database_readiness,
    drift_checker: DriftChecker = check_migration_drift,
) -> PredeploymentReport:
    """Return a sanitized deployment decision without mutating application schema."""

    readiness = readiness_checker(database_url)
    checks: dict[str, dict[str, Any]] = {"database_readiness": readiness}
    blockers: list[str] = []

    if not readiness.get("ready", False):
        blockers.append("database_readiness")
        checks["migration_drift"] = {
            "status": "skipped",
            "drift_detected": False,
            "detail": "Skipped because the database readiness check failed.",
        }
        return PredeploymentReport(
            status="blocked",
            ready=False,
            checks=checks,
            blockers=tuple(blockers),
        )

    drift = _normalize_drift_report(drift_checker(database_url))
    checks["migration_drift"] = drift
    if drift.get("status") != "current":
        blockers.append("migration_drift")

    return PredeploymentReport(
        status="ready" if not blockers else "blocked",
        ready=not blockers,
        checks=checks,
        blockers=tuple(blockers),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        default=Config.DATABASE_URL,
        help="Database URL to verify. Defaults to the validated application setting.",
    )
    return parser


def main() -> int:
    report = check_predeployment(build_parser().parse_args().database_url)
    print(json.dumps(asdict(report), sort_keys=True))
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
