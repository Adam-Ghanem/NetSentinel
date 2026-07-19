"""Detect schema changes that are missing an Alembic migration."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class DriftReport:
    status: str
    drift_detected: bool
    detail: str


def check_migration_drift(database_url: str) -> DriftReport:
    """Run Alembic's metadata comparison without exposing sensitive output."""
    env = os.environ.copy()
    env["DATABASE_URL"] = database_url
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "alembic.ini", "check"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    combined_output = f"{result.stdout}\n{result.stderr}".lower()
    if result.returncode == 0:
        return DriftReport(
            status="current",
            drift_detected=False,
            detail="Application metadata matches the reviewed migration history.",
        )
    if "new upgrade operations detected" in combined_output:
        return DriftReport(
            status="drift_detected",
            drift_detected=True,
            detail="Model changes require a reviewed Alembic migration.",
        )
    return DriftReport(
        status="unhealthy",
        drift_detected=False,
        detail="Migration drift verification could not complete safely.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        default=os.getenv("DATABASE_URL", "sqlite:///netsentinel.db"),
        help="Database URL to inspect. Defaults to DATABASE_URL.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = check_migration_drift(args.database_url)
    print(json.dumps(asdict(report), sort_keys=True))
    return 0 if report.status == "current" else 1


if __name__ == "__main__":
    raise SystemExit(main())
