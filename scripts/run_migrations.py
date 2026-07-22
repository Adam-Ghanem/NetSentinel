#!/usr/bin/env python3
"""Apply reviewed Alembic migrations and verify database readiness."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass

from alembic import command
from alembic.config import Config as AlembicConfig

from app.config import Config
from scripts.check_database_readiness import check_database_readiness


@dataclass(frozen=True, slots=True)
class MigrationRunReport:
    status: str
    migrated: bool
    ready: bool
    detail: str


def run_migrations(database_url: str, *, revision: str = "head") -> MigrationRunReport:
    """Upgrade to a reviewed revision and return a sanitized readiness result."""

    if revision != "head":
        return MigrationRunReport(
            status="blocked",
            migrated=False,
            ready=False,
            detail="Only the reviewed Alembic head revision is allowed.",
        )

    alembic_config = AlembicConfig("alembic.ini")
    alembic_config.set_main_option("sqlalchemy.url", database_url)

    try:
        command.upgrade(alembic_config, revision)
    except Exception:
        return MigrationRunReport(
            status="failed",
            migrated=False,
            ready=False,
            detail="Migration execution failed. Review migration logs and restore from backup if needed.",
        )

    readiness = check_database_readiness(database_url)
    ready = bool(readiness.get("ready", False))
    return MigrationRunReport(
        status="ready" if ready else "failed",
        migrated=True,
        ready=ready,
        detail=(
            "Database migrated and passed readiness checks."
            if ready
            else "Migration completed but database readiness verification failed."
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        default=Config.DATABASE_URL,
        help="Database URL to migrate. Defaults to the validated application setting.",
    )
    parser.add_argument(
        "--revision",
        default="head",
        help="Target Alembic revision. Only 'head' is accepted.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = run_migrations(args.database_url, revision=args.revision)
    print(json.dumps(asdict(report), sort_keys=True))
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
