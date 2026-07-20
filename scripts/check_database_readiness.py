#!/usr/bin/env python3
"""Validate database readiness without creating or mutating application tables."""

import argparse
import json

from sqlalchemy import create_engine, inspect, text

from app.config import Config
from app.database import Base
from scripts.check_schema_version import check_schema_version


def check_database_readiness(database_url):
    """Return a sanitized, read-only deployment readiness report."""
    engine = create_engine(database_url, pool_pre_ping=True)
    report = {
        "status": "ready",
        "ready": True,
        "connectivity": "ok",
        "schema": "ok",
        "missing_tables": [],
    }

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            if engine.dialect.name == "sqlite":
                integrity = connection.execute(text("PRAGMA integrity_check")).scalar_one()
                report["integrity"] = integrity
                if str(integrity).lower() != "ok":
                    report.update(status="blocked", ready=False)

        expected_tables = set(Base.metadata.tables)
        existing_tables = set(inspect(engine).get_table_names())
        missing_tables = sorted(expected_tables - existing_tables)
        if missing_tables:
            report.update(
                status="blocked",
                ready=False,
                schema="incomplete",
                missing_tables=missing_tables,
            )

        version_report = check_schema_version(database_url)
        report["schema_version"] = version_report["status"]
        if not version_report["compatible"]:
            report.update(status="blocked", ready=False)

        return report
    except Exception as exc:
        return {
            "status": "blocked",
            "ready": False,
            "connectivity": "failed",
            "schema": "unknown",
            "missing_tables": [],
            "error": type(exc).__name__,
        }
    finally:
        engine.dispose()


def build_parser():
    parser = argparse.ArgumentParser(
        description="Check database readiness without creating or altering schema."
    )
    parser.add_argument("--database-url", default=Config.DATABASE_URL)
    return parser


def main():
    report = check_database_readiness(build_parser().parse_args().database_url)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
