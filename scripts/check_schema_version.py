#!/usr/bin/env python3
"""Report whether a NetSentinel database schema is compatible with this build."""

import argparse
import json

from sqlalchemy import create_engine, inspect, text

from app.config import Config
from app.schema import CURRENT_SCHEMA_VERSION, SCHEMA_VERSION_TABLE, schema_compatibility


def check_schema_version(database_url):
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        tables = set(inspect(engine).get_table_names())
        recorded_version = None
        if SCHEMA_VERSION_TABLE in tables:
            with engine.connect() as connection:
                recorded_version = connection.execute(
                    text(f"SELECT version FROM {SCHEMA_VERSION_TABLE} ORDER BY version DESC LIMIT 1")
                ).scalar_one_or_none()
        status = schema_compatibility(recorded_version)
        return {
            "status": status,
            "compatible": status == "current",
            "current_version": CURRENT_SCHEMA_VERSION,
            "recorded_version": recorded_version,
        }
    except Exception as exc:
        return {
            "status": "unhealthy",
            "compatible": False,
            "current_version": CURRENT_SCHEMA_VERSION,
            "recorded_version": None,
            "error": type(exc).__name__,
        }
    finally:
        engine.dispose()


def build_parser():
    parser = argparse.ArgumentParser(description="Check database schema compatibility.")
    parser.add_argument("--database-url", default=Config.DATABASE_URL)
    return parser


def main():
    report = check_schema_version(build_parser().parse_args().database_url)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["compatible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
