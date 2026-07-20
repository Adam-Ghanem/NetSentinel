#!/usr/bin/env python3
"""Validate a legacy database before any explicit Alembic stamp."""

import argparse
import json

from app.config import Config
from app.legacy_adoption import inspect_legacy_database


def main():
    parser = argparse.ArgumentParser(
        description="Read-only validation for pre-Alembic NetSentinel databases."
    )
    parser.add_argument(
        "--database-url",
        default=Config.DATABASE_URL,
        help="Database URL to inspect; defaults to configured DATABASE_URL.",
    )
    args = parser.parse_args()

    report = inspect_legacy_database(args.database_url)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
