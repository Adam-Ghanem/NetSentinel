#!/usr/bin/env python3
"""Emit machine-readable database health and fail on degraded states."""

import argparse
import json

from app.database import DatabaseManager


def build_parser():
    parser = argparse.ArgumentParser(
        description="Check NetSentinel database connectivity, schema, and integrity."
    )
    parser.add_argument(
        "--database-url",
        help="Override DATABASE_URL for this check.",
    )
    return parser


def main():
    args = build_parser().parse_args()
    report = DatabaseManager(args.database_url).database_health()
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "healthy" else 1


if __name__ == "__main__":
    raise SystemExit(main())
