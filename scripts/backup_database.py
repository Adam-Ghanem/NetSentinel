#!/usr/bin/env python3
"""Create a consistent SQLite backup without copying a live database file."""

import argparse
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.database import DatabaseManager


def backup_sqlite_database(source: Path, destination: Path) -> Path:
    source = source.expanduser().resolve()
    destination = destination.expanduser().resolve()

    if not source.is_file():
        raise FileNotFoundError(f"database does not exist: {source}")
    if source == destination:
        raise ValueError("backup destination must differ from source database")

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.unlink(missing_ok=True)

    try:
        with sqlite3.connect(source) as source_connection:
            with sqlite3.connect(temporary) as destination_connection:
                source_connection.backup(destination_connection)
                result = destination_connection.execute(
                    "PRAGMA integrity_check"
                ).fetchone()
                if result is None or result[0] != "ok":
                    raise RuntimeError(f"backup integrity check failed: {result}")
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

    return destination


def default_destination(source: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path("backups") / f"{source.stem}-{timestamp}{source.suffix}"


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database",
        type=Path,
        help="SQLite database path; defaults to DATABASE_URL",
    )
    parser.add_argument("--output", type=Path, help="Backup output path")
    return parser.parse_args()


def main():
    args = parse_args()
    configured_path = DatabaseManager().sqlite_database_path()
    source = args.database or configured_path
    if source is None:
        message = "DATABASE_URL is not a file-backed SQLite database; pass --database"
        raise SystemExit(message)

    destination = args.output or default_destination(source)
    result = backup_sqlite_database(source, destination)
    print(f"Verified SQLite backup created: {result}")


if __name__ == "__main__":
    main()
