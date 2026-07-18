import sqlite3

import pytest

from scripts.backup_database import backup_sqlite_database, default_destination


def create_database(path):
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE events (id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO events (value) VALUES ('captured')")


def test_backup_preserves_data_and_integrity(tmp_path):
    source = tmp_path / "source.db"
    destination = tmp_path / "nested" / "backup.db"
    create_database(source)

    result = backup_sqlite_database(source, destination)

    assert result == destination.resolve()
    with sqlite3.connect(result) as connection:
        assert connection.execute("SELECT value FROM events").fetchone() == (
            "captured",
        )
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)


def test_backup_rejects_missing_source(tmp_path):
    with pytest.raises(FileNotFoundError, match="does not exist"):
        backup_sqlite_database(tmp_path / "missing.db", tmp_path / "backup.db")


def test_backup_rejects_source_as_destination(tmp_path):
    source = tmp_path / "source.db"
    create_database(source)

    with pytest.raises(ValueError, match="must differ"):
        backup_sqlite_database(source, source)


def test_default_destination_uses_backup_directory(tmp_path):
    destination = default_destination(tmp_path / "netsentinel.db")

    assert destination.parent.name == "backups"
    assert destination.name.startswith("netsentinel-")
    assert destination.suffix == ".db"
