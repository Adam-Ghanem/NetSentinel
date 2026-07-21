from pathlib import Path

from sqlalchemy import create_engine, text

from app.database import Base
from app.legacy_adoption import inspect_legacy_database


def _database_url(tmp_path: Path, name: str = "legacy.db") -> str:
    return f"sqlite:///{tmp_path / name}"


def _create_legacy_schema(database_url: str) -> None:
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    engine.dispose()


def test_matching_unmanaged_database_is_ready(tmp_path):
    database_url = _database_url(tmp_path)
    _create_legacy_schema(database_url)

    report = inspect_legacy_database(database_url)

    assert report["status"] == "ready"
    assert report["connectivity"] == "ok"
    assert report["missing_tables"] == []
    assert report["column_mismatches"] == {}


def test_missing_application_table_blocks_adoption(tmp_path):
    database_url = _database_url(tmp_path)
    _create_legacy_schema(database_url)
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE cases"))
    engine.dispose()

    report = inspect_legacy_database(database_url)

    assert report["status"] == "blocked"
    assert report["missing_tables"] == ["cases"]


def test_column_drift_blocks_adoption(tmp_path):
    database_url = _database_url(tmp_path)
    _create_legacy_schema(database_url)
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE users ADD COLUMN legacy_flag INTEGER"))
    engine.dispose()

    report = inspect_legacy_database(database_url)

    assert report["status"] == "blocked"
    assert report["column_mismatches"]["users"]["unexpected"] == ["legacy_flag"]


def test_existing_migration_metadata_blocks_restamping(tmp_path):
    database_url = _database_url(tmp_path)
    _create_legacy_schema(database_url)
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
        )
    engine.dispose()

    report = inspect_legacy_database(database_url)

    assert report["status"] == "blocked"
    assert report["schema_version"] == "already_managed"


def test_connection_error_is_sanitized(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'missing' / 'legacy.db'}"

    report = inspect_legacy_database(database_url)

    assert report["status"] == "unhealthy"
    assert report["connectivity"] == "failed"
    assert "sqlite" not in report["reason"].lower()
    assert "database_url" not in report
