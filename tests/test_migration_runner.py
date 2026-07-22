from __future__ import annotations

from pathlib import Path

from sqlalchemy import inspect

from app.database import Base
from scripts.run_migrations import run_migrations


def sqlite_url(path: Path) -> str:
    return f"sqlite:///{path}"


def test_migration_runner_upgrades_empty_database(tmp_path):
    database_url = sqlite_url(tmp_path / "migrated.db")

    report = run_migrations(database_url)

    assert report.status == "ready"
    assert report.migrated is True
    assert report.ready is True

    from sqlalchemy import create_engine

    engine = create_engine(database_url)
    try:
        assert set(inspect(engine).get_table_names()) >= set(Base.metadata.tables)
    finally:
        engine.dispose()


def test_migration_runner_is_idempotent(tmp_path):
    database_url = sqlite_url(tmp_path / "repeat.db")

    first = run_migrations(database_url)
    second = run_migrations(database_url)

    assert first.ready is True
    assert second.ready is True
    assert second.migrated is True


def test_migration_runner_rejects_arbitrary_revision(tmp_path):
    report = run_migrations(sqlite_url(tmp_path / "blocked.db"), revision="base")

    assert report.status == "blocked"
    assert report.migrated is False
    assert report.ready is False


def test_migration_runner_sanitizes_execution_failure(monkeypatch, tmp_path):
    def fail_upgrade(*args, **kwargs):
        raise RuntimeError("sqlite:////private/path/secret.db")

    monkeypatch.setattr("scripts.run_migrations.command.upgrade", fail_upgrade)

    report = run_migrations(sqlite_url(tmp_path / "failure.db"))

    assert report.status == "failed"
    assert report.ready is False
    assert "private/path" not in report.detail
