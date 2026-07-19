import os
import subprocess
import sys

from sqlalchemy import create_engine, inspect, text

from app.database import Base
from app.schema import CURRENT_SCHEMA_VERSION


def run_alembic(database_url, *arguments):
    env = os.environ.copy()
    env["DATABASE_URL"] = database_url
    return subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "alembic.ini", *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_baseline_upgrade_creates_expected_schema(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'migration.db'}"

    result = run_alembic(database_url, "upgrade", "head")

    assert result.returncode == 0, result.stderr
    engine = create_engine(database_url)
    tables = set(inspect(engine).get_table_names())
    assert set(Base.metadata.tables).issubset(tables)
    assert {"alembic_version", "netsentinel_schema"}.issubset(tables)
    with engine.connect() as connection:
        schema_version = connection.execute(
            text("SELECT version FROM netsentinel_schema")
        ).scalar_one()
        alembic_version = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()
    engine.dispose()

    assert schema_version == CURRENT_SCHEMA_VERSION
    assert alembic_version == "0001_baseline"


def test_baseline_upgrade_is_idempotent(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'idempotent.db'}"

    first = run_alembic(database_url, "upgrade", "head")
    second = run_alembic(database_url, "upgrade", "head")

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr


def test_destructive_baseline_downgrade_is_blocked(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'downgrade.db'}"
    assert run_alembic(database_url, "upgrade", "head").returncode == 0

    result = run_alembic(database_url, "downgrade", "base")

    assert result.returncode != 0
    assert "intentionally disabled" in result.stderr
