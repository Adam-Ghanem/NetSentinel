import json

from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import create_engine, inspect, text

from scripts.check_database_readiness import check_database_readiness, main


def migrated_database(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'ready.db'}"
    config = AlembicConfig("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    return database_url


def test_readiness_reports_migrated_database_ready(tmp_path):
    report = check_database_readiness(migrated_database(tmp_path))

    assert report["status"] == "ready"
    assert report["ready"] is True
    assert report["connectivity"] == "ok"
    assert report["schema"] == "ok"
    assert report["schema_version"] == "current"
    assert report["missing_tables"] == []
    assert report["integrity"] == "ok"


def test_readiness_blocks_incomplete_schema(tmp_path):
    database_url = migrated_database(tmp_path)
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE cases"))
    engine.dispose()

    report = check_database_readiness(database_url)

    assert report["status"] == "blocked"
    assert report["ready"] is False
    assert report["schema"] == "incomplete"
    assert report["missing_tables"] == ["cases"]


def test_readiness_does_not_create_schema(tmp_path):
    database_path = tmp_path / "empty.db"
    database_url = f"sqlite:///{database_path}"
    report = check_database_readiness(database_url)

    assert report["status"] == "blocked"
    assert report["ready"] is False
    assert report["schema"] == "incomplete"
    assert report["schema_version"] == "unversioned"

    engine = create_engine(database_url)
    assert inspect(engine).get_table_names() == []
    engine.dispose()


def test_cli_returns_nonzero_for_unready_database(tmp_path, monkeypatch, capsys):
    database_url = f"sqlite:///{tmp_path / 'empty-cli.db'}"
    monkeypatch.setattr(
        "sys.argv",
        ["check_database_readiness.py", "--database-url", database_url],
    )

    assert main() == 1
    output = json.loads(capsys.readouterr().out)
    assert output["ready"] is False
    assert "sqlite:///" not in json.dumps(output)
