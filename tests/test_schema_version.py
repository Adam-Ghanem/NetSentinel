from sqlalchemy import create_engine, text

from app.schema import CURRENT_SCHEMA_VERSION, schema_compatibility
from scripts.check_schema_version import check_schema_version


def test_schema_compatibility_states():
    assert schema_compatibility(None) == "unversioned"
    assert schema_compatibility(CURRENT_SCHEMA_VERSION) == "current"
    assert schema_compatibility(CURRENT_SCHEMA_VERSION - 1) == "upgrade_required"
    assert schema_compatibility(CURRENT_SCHEMA_VERSION + 1) == "newer_than_application"


def test_check_schema_version_reports_unversioned_database(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'unversioned.db'}"
    create_engine(database_url).dispose()

    report = check_schema_version(database_url)

    assert report == {
        "status": "unversioned",
        "compatible": False,
        "current_version": CURRENT_SCHEMA_VERSION,
        "recorded_version": None,
    }


def test_check_schema_version_reports_current_database(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'current.db'}"
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE netsentinel_schema (version INTEGER NOT NULL)"))
        connection.execute(
            text("INSERT INTO netsentinel_schema (version) VALUES (:version)"),
            {"version": CURRENT_SCHEMA_VERSION},
        )
    engine.dispose()

    report = check_schema_version(database_url)

    assert report["status"] == "current"
    assert report["compatible"] is True
    assert report["recorded_version"] == CURRENT_SCHEMA_VERSION


def test_check_schema_version_reports_newer_database(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'newer.db'}"
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE netsentinel_schema (version INTEGER NOT NULL)"))
        connection.execute(
            text("INSERT INTO netsentinel_schema (version) VALUES (:version)"),
            {"version": CURRENT_SCHEMA_VERSION + 1},
        )
    engine.dispose()

    report = check_schema_version(database_url)

    assert report["status"] == "newer_than_application"
    assert report["compatible"] is False
