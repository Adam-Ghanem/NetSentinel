import sqlite3

import pytest
from sqlalchemy import text

from app.database import AlertModel, DatabaseManager, UserModel


@pytest.fixture
def database(tmp_path):
    return DatabaseManager(f"sqlite:///{tmp_path / 'netsentinel-test.db'}")


def test_transaction_commits_and_returns_detached_values(database):
    alert = database.insert_alert(
        {
            "alert_id": "ALERT-001",
            "alert_type": "Port scan",
            "severity": "Medium",
        }
    )

    assert alert.alert_id == "ALERT-001"
    assert database.get_alerts()[0].alert_type == "Port scan"


def test_transaction_rolls_back_on_error(database):
    with pytest.raises(RuntimeError, match="abort"):
        with database.transaction() as session:
            session.add(
                AlertModel(
                    alert_id="ALERT-ROLLBACK",
                    alert_type="Test",
                    severity="Low",
                )
            )
            raise RuntimeError("abort")

    assert database.get_alerts() == []


def test_sqlite_foreign_keys_are_enabled(database):
    with database.engine.connect() as connection:
        assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1


def test_sqlite_file_uses_wal_and_busy_timeout(database):
    path = database.sqlite_database_path()
    assert path is not None

    with sqlite3.connect(path) as connection:
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        busy_timeout = connection.execute("PRAGMA busy_timeout").fetchone()[0]

    assert journal_mode.lower() == "wal"
    assert busy_timeout >= 5000


@pytest.mark.parametrize("limit", [0, -1, 10_001])
def test_query_limit_rejects_out_of_range_values(database, limit):
    with pytest.raises(ValueError, match="between 1 and 10000"):
        database.get_alerts(limit=limit)


@pytest.mark.parametrize("limit", [True, 1.5, "10", None])
def test_query_limit_rejects_non_integers(database, limit):
    with pytest.raises(TypeError, match="integer"):
        database.get_packets(limit=limit)


def test_create_user_validates_credentials(database):
    with pytest.raises(ValueError, match="username"):
        database.create_user("   ", "password")
    with pytest.raises(ValueError, match="password"):
        database.create_user("analyst", "")


def test_create_and_authenticate_user(database):
    created = database.create_user(" analyst ", "correct horse battery staple")

    assert created.username == "analyst"
    assert database.authenticate_user("analyst", "correct horse battery staple").role == "Analyst"
    assert database.authenticate_user("analyst", "wrong") is None

    with database.Session() as session:
        stored = session.query(UserModel).filter_by(username="analyst").one()
        assert stored.password_hash != "correct horse battery staple"
