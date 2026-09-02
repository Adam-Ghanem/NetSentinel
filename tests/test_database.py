import datetime
import sqlite3
import warnings

import pytest
from sqlalchemy import inspect, text

import app.database as database_module
from app.database import AlertModel, DatabaseManager, UserModel


@pytest.fixture
def database(tmp_path):
    return DatabaseManager(
        f"sqlite:///{tmp_path / 'netsentinel-test.db'}",
        auto_create_schema=True,
    )


def test_manager_can_connect_without_creating_schema(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'runtime-only.db'}"
    manager = DatabaseManager(database_url, auto_create_schema=False)

    assert inspect(manager.engine).get_table_names() == []
    report = manager.database_health()
    assert report["status"] == "degraded"
    assert report["schema"] == "incomplete"
    assert sorted(report["missing_tables"]) == ["alerts", "cases", "packets", "users"]


def test_explicit_bootstrap_creates_local_schema(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'bootstrap.db'}"
    manager = DatabaseManager(database_url, auto_create_schema=False)

    manager.bootstrap_schema()

    assert set(inspect(manager.engine).get_table_names()) == {
        "alerts",
        "cases",
        "packets",
        "users",
    }


def test_production_runtime_rejects_schema_bootstrap(tmp_path, monkeypatch):
    monkeypatch.setattr("app.database.Config.ENVIRONMENT", "production")

    with pytest.raises(RuntimeError, match="disabled in production"):
        DatabaseManager(
            f"sqlite:///{tmp_path / 'production.db'}",
            auto_create_schema=True,
        )


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


def test_add_packets_persists_batch_in_one_contract(database):
    packets = database.add_packets(
        [
            {
                "protocol": "TCP",
                "source_ip": "192.0.2.10",
                "dest_ip": "198.51.100.20",
                "packet_size": 60,
            },
            {
                "protocol": "UDP",
                "source_ip": "192.0.2.11",
                "dest_ip": "198.51.100.21",
                "packet_size": 72,
            },
        ]
    )

    assert len(packets) == 2
    stored = database.get_packets(limit=10)
    assert {packet.protocol for packet in stored} == {"TCP", "UDP"}


def test_add_packets_accepts_empty_batch(database):
    assert database.add_packets([]) == []
    assert database.get_packets(limit=10) == []


def test_add_packets_rolls_back_entire_batch_on_invalid_record(database):
    with pytest.raises(TypeError):
        database.add_packets(
            [
                {"protocol": "TCP", "packet_size": 60},
                {"protocol": "UDP", "unknown_field": "invalid"},
            ]
        )

    assert database.get_packets(limit=10) == []


def test_database_utc_clock_preserves_naive_storage_contract():
    clock = database_module._utcnow_naive
    now = clock()
    expected = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    assert now.tzinfo is None
    assert abs((expected - now).total_seconds()) < 1


def test_database_timestamp_defaults_emit_no_utcnow_deprecation(database):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        database.add_packets([{"protocol": "TCP", "packet_size": 60}])
        database.insert_alert(
            {
                "alert_id": "ALERT-TIME",
                "alert_type": "Clock contract",
                "severity": "Low",
            }
        )

    utcnow_warnings = [
        warning
        for warning in caught
        if issubclass(warning.category, DeprecationWarning)
        and "utcnow" in str(warning.message).lower()
    ]
    assert utcnow_warnings == []


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


def test_database_health_reports_healthy_sqlite(database):
    report = database.database_health()

    assert report == {
        "status": "healthy",
        "dialect": "sqlite",
        "connectivity": "ok",
        "schema": "ok",
        "missing_tables": [],
        "integrity": "ok",
    }


def test_database_health_reports_missing_tables(database):
    with database.engine.begin() as connection:
        connection.execute(text("DROP TABLE cases"))

    report = database.database_health()

    assert report["status"] == "degraded"
    assert report["schema"] == "incomplete"
    assert report["missing_tables"] == ["cases"]
    assert report["connectivity"] == "ok"


def test_database_health_handles_connectivity_failure(database):
    database.engine.dispose()
    database.engine = database.engine.execution_options()

    original_connect = database.engine.connect

    def fail_connect():
        raise RuntimeError("database unavailable")

    database.engine.connect = fail_connect
    try:
        report = database.database_health()
    finally:
        database.engine.connect = original_connect

    assert report["status"] == "unhealthy"
    assert report["connectivity"] == "failed"
    assert report["error"] == "RuntimeError"


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
        database.create_user("   ", "placeholder")
    with pytest.raises(ValueError, match="password"):
        database.create_user("analyst", "")


def test_create_and_authenticate_user(database):
    credential = "-".join(("test", "credential", "value"))
    created = database.create_user(" analyst ", credential)

    assert created.username == "analyst"
    authenticated = database.authenticate_user("analyst", credential)
    assert authenticated.role == "Analyst"
    assert database.authenticate_user("analyst", "wrong") is None

    with database.Session() as session:
        stored = session.query(UserModel).filter_by(username="analyst").one()
        assert stored.password_hash != credential
