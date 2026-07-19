import json
import subprocess

from scripts.check_migration_drift import check_migration_drift, main


def completed(returncode, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args=["alembic", "check"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def test_current_schema_is_reported_without_drift(monkeypatch):
    monkeypatch.setattr(
        "scripts.check_migration_drift.subprocess.run",
        lambda *args, **kwargs: completed(0, "No new upgrade operations detected."),
    )

    report = check_migration_drift("sqlite:///:memory:")

    assert report.status == "current"
    assert report.drift_detected is False


def test_model_changes_are_reported_as_drift(monkeypatch):
    monkeypatch.setattr(
        "scripts.check_migration_drift.subprocess.run",
        lambda *args, **kwargs: completed(
            255,
            stderr="ERROR: New upgrade operations detected: [('add_column', None)]",
        ),
    )

    report = check_migration_drift("sqlite:///:memory:")

    assert report.status == "drift_detected"
    assert report.drift_detected is True
    assert "reviewed Alembic migration" in report.detail


def test_unexpected_failure_is_sanitized(monkeypatch):
    monkeypatch.setattr(
        "scripts.check_migration_drift.subprocess.run",
        lambda *args, **kwargs: completed(
            2,
            stderr="could not connect to postgresql://admin:secret@example/db",
        ),
    )

    report = check_migration_drift("postgresql://admin:secret@example/db")

    assert report.status == "unhealthy"
    assert "secret" not in report.detail
    assert "postgresql" not in report.detail


def test_cli_emits_json_and_fails_closed(monkeypatch, capsys):
    monkeypatch.setattr(
        "scripts.check_migration_drift.subprocess.run",
        lambda *args, **kwargs: completed(255, stderr="New upgrade operations detected"),
    )
    monkeypatch.setattr(
        "scripts.check_migration_drift.build_parser",
        lambda: type(
            "Parser",
            (),
            {"parse_args": lambda self: type("Args", (), {"database_url": "sqlite:///:memory:"})()},
        )(),
    )

    exit_code = main()
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["status"] == "drift_detected"
    assert payload["drift_detected"] is True
