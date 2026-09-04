from app.case_manager import CaseManager
from app.database import DatabaseManager


def _database(tmp_path):
    return DatabaseManager(
        f"sqlite:///{tmp_path / 'case-observability.db'}",
        auto_create_schema=True,
    )


def _alert(database, alert_id):
    return database.insert_alert(
        {
            "alert_id": alert_id,
            "alert_type": "Port scan",
            "severity": "High",
            "description": "Observed scan activity",
        }
    )


def test_case_workflow_metrics_are_aggregate_only(tmp_path):
    database = _database(tmp_path)
    alert_one = _alert(database, "ALERT-METRICS-001")
    alert_two = _alert(database, "ALERT-METRICS-002")
    manager = CaseManager(database)

    first = manager.create_case_from_alert(
        {"alert_id": alert_one.alert_id, "severity": alert_one.severity},
        "First case",
        actor="analyst.alice",
    )
    manager.assign_owner(first.case_id, "analyst.alice", actor="analyst.alice")
    manager.update_case_status(first.case_id, "In Progress", actor="analyst.alice")
    manager.create_case_from_alert(
        {"alert_id": alert_two.alert_id, "severity": alert_two.severity},
        "Second case",
        actor="analyst.bob",
    )

    snapshot = database.case_workflow_metrics()

    assert snapshot == {
        "total_cases": 2,
        "owned_cases": 1,
        "unowned_cases": 1,
        "status_counts": {
            "Closed": 0,
            "In Progress": 1,
            "Open": 1,
            "Resolved": 0,
        },
        "audit_events": 4,
    }
    serialized = repr(snapshot)
    assert "analyst.alice" not in serialized
    assert "ALERT-METRICS" not in serialized


def test_case_workflow_metrics_are_zero_safe(tmp_path):
    database = _database(tmp_path)

    assert database.case_workflow_metrics() == {
        "total_cases": 0,
        "owned_cases": 0,
        "unowned_cases": 0,
        "status_counts": {
            "Closed": 0,
            "In Progress": 0,
            "Open": 0,
            "Resolved": 0,
        },
        "audit_events": 0,
    }
