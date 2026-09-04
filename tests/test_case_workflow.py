import pytest

from app.case_manager import CaseManager
from app.database import DatabaseManager


@pytest.fixture
def database(tmp_path):
    return DatabaseManager(
        f"sqlite:///{tmp_path / 'case-workflow.db'}",
        auto_create_schema=True,
    )


@pytest.fixture
def stored_alert(database):
    return database.insert_alert(
        {
            "alert_id": "ALERT-CASE-001",
            "alert_type": "Port scan",
            "severity": "High",
            "description": "Observed scan activity",
        }
    )


def test_database_case_crud_preserves_alert_link(database, stored_alert):
    created = database.insert_case(
        {
            "case_id": "CASE-001",
            "alert_id": stored_alert.alert_id,
            "title": "Investigate scan",
            "status": "Open",
            "severity": stored_alert.severity,
        }
    )

    assert created.case_id == "CASE-001"
    assert created.alert_id == stored_alert.alert_id
    assert database.get_case("CASE-001").title == "Investigate scan"

    updated = database.update_case("CASE-001", {"status": "In Progress"})

    assert updated.status == "In Progress"
    assert database.get_case("CASE-001").status == "In Progress"


def test_database_update_case_returns_none_for_unknown_case(database):
    assert database.update_case("CASE-MISSING", {"status": "Closed"}) is None


def test_database_update_case_rejects_identity_mutation(database, stored_alert):
    database.insert_case(
        {
            "case_id": "CASE-IMMUTABLE",
            "alert_id": stored_alert.alert_id,
            "title": "Immutable identity",
        }
    )

    with pytest.raises(ValueError, match="unsupported case update fields"):
        database.update_case("CASE-IMMUTABLE", {"case_id": "CASE-OTHER"})


def test_case_manager_creates_case_from_persisted_alert(database, stored_alert):
    manager = CaseManager(database)

    created = manager.create_case_from_alert(
        {"alert_id": stored_alert.alert_id, "severity": stored_alert.severity},
        "  Investigate scan activity  ",
        analyst_notes="Initial triage",
        tags="network,scan",
    )

    assert created.title == "Investigate scan activity"
    assert created.status == "Open"
    assert created.severity == "High"
    assert manager.get_case(created.case_id).alert_id == stored_alert.alert_id


def test_case_manager_rejects_empty_title(database, stored_alert):
    manager = CaseManager(database)

    with pytest.raises(ValueError, match="title"):
        manager.create_case_from_alert(
            {"alert_id": stored_alert.alert_id, "severity": stored_alert.severity},
            "   ",
        )


@pytest.mark.parametrize("status", ["Open", "In Progress", "Resolved", "Closed"])
def test_case_manager_accepts_reviewed_statuses(database, stored_alert, status):
    manager = CaseManager(database)
    case = manager.create_case_from_alert(
        {"alert_id": stored_alert.alert_id, "severity": stored_alert.severity},
        "Status transition",
    )

    updated = manager.update_case_status(case.case_id, status)

    assert updated.status == status


def test_case_manager_rejects_unknown_status(database, stored_alert):
    manager = CaseManager(database)
    case = manager.create_case_from_alert(
        {"alert_id": stored_alert.alert_id, "severity": stored_alert.severity},
        "Status transition",
    )

    with pytest.raises(ValueError, match="status"):
        manager.update_case_status(case.case_id, "Escalated-ish")


def test_case_manager_appends_analyst_notes(database, stored_alert):
    manager = CaseManager(database)
    case = manager.create_case_from_alert(
        {"alert_id": stored_alert.alert_id, "severity": stored_alert.severity},
        "Analyst notes",
        analyst_notes="First observation",
    )

    updated = manager.add_analyst_notes(case.case_id, "Second observation")

    assert updated.analyst_notes == "First observation\nSecond observation"


def test_case_manager_returns_none_for_unknown_case(database):
    manager = CaseManager(database)

    assert manager.get_case("CASE-MISSING") is None
