import pytest

from app.case_manager import CaseManager
from app.database import DatabaseManager


@pytest.fixture
def database(tmp_path):
    return DatabaseManager(
        f"sqlite:///{tmp_path / 'case-audit.db'}",
        auto_create_schema=True,
    )


@pytest.fixture
def stored_alert(database):
    return database.insert_alert(
        {
            "alert_id": "ALERT-AUDIT-001",
            "alert_type": "Beaconing",
            "severity": "Medium",
            "description": "Periodic outbound traffic",
        }
    )


def test_case_creation_records_audit_event(database, stored_alert):
    manager = CaseManager(database)

    case = manager.create_case_from_alert(
        {"alert_id": stored_alert.alert_id, "severity": stored_alert.severity},
        "Investigate beaconing",
        actor="analyst.alice",
    )

    events = manager.get_case_history(case.case_id)
    assert len(events) == 1
    assert events[0].event_type == "case.created"
    assert events[0].actor == "analyst.alice"
    assert events[0].case_id == case.case_id


def test_owner_assignment_records_before_and_after_values(database, stored_alert):
    manager = CaseManager(database)
    case = manager.create_case_from_alert(
        {"alert_id": stored_alert.alert_id, "severity": stored_alert.severity},
        "Ownership audit",
        actor="analyst.alice",
    )

    manager.assign_owner(case.case_id, "analyst.bob", actor="analyst.alice")

    events = manager.get_case_history(case.case_id)
    owner_event = events[-1]
    assert owner_event.event_type == "case.owner_changed"
    assert owner_event.previous_value == ""
    assert owner_event.new_value == "analyst.bob"


def test_status_transition_records_audit_event(database, stored_alert):
    manager = CaseManager(database)
    case = manager.create_case_from_alert(
        {"alert_id": stored_alert.alert_id, "severity": stored_alert.severity},
        "Status audit",
        actor="analyst.alice",
    )

    manager.update_case_status(case.case_id, "In Progress", actor="analyst.bob")

    event = manager.get_case_history(case.case_id)[-1]
    assert event.event_type == "case.status_changed"
    assert event.previous_value == "Open"
    assert event.new_value == "In Progress"
    assert event.actor == "analyst.bob"


def test_notes_append_records_metadata_without_note_content(database, stored_alert):
    manager = CaseManager(database)
    case = manager.create_case_from_alert(
        {"alert_id": stored_alert.alert_id, "severity": stored_alert.severity},
        "Note privacy",
        actor="analyst.alice",
    )

    manager.add_analyst_notes(case.case_id, "sensitive analyst observation", actor="analyst.bob")

    event = manager.get_case_history(case.case_id)[-1]
    assert event.event_type == "case.note_added"
    assert event.previous_value == ""
    assert event.new_value == "length=29"


def test_audit_history_is_oldest_first(database, stored_alert):
    manager = CaseManager(database)
    case = manager.create_case_from_alert(
        {"alert_id": stored_alert.alert_id, "severity": stored_alert.severity},
        "Chronological history",
        actor="analyst.alice",
    )
    manager.assign_owner(case.case_id, "analyst.bob", actor="analyst.alice")
    manager.update_case_status(case.case_id, "In Progress", actor="analyst.bob")

    events = manager.get_case_history(case.case_id)
    assert [event.event_type for event in events] == [
        "case.created",
        "case.owner_changed",
        "case.status_changed",
    ]


def test_audit_actor_is_required(database, stored_alert):
    manager = CaseManager(database)

    with pytest.raises(ValueError, match="actor"):
        manager.create_case_from_alert(
            {"alert_id": stored_alert.alert_id, "severity": stored_alert.severity},
            "Missing actor",
            actor="   ",
        )
