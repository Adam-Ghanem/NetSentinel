import pytest

from app.case_manager import CaseManager
from app.database import DatabaseManager


@pytest.fixture
def database(tmp_path):
    return DatabaseManager(
        f"sqlite:///{tmp_path / 'case-evidence-audit.db'}",
        auto_create_schema=True,
    )


@pytest.fixture
def case(database):
    alert = database.insert_alert(
        {
            "alert_id": "ALERT-EVIDENCE-AUDIT-001",
            "alert_type": "Suspicious transfer",
            "severity": "High",
        }
    )
    return CaseManager(database).create_case_from_alert(
        {"alert_id": alert.alert_id, "severity": alert.severity},
        "Evidence audit",
        actor="analyst.alice",
    )


def test_adding_evidence_records_audit_event(database, case):
    manager = CaseManager(database)

    evidence = manager.add_evidence(
        case.case_id,
        evidence_type="packet_capture",
        reference="captures/incident-001.pcapng",
        sha256="a" * 64,
        actor="analyst.alice",
    )

    event = manager.get_case_history(case.case_id)[-1]
    assert event.event_type == "case.evidence_added"
    assert event.actor == "analyst.alice"
    assert event.new_value == f"evidence_id={evidence.evidence_id};type=packet_capture;sha256=yes"


def test_evidence_audit_event_does_not_copy_reference(database, case):
    manager = CaseManager(database)
    reference = "https://example.invalid/private/evidence?id=secret"

    manager.add_evidence(
        case.case_id,
        evidence_type="external_reference",
        reference=reference,
        actor="analyst.alice",
    )

    event = manager.get_case_history(case.case_id)[-1]
    serialized = f"{event.previous_value} {event.new_value}"
    assert reference not in serialized
    assert "secret" not in serialized
