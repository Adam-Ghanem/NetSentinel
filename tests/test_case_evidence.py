import pytest

from app.case_manager import CaseManager
from app.database import DatabaseManager


@pytest.fixture
def database(tmp_path):
    return DatabaseManager(
        f"sqlite:///{tmp_path / 'case-evidence.db'}",
        auto_create_schema=True,
    )


@pytest.fixture
def case(database):
    alert = database.insert_alert(
        {
            "alert_id": "ALERT-EVIDENCE-001",
            "alert_type": "Beaconing",
            "severity": "High",
            "description": "Periodic outbound traffic",
        }
    )
    return CaseManager(database).create_case_from_alert(
        {"alert_id": alert.alert_id, "severity": alert.severity},
        "Investigate beaconing",
        actor="analyst.alice",
    )


def test_case_manager_adds_normalized_structured_evidence(database, case):
    manager = CaseManager(database)

    evidence = manager.add_evidence(
        case.case_id,
        evidence_type="  packet-capture  ",
        source="  sensor-01  ",
        reference="  sha256:abc123  ",
        summary="  PCAP slice containing the beacon sequence  ",
        actor="analyst.alice",
    )

    assert evidence.case_id == case.case_id
    assert evidence.evidence_type == "packet-capture"
    assert evidence.source == "sensor-01"
    assert evidence.reference == "sha256:abc123"
    assert evidence.summary == "PCAP slice containing the beacon sequence"
    assert evidence.added_by == "analyst.alice"


def test_case_evidence_is_append_only_and_ordered(database, case):
    manager = CaseManager(database)
    first = manager.add_evidence(
        case.case_id,
        "log-query",
        "wazuh",
        "query:beacon-001",
        "Initial correlated events",
        actor="analyst.alice",
    )
    second = manager.add_evidence(
        case.case_id,
        "ioc",
        "local-analysis",
        "domain:example.invalid",
        "Domain extracted from alert context",
        actor="analyst.bob",
    )

    evidence = manager.get_case_evidence(case.case_id)

    assert [item.evidence_id for item in evidence] == [first.evidence_id, second.evidence_id]
    assert not hasattr(manager, "update_evidence")
    assert not hasattr(manager, "delete_evidence")


def test_case_evidence_audit_event_does_not_copy_sensitive_fields(database, case):
    manager = CaseManager(database)
    item = manager.add_evidence(
        case.case_id,
        "artifact",
        "sandbox",
        "sha256:secret-reference",
        "Sensitive analyst-only summary",
        actor="analyst.alice",
    )

    event = manager.get_case_history(case.case_id)[-1]

    assert event.event_type == "case.evidence_added"
    assert event.actor == "analyst.alice"
    assert item.evidence_id in event.new_value
    assert "artifact" in event.new_value
    assert "secret-reference" not in event.new_value
    assert "Sensitive analyst-only summary" not in event.new_value


def test_case_manager_rejects_invalid_evidence_boundaries(database, case):
    manager = CaseManager(database)

    with pytest.raises(ValueError, match="evidence_type"):
        manager.add_evidence(case.case_id, " ", "sensor", "ref", "summary")
    with pytest.raises(ValueError, match="source"):
        manager.add_evidence(case.case_id, "artifact", " ", "ref", "summary")
    with pytest.raises(ValueError, match="reference"):
        manager.add_evidence(case.case_id, "artifact", "sensor", " ", "summary")
    with pytest.raises(ValueError, match="summary"):
        manager.add_evidence(case.case_id, "artifact", "sensor", "ref", "x" * 2001)


def test_case_manager_returns_none_when_adding_evidence_to_unknown_case(database):
    manager = CaseManager(database)

    assert (
        manager.add_evidence(
            "CASE-MISSING",
            "artifact",
            "sensor",
            "sha256:abc",
            "Missing case",
        )
        is None
    )


def test_case_evidence_reads_use_validated_limits(database, case):
    manager = CaseManager(database)
    manager.add_evidence(case.case_id, "artifact", "sensor", "ref-1", "one")
    manager.add_evidence(case.case_id, "artifact", "sensor", "ref-2", "two")

    assert len(manager.get_case_evidence(case.case_id, limit=1)) == 1
    with pytest.raises(ValueError, match="limit"):
        manager.get_case_evidence(case.case_id, limit=0)
