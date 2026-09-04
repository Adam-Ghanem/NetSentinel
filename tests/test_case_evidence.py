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
        }
    )
    return CaseManager(database).create_case_from_alert(
        {"alert_id": alert.alert_id, "severity": alert.severity},
        "Investigate evidence",
        actor="analyst.alice",
    )


def test_add_case_evidence_persists_reference(database, case):
    manager = CaseManager(database)

    evidence = manager.add_evidence(
        case.case_id,
        evidence_type="packet_capture",
        reference="captures/incident-001.pcapng",
        actor="analyst.alice",
    )

    stored = manager.get_case_evidence(case.case_id)
    assert evidence.case_id == case.case_id
    assert evidence.evidence_type == "packet_capture"
    assert evidence.reference == "captures/incident-001.pcapng"
    assert [item.evidence_id for item in stored] == [evidence.evidence_id]


def test_add_case_evidence_returns_none_for_unknown_case(database):
    manager = CaseManager(database)

    assert (
        manager.add_evidence(
            "CASE-MISSING",
            evidence_type="report",
            reference="reports/missing.pdf",
            actor="analyst.alice",
        )
        is None
    )


def test_evidence_sha256_is_normalized(database, case):
    manager = CaseManager(database)
    digest = "A" * 64

    evidence = manager.add_evidence(
        case.case_id,
        evidence_type="report",
        reference="reports/incident.pdf",
        sha256=digest,
        actor="analyst.alice",
    )

    assert evidence.sha256 == digest.lower()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("evidence_type", "", "evidence_type"),
        ("evidence_type", "x" * 65, "evidence_type"),
        ("reference", "", "reference"),
        ("reference", "x" * 2049, "reference"),
        ("sha256", "not-a-digest", "sha256"),
    ],
)
def test_evidence_validation_rejects_invalid_values(
    database,
    case,
    field,
    value,
    message,
):
    manager = CaseManager(database)
    values = {
        "evidence_type": "report",
        "reference": "reports/incident.pdf",
        "sha256": None,
    }
    values[field] = value

    with pytest.raises(ValueError, match=message):
        manager.add_evidence(
            case.case_id,
            actor="analyst.alice",
            **values,
        )
