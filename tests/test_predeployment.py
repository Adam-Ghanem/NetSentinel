from __future__ import annotations

from scripts.check_migration_drift import DriftReport
from scripts.check_predeployment import check_predeployment


def test_predeployment_is_ready_when_all_checks_pass():
    report = check_predeployment(
        "sqlite:///ready.db",
        readiness_checker=lambda _: {"status": "ready", "ready": True},
        drift_checker=lambda _: DriftReport(
            status="current",
            drift_detected=False,
            detail="Metadata matches migrations.",
        ),
    )

    assert report.ready is True
    assert report.status == "ready"
    assert report.blockers == ()
    assert report.checks["migration_drift"]["status"] == "current"


def test_predeployment_blocks_and_skips_drift_when_database_is_not_ready():
    drift_called = False

    def drift_checker(_):
        nonlocal drift_called
        drift_called = True
        raise AssertionError("drift checker must not run")

    report = check_predeployment(
        "sqlite:///blocked.db",
        readiness_checker=lambda _: {"status": "blocked", "ready": False},
        drift_checker=drift_checker,
    )

    assert report.ready is False
    assert report.blockers == ("database_readiness",)
    assert report.checks["migration_drift"]["status"] == "skipped"
    assert drift_called is False


def test_predeployment_blocks_detected_migration_drift():
    report = check_predeployment(
        "sqlite:///drift.db",
        readiness_checker=lambda _: {"status": "ready", "ready": True},
        drift_checker=lambda _: DriftReport(
            status="drift_detected",
            drift_detected=True,
            detail="A reviewed migration is required.",
        ),
    )

    assert report.ready is False
    assert report.status == "blocked"
    assert report.blockers == ("migration_drift",)


def test_predeployment_fails_closed_for_unsupported_drift_results():
    report = check_predeployment(
        "sqlite:///unknown.db",
        readiness_checker=lambda _: {"status": "ready", "ready": True},
        drift_checker=lambda _: object(),
    )

    assert report.ready is False
    assert report.checks["migration_drift"]["status"] == "unhealthy"
