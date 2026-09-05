from fastapi.testclient import TestClient

from api import create_app
from app.rules_engine import RulesEngine


_VALID_RULE = """
name: DNS visibility
protocol: UDP
dest_port: 53
description: Detect DNS traffic for readiness validation.
severity: Low
"""


def _write_rule(rules_dir, content: str, name: str = "rule.yaml") -> None:
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / name).write_text(content, encoding="utf-8")


def test_rules_readiness_is_healthy_for_valid_content(tmp_path):
    rules_dir = tmp_path / "rules"
    _write_rule(rules_dir, _VALID_RULE)

    report = RulesEngine(rules_dir).readiness_report()

    assert report == {
        "status": "healthy",
        "files_seen": 1,
        "rules_loaded": 1,
        "load_errors": 0,
        "invalid_rules": 0,
    }


def test_rules_readiness_fails_when_no_rule_files_exist(tmp_path):
    report = RulesEngine(tmp_path / "rules").readiness_report()

    assert report["status"] == "unhealthy"
    assert report["files_seen"] == 0
    assert report["rules_loaded"] == 0


def test_rules_readiness_fails_closed_on_invalid_rule(tmp_path):
    rules_dir = tmp_path / "rules"
    _write_rule(
        rules_dir,
        "name: Invalid\ndescription: Missing a supported condition\nseverity: Low\n",
    )

    report = RulesEngine(rules_dir).readiness_report()

    assert report["status"] == "unhealthy"
    assert report["files_seen"] == 1
    assert report["rules_loaded"] == 0
    assert report["invalid_rules"] == 1


def test_rules_readiness_fails_closed_on_yaml_error(tmp_path):
    rules_dir = tmp_path / "rules"
    _write_rule(rules_dir, "name: [unterminated")

    report = RulesEngine(rules_dir).readiness_report()

    assert report["status"] == "unhealthy"
    assert report["files_seen"] == 1
    assert report["rules_loaded"] == 0
    assert report["load_errors"] == 1


def test_api_readiness_includes_rule_health(tmp_path):
    rules_dir = tmp_path / "rules"
    _write_rule(rules_dir, _VALID_RULE)
    rules_engine = RulesEngine(rules_dir)
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'api.db'}",
        rules_engine=rules_engine,
    )

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 200
    assert response.json()["rules"] == rules_engine.readiness_report()


def test_api_readiness_returns_503_when_rule_loading_is_unhealthy(tmp_path):
    rules_engine = RulesEngine(tmp_path / "empty-rules")
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'api.db'}",
        rules_engine=rules_engine,
    )

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["rules"]["status"] == "unhealthy"
