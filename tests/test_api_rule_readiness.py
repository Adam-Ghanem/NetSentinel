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


def _healthy_rules_engine(tmp_path) -> RulesEngine:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "dns.yaml").write_text(_VALID_RULE, encoding="utf-8")
    return RulesEngine(rules_dir)


def test_api_readiness_includes_rule_health(tmp_path):
    rules_engine = _healthy_rules_engine(tmp_path)
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
