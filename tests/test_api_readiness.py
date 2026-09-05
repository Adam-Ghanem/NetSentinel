from fastapi.testclient import TestClient

from api import create_app


def test_readiness_reports_database_health(tmp_path):
    client = TestClient(create_app(database_url=f"sqlite:///{tmp_path / 'api-readiness.db'}"))

    response = client.get("/health/ready")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload["database"]["status"] == "healthy"
    assert payload["database"]["connectivity"] == "ok"
    assert payload["database"]["schema"] == "ok"
