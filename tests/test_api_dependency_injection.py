from fastapi.testclient import TestClient

from api import create_app
from app.database import DatabaseManager


def test_readiness_returns_503_for_incomplete_schema(tmp_path):
    database = DatabaseManager(
        f"sqlite:///{tmp_path / 'api-incomplete.db'}",
        auto_create_schema=False,
    )
    client = TestClient(create_app(database_manager=database))

    response = client.get("/health/ready")

    assert response.status_code == 503
    payload = response.json()
    assert payload["status"] == "not_ready"
    assert payload["database"]["status"] == "degraded"
    assert payload["database"]["schema"] == "incomplete"
