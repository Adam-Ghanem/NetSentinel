from fastapi.testclient import TestClient

from api import create_app


def test_api_root_reports_stable_product_identity(tmp_path):
    client = TestClient(create_app(database_url=f"sqlite:///{tmp_path / 'api.db'}"))

    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "status": "operational",
        "service": "NetSentinel API",
        "version": "1.0.0",
    }


def test_liveness_does_not_require_database_access(tmp_path):
    client = TestClient(create_app(database_url=f"sqlite:///{tmp_path / 'api.db'}"))

    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}
