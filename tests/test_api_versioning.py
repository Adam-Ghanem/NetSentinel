from fastapi.testclient import TestClient

from api import create_app


def test_versioned_alert_route_returns_persisted_alerts(tmp_path):
    application = create_app(database_url=f"sqlite:///{tmp_path / 'api-alerts.db'}")
    application.state.database.insert_alert(
        {
            "alert_id": "API-ALERT-001",
            "alert_type": "Port scan",
            "severity": "High",
            "description": "Observed scan activity",
        }
    )
    client = TestClient(application)

    response = client.get("/api/v1/alerts")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["alert_id"] == "API-ALERT-001"
    assert payload[0]["severity"] == "High"


def test_versioned_alert_route_rejects_unbounded_limits(tmp_path):
    client = TestClient(create_app(database_url=f"sqlite:///{tmp_path / 'api-bounds.db'}"))

    assert client.get("/api/v1/alerts?limit=0").status_code == 422
    assert client.get("/api/v1/alerts?limit=1001").status_code == 422
