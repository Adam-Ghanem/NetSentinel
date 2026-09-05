from fastapi.testclient import TestClient

from api import create_app


def test_versioned_stats_are_explicitly_sampled(tmp_path):
    application = create_app(database_url=f"sqlite:///{tmp_path / 'api-stats.db'}")
    database = application.state.database
    database.add_packet({"protocol": "TCP", "packet_size": 60})
    database.insert_alert(
        {
            "alert_id": "API-STATS-001",
            "alert_type": "Port scan",
            "severity": "Critical",
        }
    )
    client = TestClient(application)

    response = client.get("/api/v1/stats")

    assert response.status_code == 200
    assert response.json() == {
        "sampled_packets": 1,
        "sampled_alerts": 1,
        "sampled_critical_alerts": 1,
        "sample_limit": 1000,
    }


def test_legacy_stats_route_remains_available_but_deprecated(tmp_path):
    application = create_app(database_url=f"sqlite:///{tmp_path / 'api-legacy-stats.db'}")
    client = TestClient(application)

    response = client.get("/stats")

    assert response.status_code == 200
    operation = application.openapi()["paths"]["/stats"]["get"]
    assert operation["deprecated"] is True
