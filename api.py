import datetime
from typing import Annotated

from fastapi import FastAPI, Query, Response, status
from pydantic import BaseModel, ConfigDict

from app.database import DatabaseManager

API_VERSION = "1.0.0"
_SAMPLE_LIMIT = 1000


class AlertSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    alert_id: str
    timestamp: datetime.datetime | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    alert_type: str
    severity: str
    description: str | None = None
    mitre_attack: str | None = None


class StatsSchema(BaseModel):
    sampled_packets: int
    sampled_alerts: int
    sampled_critical_alerts: int
    sample_limit: int


def create_app(
    database_url: str | None = None,
    database_manager: DatabaseManager | None = None,
) -> FastAPI:
    if database_url is not None and database_manager is not None:
        raise ValueError("provide database_url or database_manager, not both")

    application = FastAPI(title="NetSentinel API", version=API_VERSION)
    database = database_manager or (
        DatabaseManager(database_url) if database_url else DatabaseManager()
    )
    application.state.database = database

    @application.get("/")
    def read_root():
        return {
            "status": "operational",
            "service": "NetSentinel API",
            "version": API_VERSION,
        }

    @application.get("/health/live")
    def liveness():
        return {"status": "alive"}

    @application.get("/health/ready")
    def readiness(response: Response):
        database_report = database.database_health()
        ready = database_report["status"] == "healthy"
        if not ready:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "ready" if ready else "not_ready",
            "database": database_report,
        }

    def read_alerts(limit: int):
        return database.get_alerts(limit=limit)

    @application.get("/api/v1/alerts", response_model=list[AlertSchema])
    def get_versioned_alerts(limit: Annotated[int, Query(ge=1, le=1000)] = 100):
        return read_alerts(limit)

    @application.get("/alerts", response_model=list[AlertSchema], deprecated=True)
    def get_legacy_alerts(limit: Annotated[int, Query(ge=1, le=1000)] = 100):
        return read_alerts(limit)

    def read_stats():
        packets = database.get_packets(limit=_SAMPLE_LIMIT)
        alerts = database.get_alerts(limit=_SAMPLE_LIMIT)
        return {
            "sampled_packets": len(packets),
            "sampled_alerts": len(alerts),
            "sampled_critical_alerts": sum(
                alert.severity == "Critical" for alert in alerts
            ),
            "sample_limit": _SAMPLE_LIMIT,
        }

    @application.get("/api/v1/stats", response_model=StatsSchema)
    def get_versioned_stats():
        return read_stats()

    @application.get("/stats", response_model=StatsSchema, deprecated=True)
    def get_legacy_stats():
        return read_stats()

    return application


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
