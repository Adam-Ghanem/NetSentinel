import datetime
from typing import Annotated

from fastapi import FastAPI, Query
from pydantic import BaseModel, ConfigDict

from app.database import DatabaseManager

API_VERSION = "1.0.0"


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


def create_app(database_url: str | None = None) -> FastAPI:
    application = FastAPI(title="NetSentinel API", version=API_VERSION)
    database = DatabaseManager(database_url) if database_url else DatabaseManager()
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

    @application.get("/alerts", response_model=list[AlertSchema], deprecated=True)
    def get_alerts(limit: Annotated[int, Query(ge=1, le=1000)] = 100):
        return database.get_alerts(limit=limit)

    @application.get("/stats")
    def get_system_stats():
        packets = database.get_packets(limit=1000)
        alerts = database.get_alerts(limit=1000)
        return {
            "sampled_packets": len(packets),
            "sampled_alerts": len(alerts),
            "sampled_critical_alerts": sum(
                alert.severity == "Critical" for alert in alerts
            ),
            "sample_limit": 1000,
        }

    return application


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
