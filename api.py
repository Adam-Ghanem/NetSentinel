from fastapi import FastAPI, Query
from pydantic import BaseModel, ConfigDict
from typing import List, Optional
import datetime
from app.database import DatabaseManager

app = FastAPI(title="NetSentinel API", version="0.2.0")
db = DatabaseManager()

class AlertSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    alert_id: str
    timestamp: datetime.datetime
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    alert_type: str
    severity: str
    description: Optional[str] = None
    mitre_attack: Optional[str] = None

@app.get("/")
def read_root():
    return {"status": "operational", "version": "0.2.0", "engine": "NetSentinel"}

@app.get("/alerts", response_model=List[AlertSchema])
def get_alerts(limit: int = Query(default=100, ge=1, le=1000)):
    alerts = db.get_alerts(limit=limit)
    return alerts

@app.get("/stats")
def get_system_stats():
    return {
        "total_packets_processed": db.count_packets(),
        "total_alerts_generated": db.count_alerts(),
        "critical_alerts": db.count_alerts(severity="Critical"),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
