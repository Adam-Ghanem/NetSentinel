from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
import datetime
from app.database import DatabaseManager
from app.config import Config

app = FastAPI(title="NetSentinel Elite API", version="2.0.0")
db = DatabaseManager()

class AlertSchema(BaseModel):
    alert_id: str
    timestamp: datetime.datetime
    source_ip: str
    dest_ip: str
    alert_type: str
    severity: str
    description: str
    mitre_attack: Optional[str]

@app.get("/")
def read_root():
    return {"status": "operational", "version": "2.0.0", "engine": "NetSentinel Elite"}

@app.get("/alerts", response_model=List[AlertSchema])
def get_alerts(limit: int = 100):
    alerts = db.get_alerts(limit=limit)
    return alerts

@app.get("/stats")
def get_system_stats():
    packets = db.get_packets(limit=1000)
    alerts = db.get_alerts(limit=1000)
    return {
        "total_packets_processed": len(packets),
        "total_alerts_generated": len(alerts),
        "critical_alerts": len([a for a in alerts if a.severity == "Critical"])
    }

@app.post("/soar/block/{ip}")
def block_ip(ip: str):
    # This would call the SOAR manager
    return {"message": f"Block request for {ip} received and queued."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
