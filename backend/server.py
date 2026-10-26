"""
KeyShield AI Backend Cloud API Server.
Provides REST API endpoints for multi-device management, event synchronization, incident reports, and mitigation action logs.
"""

import os
import json
import time
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.models import (
    init_db, User, Device, AgentStatusRecord,
    SecurityEventRecord, IncidentRecord, MitigationActionRecord, AuditLogRecord
)

app = FastAPI(title="KeyShield AI Cloud Backend API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Database
db_path = os.path.join(os.path.dirname(__file__), "..", "logs", "keyshield.db")
os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
engine, SessionLocal = init_db(f"sqlite:///{os.path.abspath(db_path)}")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Request Pydantic Models
class DeviceRegisterRequest(BaseModel):
    device_id: str
    node_name: str
    ip_address: Optional[str] = "127.0.0.1"

class TelemetrySyncRequest(BaseModel):
    device_id: str
    timestamp: str
    events_count: int
    events: List[Dict[str, Any]]

class MitigationConfirmRequest(BaseModel):
    incident_id: str
    command: str
    explanation: str
    user_confirmed: bool
    target_pid: Optional[int] = None
    target_path: Optional[str] = None

@app.get("/api/v1/health")
def get_health():
    return {"status": "HEALTHY", "service": "KeyShield Cloud Backend API", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

@app.post("/api/v1/devices/register")
def register_device(req: DeviceRegisterRequest):
    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == req.device_id).first()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if not device:
            device = Device(id=req.device_id, node_name=req.node_name, ip_address=req.ip_address, status="ONLINE", last_seen=now)
            db.add(device)
        else:
            device.node_name = req.node_name
            device.ip_address = req.ip_address
            device.status = "ONLINE"
            device.last_seen = now
        db.commit()
        return {"status": "registered", "device_id": req.device_id}
    finally:
        db.close()

@app.get("/api/v1/devices")
def list_devices():
    db = SessionLocal()
    try:
        devices = db.query(Device).all()
        return [{"id": d.id, "node_name": d.node_name, "ip_address": d.ip_address, "status": d.status, "last_seen": d.last_seen} for d in devices]
    finally:
        db.close()

@app.post("/api/v1/telemetry/sync")
def sync_telemetry(req: TelemetrySyncRequest):
    db = SessionLocal()
    try:
        stored_count = 0
        for evt in req.events:
            event_id = evt.get("event_id") or f"evt_{int(time.time()*1000)}_{stored_count}"
            existing = db.query(SecurityEventRecord).filter(SecurityEventRecord.event_id == event_id).first()
            if not existing:
                record = SecurityEventRecord(
                    event_id=event_id,
                    device_id=req.device_id,
                    agent_type=evt.get("module") or evt.get("agent_type") or "unknown",
                    event_type=evt.get("event_type") or "GENERIC_EVENT",
                    severity=evt.get("level") or evt.get("severity") or "INFO",
                    process_id=evt.get("pid") or evt.get("process_id"),
                    process_name=evt.get("process_name"),
                    payload_json=json.dumps(evt.get("extra_data") or evt.get("payload") or {}),
                    timestamp=evt.get("timestamp") or req.timestamp
                )
                db.add(record)
                stored_count += 1
        
        # Update Device last seen
        dev = db.query(Device).filter(Device.id == req.device_id).first()
        if dev:
            dev.last_seen = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        db.commit()
        return {"status": "synced", "received": len(req.events), "stored": stored_count}
    finally:
        db.close()

@app.get("/api/v1/incidents")
def list_incidents(limit: int = 50):
    db = SessionLocal()
    try:
        incidents = db.query(IncidentRecord).order_by(IncidentRecord.id.desc()).limit(limit).all()
        return [
            {
                "incident_id": inc.incident_id,
                "device_id": inc.device_id,
                "risk_score": inc.risk_score,
                "risk_level": inc.risk_level,
                "confidence": inc.confidence,
                "reasons": json.loads(inc.reasons_json or "[]"),
                "ai_explanation": inc.ai_explanation,
                "recommended_mitigation": inc.recommended_mitigation,
                "timestamp": inc.timestamp
            } for inc in incidents
        ]
    finally:
        db.close()

@app.post("/api/v1/mitigation/confirm")
def confirm_mitigation(req: MitigationConfirmRequest):
    db = SessionLocal()
    try:
        action = MitigationActionRecord(
            incident_id=req.incident_id,
            command=req.command,
            explanation=req.explanation,
            target_pid=req.target_pid,
            target_path=req.target_path,
            user_confirmed=req.user_confirmed,
            status="EXECUTED" if req.user_confirmed else "REJECTED",
            output="Executed defensively with user approval." if req.user_confirmed else "Execution cancelled by user."
        )
        db.add(action)

        # Audit Log
        audit = AuditLogRecord(
            action="MITIGATION_DECISION",
            performed_by="user",
            details_json=json.dumps({
                "incident_id": req.incident_id,
                "command": req.command,
                "confirmed": req.user_confirmed
            })
        )
        db.add(audit)
        db.commit()
        return {"status": "recorded", "action_id": action.id, "confirmed": req.user_confirmed}
    finally:
        db.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
