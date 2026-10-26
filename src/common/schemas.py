"""
Pydantic Data Schemas for KeyShield REST API and Agent Data Structures.
"""

from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List

class SecurityEventSchema(BaseModel):
    event_id: str
    timestamp: str
    agent_id: str
    agent_type: str
    event_type: str
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    severity: str = "INFO"
    confidence: float = 1.0
    source: str = "keyshield-node"
    payload: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class IncidentReportSchema(BaseModel):
    incident_id: str
    risk_score: float
    risk_level: str
    confidence: float
    reasons: List[str] = Field(default_factory=list)
    events: List[Dict[str, Any]] = Field(default_factory=list)
    ai_explanation: Optional[str] = None
    recommended_mitigation: Optional[str] = None
    timestamp: str

class MitigationCommandRequest(BaseModel):
    incident_id: str
    command: str
    explanation: str
    target_pid: Optional[int] = None
    target_path: Optional[str] = None
    confirmed: bool = False

class MitigationCommandResponse(BaseModel):
    incident_id: str
    success: bool
    status: str
    executed_by: str
    timestamp: str
    output: Optional[str] = None
