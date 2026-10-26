"""
Standardized Security Event Schema for SecureShield AI.
Every agent produces events conforming to this schema for ingestion by the Orchestrator.
"""

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional

@dataclass
class SecurityEvent:
    event_type: str
    agent_type: str
    agent_id: str = "agent-unknown"
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence: float = 1.0  # 0.0 to 1.0
    source: str = "secureshield-node"
    payload: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert SecurityEvent instance to a standard dictionary.
        """
        data = asdict(self)
        # Ensure backward compatibility with existing dictionary fields
        data["module"] = self.agent_type
        data["pid"] = self.process_id
        data["source_agent"] = self.agent_id
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        """
        Factory method to reconstruct SecurityEvent from dictionary.
        """
        return cls(
            event_id=data.get("event_id") or str(uuid.uuid4()),
            timestamp=data.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            agent_id=data.get("agent_id") or data.get("source_agent", "agent-unknown"),
            agent_type=data.get("agent_type") or data.get("module", "unknown"),
            event_type=data.get("event_type", "GENERIC_EVENT"),
            process_id=data.get("process_id") or data.get("pid"),
            process_name=data.get("process_name"),
            severity=data.get("severity") or data.get("level", "INFO"),
            confidence=float(data.get("confidence", 1.0)),
            source=data.get("source", "secureshield-node"),
            payload=data.get("payload") or data.get("extra_data") or {},
            metadata=data.get("metadata", {})
        )
