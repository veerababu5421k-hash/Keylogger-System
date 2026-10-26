"""
Agent 6: Threat Engine Agent
Receives raw telemetry events from the Orchestrator.
Calculates Threat Score, Threat Level, Risk Assessment, and Detection Confidence.
Returns enriched threat analysis back to the Orchestrator.
"""

import time
from typing import Dict, Any
from src.agents.threat_engine_agent.config import ThreatEngineAgentConfig
from src.agents.threat_engine_agent.logger import get_threat_engine_logger

class ThreatEngineAgent:
    def __init__(self, raw_config: Dict[str, Any] = None):
        self.config = ThreatEngineAgentConfig(raw_config)
        self.logger = get_threat_engine_logger()

    def evaluate_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate telemetry event and return detailed risk score and assessment.
        """
        module = event.get("module", "unknown")
        event_type = event.get("event_type", "UNKNOWN")

        # Base scoring weights by event type
        weights = {
            "SUSPICIOUS_KEYBOARD_HOOK": 85.0,
            "SUSPICIOUS_PROCESS": 75.0,
            "SUSPICIOUS_NETWORK_CONNECTION": 88.0,
            "SUSPICIOUS_FILE_CREATED": 70.0,
            "NEW_PERSISTENCE_ENTRY": 65.0
        }

        score = weights.get(event_type, 50.0)

        # Determine Threat Level
        if score >= self.config.critical_threshold:
            level = "CRITICAL"
            confidence = 0.95
        elif score >= self.config.high_threshold:
            level = "WARNING"
            confidence = 0.85
        elif score >= self.config.medium_threshold:
            level = "MEDIUM"
            confidence = 0.70
        else:
            level = "LOW"
            confidence = 0.50

        assessment = {
            "timestamp": event.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "level": level,
            "module": module,
            "risk_score": score,
            "confidence_score": confidence,
            "pid": event.get("pid"),
            "message": event.get("message") or f"Detected behavioral anomaly in {module}",
            "extra_data": {
                "event_type": event_type,
                "process_name": event.get("process_name"),
                "cmdline": event.get("cmdline"),
                "destination_ip": event.get("destination_ip"),
                "filepath": event.get("filepath"),
                "target_path": event.get("target_path")
            }
        }

        self.logger.info("Evaluated %s: Threat Score=%.1f Level=%s", event_type, score, level)
        return assessment
