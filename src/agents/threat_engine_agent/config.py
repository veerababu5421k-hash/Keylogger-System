"""
Configuration manager for Threat Engine Agent.
"""

from typing import Dict, Any

class ThreatEngineAgentConfig:
    def __init__(self, raw_config: Dict[str, Any] = None):
        cfg = (raw_config or {}).get("threat_engine", {})
        self.critical_threshold: float = float(cfg.get("critical_threshold", 80.0))
        self.high_threshold: float = float(cfg.get("high_threshold", 60.0))
        self.medium_threshold: float = float(cfg.get("medium_threshold", 40.0))
