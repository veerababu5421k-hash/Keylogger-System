"""
Configuration manager for Dashboard Agent.
"""

from typing import Dict, Any

class DashboardAgentConfig:
    def __init__(self, raw_config: Dict[str, Any] = None):
        cfg = (raw_config or {}).get("dashboard", {})
        self.host: str = cfg.get("host", "0.0.0.0")
        self.port: int = int(cfg.get("port", 8000))
