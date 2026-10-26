"""
Configuration manager for Logging Agent.
"""

import os
from typing import Dict, Any

class LoggingAgentConfig:
    def __init__(self, raw_config: Dict[str, Any] = None):
        cfg = (raw_config or {}).get("logging", {})
        self.log_dir: str = cfg.get("log_dir", "logs")
        self.max_bytes: int = int(cfg.get("max_bytes", 5 * 1024 * 1024))  # 5MB
        self.backup_count: int = int(cfg.get("backup_count", 5))
