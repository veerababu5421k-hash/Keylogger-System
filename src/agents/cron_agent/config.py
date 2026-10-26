"""
Configuration manager for Cron Automation Agent.
"""

from typing import Dict, Any

class CronAgentConfig:
    def __init__(self, raw_config: Dict[str, Any] = None):
        cfg = (raw_config or {}).get("cron", {})
        self.scan_interval_sec: float = float(cfg.get("scan_interval_sec", 60.0))
        self.report_interval_sec: float = float(cfg.get("report_interval_sec", 300.0))
        self.cloud_sync_enabled: bool = bool(cfg.get("cloud_sync_enabled", False))
