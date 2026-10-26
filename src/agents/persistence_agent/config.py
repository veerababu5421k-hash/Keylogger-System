"""
Configuration manager for Persistence Monitor Agent.
"""

import os
from typing import Dict, Any, List

class PersistenceAgentConfig:
    def __init__(self, raw_config: Dict[str, Any] = None):
        cfg = (raw_config or {}).get("monitors", {}).get("persistence", {})
        self.enabled: bool = cfg.get("enabled", True)
        self.scan_interval: float = float(cfg.get("scan_interval", 10.0))
        user_home = os.path.expanduser("~")
        self.watch_paths: List[str] = cfg.get("watch_paths", [
            os.path.join(user_home, ".config/autostart"),
            "/etc/xdg/autostart",
            "/etc/systemd/system",
            os.path.join(user_home, ".config/systemd/user"),
            os.path.join(user_home, ".bashrc"),
            "/etc/crontab",
            "/etc/cron.hourly",
            "/etc/cron.daily"
        ])
