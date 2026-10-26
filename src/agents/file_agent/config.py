"""
Configuration manager for File Activity Agent.
"""

import os
from typing import Dict, Any, List

class FileAgentConfig:
    def __init__(self, raw_config: Dict[str, Any] = None):
        cfg = (raw_config or {}).get("monitors", {}).get("file", {})
        self.enabled: bool = cfg.get("enabled", True)
        self.scan_interval: float = float(cfg.get("scan_interval", 3.0))
        user_home = os.path.expanduser("~")
        self.sensitive_dirs: List[str] = cfg.get("sensitive_dirs", [
            "/tmp",
            "/dev/shm",
            os.path.join(user_home, ".local")
        ])
        self.suspicious_file_extensions: List[str] = cfg.get("suspicious_file_extensions", [
            ".kl", ".keystrokes", ".klog", ".log.txt", ".rawlog"
        ])
