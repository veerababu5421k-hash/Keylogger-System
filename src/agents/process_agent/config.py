"""
Configuration manager for Process Monitor Agent.
"""

from typing import Dict, Any

class ProcessAgentConfig:
    def __init__(self, raw_config: Dict[str, Any] = None):
        cfg = (raw_config or {}).get("monitors", {}).get("process", {})
        self.enabled: bool = cfg.get("enabled", True)
        self.scan_interval: float = float(cfg.get("scan_interval", 3.0))
        self.cpu_threshold: float = float(cfg.get("cpu_threshold", 75.0))
        self.memory_threshold: float = float(cfg.get("memory_threshold", 150.0))
        self.suspicious_cmdlines = cfg.get("suspicious_cmdlines", [
            "keylogger", "logkeys", "pykeylogger", "xinput", "evdev", "pynput"
        ])
