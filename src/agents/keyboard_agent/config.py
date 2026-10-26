"""
Configuration manager for Keyboard Activity Agent.
"""

from typing import Dict, Any

class KeyboardAgentConfig:
    def __init__(self, raw_config: Dict[str, Any] = None):
        cfg = (raw_config or {}).get("monitors", {}).get("keyboard", {})
        self.enabled: bool = cfg.get("enabled", True)
        self.scan_interval: float = float(cfg.get("scan_interval", 2.0))
        self.keystroke_rate_threshold: float = float(cfg.get("keystroke_rate_threshold", 20.0))
        self.input_devices_path: str = cfg.get("input_devices_path", "/dev/input")
