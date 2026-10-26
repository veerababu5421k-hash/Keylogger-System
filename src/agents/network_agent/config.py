"""
Configuration manager for Network Monitor Agent.
"""

from typing import Dict, Any, List

class NetworkAgentConfig:
    def __init__(self, raw_config: Dict[str, Any] = None):
        cfg = (raw_config or {}).get("monitors", {}).get("network", {})
        self.enabled: bool = cfg.get("enabled", True)
        self.scan_interval: float = float(cfg.get("scan_interval", 4.0))
        self.blacklisted_ips: List[str] = cfg.get("blacklisted_ips", [
            "185.220.101.4", "45.227.254.12", "192.168.1.250"
        ])
        self.suspicious_ports: List[int] = cfg.get("suspicious_ports", [
            4444, 5555, 6666, 8888, 9999, 1337
        ])
