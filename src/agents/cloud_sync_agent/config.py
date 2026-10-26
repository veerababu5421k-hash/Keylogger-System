"""
Configuration handler for Cloud Synchronization Agent.
"""

from typing import Dict, Any

class CloudSyncAgentConfig:
    def __init__(self, raw_config: Dict[str, Any] = None):
        self.raw_config = raw_config or {}
        cloud_cfg = self.raw_config.get("cloud", {})
        self.enabled: bool = cloud_cfg.get("enabled", True)
        self.endpoint: str = cloud_cfg.get("endpoint", "http://localhost:8000/api/v1/telemetry/sync")
        self.sync_interval: float = cloud_cfg.get("sync_interval", 15.0)
        self.batch_size: int = cloud_cfg.get("batch_size", 20)
        self.api_key: str = cloud_cfg.get("api_key", "secureshield-dev-key")
