"""
Configuration manager for AI Security Analyst Agent.
"""

import os
from typing import Dict, Any

class AIAnalystAgentConfig:
    def __init__(self, raw_config: Dict[str, Any] = None):
        cfg = (raw_config or {}).get("ai_analyst", {})
        self.model_name: str = cfg.get("model_name", "gemini-2.5-flash")
        self.api_key: str = os.environ.get("GEMINI_API_KEY", cfg.get("api_key", ""))
        self.offline_mode: bool = cfg.get("offline_mode", False)
