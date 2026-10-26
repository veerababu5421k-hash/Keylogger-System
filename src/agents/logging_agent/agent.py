"""
Agent 8: Logging Agent
Maintains structured logs for Process, Keyboard, File, Network, Persistence events, Threat Scores, AI recommendations, and User actions.
Supports log rotation via RotatingFileHandler.
"""

import os
import json
import logging
from logging.handlers import RotatingFileHandler
from typing import Dict, Any
from src.agents.logging_agent.config import LoggingAgentConfig
from src.agents.logging_agent.logger import get_logging_agent_logger

class LoggingAgent:
    def __init__(self, raw_config: Dict[str, Any] = None):
        self.config = LoggingAgentConfig(raw_config)
        self.internal_logger = get_logging_agent_logger()
        self.structured_logger = None
        self._init_structured_logger()

    def _init_structured_logger(self):
        os.makedirs(self.config.log_dir, exist_ok=True)
        log_path = os.path.join(self.config.log_dir, "secureshield.log")
        
        self.structured_logger = logging.getLogger(f"SecureShieldStructuredLog_{id(self)}")
        self.structured_logger.setLevel(logging.INFO)
        
        if not self.structured_logger.handlers:
            handler = RotatingFileHandler(
                log_path,
                maxBytes=self.config.max_bytes,
                backupCount=self.config.backup_count
            )
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.structured_logger.addHandler(handler)
            self.internal_logger.info("Initialized structured logger with rotation at %s", log_path)

    def log_event(self, event_data: Dict[str, Any]):
        """
        Logs event payload to JSON log file.
        """
        try:
            log_entry = json.dumps(event_data)
            self.structured_logger.info(log_entry)
            # Flush handlers to ensure disk write
            for h in self.structured_logger.handlers:
                h.flush()
        except Exception as e:
            self.internal_logger.error("Failed to write log event: %s", e)

    def rotate_logs(self):
        """
        Triggers manual log rotation.
        """
        for handler in self.structured_logger.handlers:
            if isinstance(handler, RotatingFileHandler):
                handler.doRollover()
                self.internal_logger.info("Log rotation executed successfully.")
