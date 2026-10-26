"""
Agent 4: File Activity Agent
Monitors sensitive directories (/tmp, /dev/shm) for suspicious keystroke log creation and modifications.
Sends File Event ONLY to Orchestrator via EventBus.
"""

import os
import time
import threading
from typing import Dict, Any, Set
from src.agents.file_agent.config import FileAgentConfig
from src.agents.file_agent.logger import get_file_logger

class FileAgent(threading.Thread):
    def __init__(self, raw_config: Dict[str, Any] = None, event_bus = None):
        super().__init__(daemon=True, name="FileAgent")
        self.config = FileAgentConfig(raw_config)
        self.logger = get_file_logger()
        self.event_bus = event_bus
        self.running = False
        self._known_files: Set[str] = set()

    def start(self):
        self.logger.info("Initializing File Activity Agent...")
        self.running = True
        self._take_snapshot()
        super().start()

    def stop(self):
        self.logger.info("Stopping File Activity Agent...")
        self.running = False

    def run(self):
        self.logger.info("File Activity Agent loop running.")
        while self.running:
            try:
                self._scan_sensitive_directories()
            except Exception as e:
                self.logger.error("Error monitoring file activity: %s", e)
            time.sleep(self.config.scan_interval)

    def _take_snapshot(self):
        for sdir in self.config.sensitive_dirs:
            if os.path.exists(sdir):
                try:
                    for root, _, files in os.walk(sdir):
                        for f in files:
                            self._known_files.add(os.path.join(root, f))
                except Exception:
                    pass

    def _scan_sensitive_directories(self):
        current_files: Set[str] = set()
        for sdir in self.config.sensitive_dirs:
            if os.path.exists(sdir):
                try:
                    for root, _, files in os.walk(sdir):
                        for f in files:
                            filepath = os.path.join(root, f)
                            current_files.add(filepath)
                            
                            # Check suspicious file patterns
                            fname_lower = f.lower()
                            if any(fname_lower.endswith(ext) or "keylog" in fname_lower or "keystroke" in fname_lower 
                                   for ext in self.config.suspicious_file_extensions):
                                if filepath not in self._known_files:
                                    event = {
                                        "source_agent": "file_agent",
                                        "event_type": "SUSPICIOUS_FILE_CREATED",
                                        "module": "file",
                                        "filepath": filepath,
                                        "message": f"Suspicious keystroke log file created in temporary directory: {filepath}",
                                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                                    }
                                    self.logger.warning("Suspicious file detected: %s", filepath)
                                    if self.event_bus:
                                        self.event_bus.publish(event)
                except Exception:
                    pass
        self._known_files = current_files
