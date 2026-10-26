"""
Agent 3: Persistence Monitor Agent
Monitors startup entries, systemd units, autostart desktop files, and crontabs.
Sends Persistence Event ONLY to Orchestrator via EventBus.
"""

import os
import time
import threading
from typing import Dict, Any, Set
from src.agents.persistence_agent.config import PersistenceAgentConfig
from src.agents.persistence_agent.logger import get_persistence_logger

class PersistenceAgent(threading.Thread):
    def __init__(self, raw_config: Dict[str, Any] = None, event_bus = None):
        super().__init__(daemon=True, name="PersistenceAgent")
        self.config = PersistenceAgentConfig(raw_config)
        self.logger = get_persistence_logger()
        self.event_bus = event_bus
        self.running = False
        self._known_entries: Set[str] = set()

    def start(self):
        self.logger.info("Initializing Persistence Monitor Agent...")
        self.running = True
        self._initial_snapshot()
        super().start()

    def stop(self):
        self.logger.info("Stopping Persistence Monitor Agent...")
        self.running = False

    def run(self):
        self.logger.info("Persistence Monitor Agent loop running.")
        while self.running:
            try:
                self._check_persistence_entries()
            except Exception as e:
                self.logger.error("Error inspecting persistence: %s", e)
            time.sleep(self.config.scan_interval)

    def _initial_snapshot(self):
        for path in self.config.watch_paths:
            if os.path.isdir(path):
                try:
                    for root, _, files in os.walk(path):
                        for f in files:
                            self._known_entries.add(os.path.join(root, f))
                except Exception:
                    pass
            elif os.path.isfile(path):
                self._known_entries.add(path)

    def _check_persistence_entries(self):
        current_entries: Set[str] = set()
        for path in self.config.watch_paths:
            if os.path.isdir(path):
                try:
                    for root, _, files in os.walk(path):
                        for f in files:
                            current_entries.add(os.path.join(root, f))
                except Exception:
                    pass
            elif os.path.isfile(path):
                current_entries.add(path)

        new_entries = current_entries - self._known_entries
        for new_item in new_entries:
            event = {
                "source_agent": "persistence_agent",
                "event_type": "NEW_PERSISTENCE_ENTRY",
                "module": "persistence",
                "target_path": new_item,
                "message": f"New startup persistence mechanism detected at: {new_item}",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            self.logger.warning("New persistence mechanism registered: %s", new_item)
            if self.event_bus:
                self.event_bus.publish(event)

        self._known_entries = current_entries
