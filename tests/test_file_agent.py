"""
Unit tests for Agent 4: File Activity Agent.
"""

import unittest
from src.orchestrator.event_bus import EventBus
from src.agents.file_agent.agent import FileAgent

class TestFileAgent(unittest.TestCase):
    def setUp(self):
        self.bus = EventBus()
        self.agent = FileAgent(event_bus=self.bus)

    def test_agent_lifecycle(self):
        self.assertFalse(self.agent.is_alive())
        self.agent.start()
        self.assertTrue(self.agent.is_alive())
        self.agent.stop()
        self.agent.join(timeout=1.0)
        self.assertFalse(self.agent.running)

    def test_scan_sensitive_directories(self):
        self.agent._scan_sensitive_directories()
        self.assertIsInstance(self.agent._known_files, set)

if __name__ == "__main__":
    unittest.main()
