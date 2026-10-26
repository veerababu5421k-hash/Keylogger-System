"""
Unit tests for Agent 1: Process Monitor Agent.
"""

import unittest
from src.orchestrator.event_bus import EventBus
from src.agents.process_agent.agent import ProcessAgent

class TestProcessAgent(unittest.TestCase):
    def setUp(self):
        self.bus = EventBus()
        self.agent = ProcessAgent(event_bus=self.bus)

    def test_agent_lifecycle(self):
        self.assertFalse(self.agent.is_alive())
        self.agent.start()
        self.assertTrue(self.agent.is_alive())
        self.agent.stop()
        self.agent.join(timeout=1.0)
        self.assertFalse(self.agent.running)

    def test_process_scan(self):
        self.agent._scan_processes()
        # Ensure scan completes without exception and known_pids populated
        self.assertGreater(len(self.agent._known_pids), 0)

if __name__ == "__main__":
    unittest.main()
