"""
Unit tests for Agent 3: Persistence Monitor Agent.
"""

import unittest
from src.orchestrator.event_bus import EventBus
from src.agents.persistence_agent.agent import PersistenceAgent

class TestPersistenceAgent(unittest.TestCase):
    def setUp(self):
        self.bus = EventBus()
        self.agent = PersistenceAgent(event_bus=self.bus)

    def test_agent_lifecycle(self):
        self.assertFalse(self.agent.is_alive())
        self.agent.start()
        self.assertTrue(self.agent.is_alive())
        self.agent.stop()
        self.agent.join(timeout=1.0)
        self.assertFalse(self.agent.running)

    def test_check_persistence_entries(self):
        self.agent._check_persistence_entries()
        self.assertIsInstance(self.agent._known_entries, set)

if __name__ == "__main__":
    unittest.main()
