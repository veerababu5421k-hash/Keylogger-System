"""
Unit tests for Agent 2: Keyboard Activity Agent.
"""

import unittest
from src.orchestrator.event_bus import EventBus
from src.agents.keyboard_agent.agent import KeyboardAgent

class TestKeyboardAgent(unittest.TestCase):
    def setUp(self):
        self.bus = EventBus()
        self.agent = KeyboardAgent(event_bus=self.bus)

    def test_agent_lifecycle(self):
        self.assertFalse(self.agent.is_alive())
        self.agent.start()
        self.assertTrue(self.agent.is_alive())
        self.agent.stop()
        self.agent.join(timeout=1.0)
        self.assertFalse(self.agent.running)

    def test_inspect_descriptors(self):
        # Executes descriptor check without raising exception
        self.agent._inspect_input_file_descriptors()

if __name__ == "__main__":
    unittest.main()
