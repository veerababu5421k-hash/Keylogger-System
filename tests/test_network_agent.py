"""
Unit tests for Agent 5: Network Monitor Agent.
"""

import unittest
from src.orchestrator.event_bus import EventBus
from src.agents.network_agent.agent import NetworkAgent

class TestNetworkAgent(unittest.TestCase):
    def setUp(self):
        self.bus = EventBus()
        self.agent = NetworkAgent(event_bus=self.bus)

    def test_agent_lifecycle(self):
        self.assertFalse(self.agent.is_alive())
        self.agent.start()
        self.assertTrue(self.agent.is_alive())
        self.agent.stop()
        self.agent.join(timeout=1.0)
        self.assertFalse(self.agent.running)

    def test_inspect_network_connections(self):
        self.agent._inspect_network_connections()
        self.assertIsInstance(self.agent._reported_conns, set)

if __name__ == "__main__":
    unittest.main()
