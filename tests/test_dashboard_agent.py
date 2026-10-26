"""
Unit tests for Agent 9: Dashboard Agent.
"""

import unittest
from src.agents.dashboard_agent.agent import DashboardAgent
from src.orchestrator.orchestrator import Orchestrator

class TestDashboardAgent(unittest.TestCase):
    def setUp(self):
        self.orchestrator = Orchestrator()
        self.agent = DashboardAgent(orchestrator=self.orchestrator)

    def test_routes_registered(self):
        routes = [route.path for route in self.agent.app.routes]
        self.assertIn("/api/status", routes)
        self.assertIn("/api/monitors", routes)
        self.assertIn("/api/alerts", routes)
        self.assertIn("/api/chat", routes)
        self.assertIn("/api/control", routes)

if __name__ == "__main__":
    unittest.main()
