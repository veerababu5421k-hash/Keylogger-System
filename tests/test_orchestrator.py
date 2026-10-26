"""
Unit tests for central Orchestrator.
"""

import unittest
from src.orchestrator.orchestrator import Orchestrator

class TestOrchestrator(unittest.TestCase):
    def setUp(self):
        self.orchestrator = Orchestrator()

    def test_orchestrator_initialization(self):
        self.assertIsNotNone(self.orchestrator.event_bus)
        self.assertIsNotNone(self.orchestrator.system_state)
        self.assertIsNotNone(self.orchestrator.threat_engine_agent)
        self.assertIsNotNone(self.orchestrator.ai_analyst_agent)
        self.assertIsNotNone(self.orchestrator.logging_agent)

    def test_telemetry_event_pipeline(self):
        event = {
            "source_agent": "keyboard_agent",
            "event_type": "SUSPICIOUS_KEYBOARD_HOOK",
            "module": "keyboard",
            "pid": 8888,
            "message": "Raw keyboard hook attached."
        }
        self.orchestrator.handle_telemetry_event(event)

        alerts = self.orchestrator.system_state.get_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["pid"], 8888)
        self.assertIn("ai_insights", alerts[0])
        self.assertIn("mitigation_command", alerts[0]["ai_insights"])

if __name__ == "__main__":
    unittest.main()
