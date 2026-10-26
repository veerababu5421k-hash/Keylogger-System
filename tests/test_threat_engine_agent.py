"""
Unit tests for Agent 6: Threat Engine Agent.
"""

import unittest
from src.agents.threat_engine_agent.agent import ThreatEngineAgent

class TestThreatEngineAgent(unittest.TestCase):
    def setUp(self):
        self.agent = ThreatEngineAgent()

    def test_evaluate_keyboard_event(self):
        event = {
            "source_agent": "keyboard_agent",
            "event_type": "SUSPICIOUS_KEYBOARD_HOOK",
            "module": "keyboard",
            "pid": 1234,
            "message": "Raw keyboard hook opened."
        }
        assessment = self.agent.evaluate_event(event)
        self.assertEqual(assessment["level"], "CRITICAL")
        self.assertGreaterEqual(assessment["risk_score"], 80.0)
        self.assertEqual(assessment["pid"], 1234)

    def test_evaluate_process_event(self):
        event = {
            "source_agent": "process_agent",
            "event_type": "SUSPICIOUS_PROCESS",
            "module": "process",
            "pid": 5678,
            "message": "Keylogger process detected."
        }
        assessment = self.agent.evaluate_event(event)
        self.assertIn("level", assessment)
        self.assertEqual(assessment["pid"], 5678)

if __name__ == "__main__":
    unittest.main()
