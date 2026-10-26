"""
Unit tests for Agent 7: AI Security Analyst Agent.
"""

import unittest
from src.agents.ai_analyst_agent.agent import AIAnalystAgent

class TestAIAnalystAgent(unittest.TestCase):
    def setUp(self):
        self.agent = AIAnalystAgent({"ai_analyst": {"offline_mode": True}})

    def test_analyze_threat(self):
        alert_data = {
            "module": "keyboard",
            "pid": 4321,
            "message": "Keylogger attached."
        }
        res = self.agent.analyze_threat(alert_data)
        self.assertIn("incident_analysis", res)
        self.assertIn("mitigation_command", res)
        self.assertIn("4321", res["mitigation_command"])

    def test_chat_response(self):
        ctx = {"module": "network", "pid": 9876, "extra_data": {"destination_ip": "10.0.0.1"}}
        reply = self.agent.generate_chat_response("How to mitigate this network threat?", ctx)
        self.assertTrue("iptables" in reply.lower() or "kill" in reply.lower())

    def test_daily_report(self):
        report = self.agent.generate_daily_report([{"level": "CRITICAL", "risk_score": 90.0}])
        self.assertIn("Daily Security Summary Report", report)

if __name__ == "__main__":
    unittest.main()
