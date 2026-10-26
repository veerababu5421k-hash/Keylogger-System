"""
Unit tests for Agent 10: Cron Automation Agent.
"""

import unittest
from src.agents.cron_agent.agent import CronAgent
from src.orchestrator.orchestrator import Orchestrator

class TestCronAgent(unittest.TestCase):
    def setUp(self):
        self.orchestrator = Orchestrator()
        self.agent = CronAgent(orchestrator=self.orchestrator)

    def test_scheduled_scan_trigger(self):
        self.agent._run_scheduled_scan()
        logs = self.orchestrator.system_state.get_logs()
        self.assertTrue(any("scan" in l.lower() for l in logs))

    def test_daily_report_trigger(self):
        self.agent._generate_scheduled_report()
        logs = self.orchestrator.system_state.get_logs()
        self.assertTrue(any("daily report" in l.lower() for l in logs))

if __name__ == "__main__":
    unittest.main()
