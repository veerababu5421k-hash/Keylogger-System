"""
Unit tests for Agent 8: Logging Agent.
"""

import os
import shutil
import unittest
from src.agents.logging_agent.agent import LoggingAgent

class TestLoggingAgent(unittest.TestCase):
    def setUp(self):
        self.test_log_dir = "logs_test_tmp"
        self.agent = LoggingAgent({"logging": {"log_dir": self.test_log_dir}})

    def tearDown(self):
        if os.path.exists(self.test_log_dir):
            shutil.rmtree(self.test_log_dir, ignore_errors=True)

    def test_log_event(self):
        event = {"event_type": "TEST_EVENT", "status": "OK"}
        self.agent.log_event(event)
        log_file = os.path.join(self.test_log_dir, "secureshield.log")
        self.assertTrue(os.path.exists(log_file))

    def test_rotate_logs(self):
        self.agent.rotate_logs()

if __name__ == "__main__":
    unittest.main()
