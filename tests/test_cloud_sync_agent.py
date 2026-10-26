"""
Unit tests for Cloud Synchronization Agent.
"""

import unittest
from src.agents.cloud_sync_agent.agent import CloudSyncAgent

class TestCloudSyncAgent(unittest.TestCase):
    def setUp(self):
        self.config = {
            "agent": {"node_name": "test-node"},
            "cloud": {
                "enabled": True,
                "endpoint": "http://localhost:9999/invalid",  # Intentional offline endpoint
                "sync_interval": 0.1,
                "batch_size": 5
            }
        }
        self.agent = CloudSyncAgent(self.config)

    def test_event_sanitization_removes_sensitive_keys(self):
        raw_event = {
            "event_type": "TEST_EVENT",
            "payload": {
                "raw_keystrokes": "secret_password",
                "password": "my_password",
                "safe_pid": 1234
            }
        }
        sanitized = self.agent._sanitize_event(raw_event)
        self.assertNotIn("raw_keystrokes", sanitized["payload"])
        self.assertNotIn("password", sanitized["payload"])
        self.assertEqual(sanitized["payload"]["safe_pid"], 1234)

    def test_offline_enqueueing(self):
        event = {"event_type": "TEST", "payload": {}}
        self.agent.enqueue_telemetry(event)
        self.assertEqual(self.agent.event_queue.qsize(), 1)

if __name__ == "__main__":
    unittest.main()
