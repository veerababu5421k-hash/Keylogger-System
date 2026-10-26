"""
Integration tests for system resilience and graceful degradation.
Verifies system operation when AI or Cloud services are offline or degraded.
"""

import unittest
from src.orchestrator.orchestrator import Orchestrator

class TestFailureResilience(unittest.TestCase):
    def setUp(self):
        self.config = {
            "agent": {"node_name": "test-resilience-node"},
            "monitors": {
                "process": {"enabled": False},
                "keyboard": {"enabled": False},
                "persistence": {"enabled": False},
                "file": {"enabled": False},
                "network": {"enabled": False}
            },
            "ai_analyst": {"enabled": True, "provider": "invalid_provider"},
            "cloud": {"enabled": True, "endpoint": "http://127.0.0.1:99999/invalid"}
        }
        self.orchestrator = Orchestrator(self.config)

    def test_orchestrator_handles_invalid_ai_gracefully(self):
        event = {
            "source_agent": "keyboard_agent",
            "module": "keyboard",
            "event_type": "SUSPICIOUS_KEYBOARD_HOOK",
            "pid": 999,
            "process_name": "test_hook"
        }
        # handle_telemetry_event should not raise exception even if AI backend is invalid
        try:
            self.orchestrator.handle_telemetry_event(event)
            alerts = self.orchestrator.system_state.get_alerts()
            self.assertGreater(len(alerts), 0)
        except Exception as e:
            self.fail(f"handle_telemetry_event raised exception when AI was offline: {e}")

    def test_agent_start_stop_resilience(self):
        success_stop = self.orchestrator.stop_agent("nonexistent_agent")
        self.assertFalse(success_stop)

if __name__ == "__main__":
    unittest.main()
