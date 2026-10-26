"""
Unit tests for SecurityEvent schema and serialization.
"""

import unittest
from src.common.events import SecurityEvent

class TestSecurityEventSchema(unittest.TestCase):
    def test_security_event_defaults_and_dict(self):
        event = SecurityEvent(
            agent_type="keyboard",
            event_type="SUSPICIOUS_KEYBOARD_HOOK",
            process_id=4521,
            process_name="python3",
            severity="CRITICAL"
        )
        d = event.to_dict()
        self.assertEqual(d["module"], "keyboard")
        self.assertEqual(d["pid"], 4521)
        self.assertEqual(d["severity"], "CRITICAL")
        self.assertIsNotNone(d["event_id"])
        self.assertIsNotNone(d["timestamp"])

    def test_from_dict_reconstruction(self):
        d = {
            "source_agent": "process_agent",
            "module": "process",
            "event_type": "NEW_PROCESS",
            "pid": 100,
            "level": "HIGH"
        }
        event = SecurityEvent.from_dict(d)
        self.assertEqual(event.agent_id, "process_agent")
        self.assertEqual(event.agent_type, "process")
        self.assertEqual(event.process_id, 100)
        self.assertEqual(event.severity, "HIGH")

if __name__ == "__main__":
    unittest.main()
