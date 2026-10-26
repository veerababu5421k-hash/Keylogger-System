import os
import unittest
import logging
from src.core.config import load_config, DEFAULT_CONFIG
from src.core.logger import JsonFormatter, setup_logger
from src.core.threat_engine import ThreatEngine, get_threat_state, clear_threat_state
from src.core.ai_analyst import AiAnalyst
from src.monitors.process_monitor import ProcessMonitor

class TestSecureShieldCore(unittest.TestCase):
    
    def setUp(self):
        clear_threat_state()

    def test_config_loader(self):
        """
        Verify that configuration loads default dictionary if file is missing.
        """
        config = load_config("nonexistent_path.yaml")
        self.assertEqual(config["agent"]["node_name"], DEFAULT_CONFIG["agent"]["node_name"])
        self.assertTrue(config["monitors"]["process"]["enabled"])

    def test_json_formatter(self):
        """
        Verify the custom JSON logging formatter structure.
        """
        formatter = JsonFormatter()
        log_record = logging.LogRecord(
            name="TestLogger",
            level=logging.INFO,
            pathname="test_agent_core.py",
            lineno=10,
            msg="Simulated alert message",
            args=(),
            exc_info=None
        )
        # Mock additional telemetry details
        log_record.extra_data = {"risk_score": 85.0, "pid": 1234}
        formatted_json = formatter.format(log_record)
        
        # Parse output JSON to check keys
        import json
        data = json.loads(formatted_json)
        self.assertEqual(data["level"], "INFO")
        self.assertEqual(data["message"], "Simulated alert message")
        self.assertEqual(data["risk_score"], 85.0)
        self.assertEqual(data["pid"], 1234)

    def test_threat_engine_aggregation(self):
        """
        Verify that multiple warnings against the same PID aggregate correctly.
        """
        mock_config = {
            "threat_engine": {"alert_risk_threshold": 50.0},
            "logging": {"alert_file": "logs/test_alerts.json"}
        }
        engine = ThreatEngine(mock_config)
        
        # 1. Report minor process usage
        engine.report_event(
            monitor="process",
            message="CPU threshold crossed",
            risk_score=40.0,
            pid=9999
        )
        
        state = get_threat_state()
        self.assertEqual(len(state), 1)
        self.assertEqual(state[0]["pid"], 9999)
        self.assertEqual(state[0]["score"], 40.0)

        # 2. Report another minor network trigger on the same process
        engine.report_event(
            monitor="network",
            message="Suspicious connection opened",
            risk_score=30.0,
            pid=9999
        )
        
        # Dynamic risk aggregation should increase the score
        updated_state = get_threat_state()
        self.assertGreater(updated_state[0]["score"], 40.0)
        self.assertLessEqual(updated_state[0]["score"], 100.0)

    def test_ai_analyst_fallback(self):
        """
        Verify AI Security Analyst falls back to high-fidelity mock response offline.
        """
        mock_config = {
            "ai_analyst": {
                "enabled": True,
                "model_name": "gemini-2.5-flash"
            }
        }
        # Force API key absence to check fallback
        if "GEMINI_API_KEY" in os.environ:
            del os.environ["GEMINI_API_KEY"]
            
        analyst = AiAnalyst(mock_config)
        result = analyst.analyze_incident({
            "module": "keyboard",
            "pid": 5555
        })
        
        self.assertIn("analysis", result)
        self.assertIn("recommendation", result)
        self.assertIn("5555", result["recommendation"])

    def test_ai_analyst_ollama_fallback(self):
        """
        Verify AI Security Analyst falls back to high-fidelity mock response if Ollama is unreachable.
        """
        mock_config = {
            "ai_analyst": {
                "enabled": True,
                "provider": "ollama",
                "model_name": "qwen2.5-coder:3b",
                "ollama_url": "http://localhost:11111"
            }
        }
        analyst = AiAnalyst(mock_config)
        result = analyst.analyze_incident({
            "module": "process",
            "pid": 7777
        })
        
        self.assertIn("analysis", result)
        self.assertIn("Fallback Analysis due to error", result["analysis"])
        self.assertIn("recommendation", result)
        self.assertIn("7777", result["recommendation"])

if __name__ == "__main__":
    unittest.main()
