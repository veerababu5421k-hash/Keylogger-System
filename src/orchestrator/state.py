"""
Thread-safe System State Store for Orchestrator and Dashboard.
Maintains live metrics, alert history, active agent statuses, and uptime.
"""

import time
import threading
import psutil
from typing import Dict, Any, List

class SystemState:
    """
    Holds global system telemetry, thread statuses, alert history, and logs.
    Updated strictly by the Orchestrator.
    """
    def __init__(self, node_name: str = "keyshield-agent"):
        self.node_name = node_name
        self.start_time = time.time()
        self.lock = threading.Lock()
        
        self.agent_statuses: Dict[str, Dict[str, Any]] = {}
        self.alerts: List[Dict[str, Any]] = []
        self.logs: List[str] = []
        self.metrics: Dict[str, float] = {
            "agent_cpu_percent": 0.0,
            "agent_memory_mb": 0.0,
            "system_cpu_percent": 0.0,
            "system_memory_percent": 0.0
        }
        self.alert_count = 0

    def update_agent_status(self, agent_name: str, enabled: bool, running: bool):
        with self.lock:
            self.agent_statuses[agent_name] = {
                "name": agent_name.replace("_", " ").title(),
                "key": agent_name,
                "enabled_config": enabled,
                "running": running
            }

    def add_alert(self, alert: Dict[str, Any]):
        with self.lock:
            self.alerts.insert(0, alert)
            # Keep last 100 alerts
            if len(self.alerts) > 100:
                self.alerts.pop()
            self.alert_count += 1

    def add_log(self, log_line: str):
        with self.lock:
            self.logs.append(log_line)
            if len(self.logs) > 200:
                self.logs.pop(0)

    def refresh_metrics(self):
        with self.lock:
            try:
                self.metrics["system_cpu_percent"] = round(psutil.cpu_percent(interval=None), 1)
                self.metrics["system_memory_percent"] = round(psutil.virtual_memory().percent, 1)
                process = psutil.Process()
                self.metrics["agent_cpu_percent"] = round(process.cpu_percent(interval=None), 1)
                self.metrics["agent_memory_mb"] = round(process.memory_info().rss / (1024 * 1024), 1)
            except Exception:
                pass

    def get_summary(self) -> Dict[str, Any]:
        with self.lock:
            uptime_seconds = int(time.time() - self.start_time)
            return {
                "status": "RUNNING",
                "node_name": self.node_name,
                "uptime": uptime_seconds,
                "alert_count": self.alert_count,
                "metrics": dict(self.metrics)
            }

    def get_monitors_list(self) -> List[Dict[str, Any]]:
        with self.lock:
            return list(self.agent_statuses.values())

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.lock:
            return list(self.alerts[:limit])

    def get_logs(self, limit: int = 100) -> List[str]:
        with self.lock:
            return list(self.logs[-limit:])
