"""
Agent 1: Process Monitor Agent
Monitors process creation, CPU/RAM usage, parent-child processes, and suspicious cmdlines.
Sends Process Event ONLY to Orchestrator via EventBus.
"""

import time
import threading
import psutil
from typing import Dict, Any, Optional
from src.agents.process_agent.config import ProcessAgentConfig
from src.agents.process_agent.logger import get_process_logger

class ProcessAgent(threading.Thread):
    def __init__(self, raw_config: Dict[str, Any] = None, event_bus = None):
        super().__init__(daemon=True, name="ProcessAgent")
        self.config = ProcessAgentConfig(raw_config)
        self.logger = get_process_logger()
        self.event_bus = event_bus
        self.running = False
        self._known_pids = set()

    def start(self):
        self.logger.info("Initializing Process Monitor Agent...")
        self.running = True
        super().start()

    def stop(self):
        self.logger.info("Stopping Process Monitor Agent...")
        self.running = False

    def run(self):
        self.logger.info("Process Monitor Agent loop running.")
        while self.running:
            try:
                self._scan_processes()
            except Exception as e:
                self.logger.error("Error scanning processes: %s", e)
            time.sleep(self.config.scan_interval)

    def _scan_processes(self):
        current_pids = set()
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_info', 'ppid']):
            try:
                info = proc.info
                pid = info['pid']
                current_pids.add(pid)
                name = info['name'] or ""
                cmdline = " ".join(info['cmdline'] or [])
                cpu = info.get('cpu_percent') or 0.0
                mem_info = info.get('memory_info')
                mem_mb = (mem_info.rss / (1024 * 1024)) if mem_info else 0.0
                ppid = info.get('ppid')

                # Check new process creation
                if pid not in self._known_pids:
                    suspicious_match = any(pattern in cmdline.lower() or pattern in name.lower() 
                                           for pattern in self.config.suspicious_cmdlines)
                    if suspicious_match:
                        event = {
                            "source_agent": "process_agent",
                            "event_type": "SUSPICIOUS_PROCESS",
                            "module": "process",
                            "pid": pid,
                            "process_name": name,
                            "cmdline": cmdline,
                            "ppid": ppid,
                            "cpu_percent": cpu,
                            "memory_mb": mem_mb,
                            "risk_indicators": [f"Command line matches suspicious pattern: {name}"],
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                        }
                        self.logger.warning("Suspicious process detected: %s (PID: %d)", name, pid)
                        if self.event_bus:
                            self.event_bus.publish(event)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        self._known_pids = current_pids
