"""
Agent 10: Cron Automation Agent
Schedules and executes automated periodic jobs:
- Security scans
- Log rotations
- System health telemetry monitoring
- Daily security report generation
- Future Cloud Synchronization stubs
Communicates ONLY with Orchestrator.
"""

import time
import threading
from typing import Dict, Any
from src.agents.cron_agent.config import CronAgentConfig
from src.agents.cron_agent.logger import get_cron_logger

class CronAgent(threading.Thread):
    def __init__(self, raw_config: Dict[str, Any] = None, orchestrator = None):
        super().__init__(daemon=True, name="CronAgent")
        self.config = CronAgentConfig(raw_config)
        self.logger = get_cron_logger()
        self.orchestrator = orchestrator
        self.running = False
        self._last_report_time = time.time()
        self._last_scan_time = time.time()

    def start(self):
        self.logger.info("Initializing Cron Automation Agent...")
        self.running = True
        super().start()

    def stop(self):
        self.logger.info("Stopping Cron Automation Agent...")
        self.running = False

    def run(self):
        self.logger.info("Cron Automation Agent scheduler loop running.")
        while self.running:
            now = time.time()
            try:
                # Scheduled Security & Health Check Scan
                if now - self._last_scan_time >= self.config.scan_interval_sec:
                    self._run_scheduled_scan()
                    self._last_scan_time = now

                # Scheduled Daily Security Report Generation
                if now - self._last_report_time >= self.config.report_interval_sec:
                    self._generate_scheduled_report()
                    self._last_report_time = now

            except Exception as e:
                self.logger.error("Error in cron scheduler loop: %s", e)

            time.sleep(5.0)

    def _run_scheduled_scan(self):
        self.logger.info("Triggering scheduled multi-agent health and security scan...")
        if self.orchestrator:
            self.orchestrator.trigger_cron_event("SCHEDULED_SYSTEM_SCAN")

    def _generate_scheduled_report(self):
        self.logger.info("Triggering scheduled daily security report generation...")
        if self.orchestrator:
            self.orchestrator.trigger_cron_event("GENERATE_DAILY_REPORT")
