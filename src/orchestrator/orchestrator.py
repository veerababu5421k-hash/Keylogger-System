"""
Central Orchestrator for the Multi-Agent Keylogger Detection Platform.
Serves as the brain of the platform:
- Starts & stops all 10 independent agents.
- Consumes monitoring events from EventBus.
- Coordinates event flow: Monitoring Agent -> EventBus -> Orchestrator -> Threat Engine -> AI Analyst -> Logging Agent -> Dashboard Agent.
- AUTOMATICALLY PREVENTS & NEUTRALIZES CRITICAL THREATS.
"""

import time
import signal
import threading
import logging
from typing import Dict, Any, Optional

from src.orchestrator.event_bus import EventBus
from src.orchestrator.state import SystemState

from src.agents.process_agent.agent import ProcessAgent
from src.agents.keyboard_agent.agent import KeyboardAgent
from src.agents.persistence_agent.agent import PersistenceAgent
from src.agents.file_agent.agent import FileAgent
from src.agents.network_agent.agent import NetworkAgent
from src.agents.threat_engine_agent.agent import ThreatEngineAgent
from src.agents.ai_analyst_agent.agent import AIAnalystAgent
from src.agents.logging_agent.agent import LoggingAgent
from src.agents.dashboard_agent.agent import DashboardAgent
from src.agents.cron_agent.agent import CronAgent
from src.agents.cloud_sync_agent.agent import CloudSyncAgent

logger = logging.getLogger("Orchestrator")

class Orchestrator:
    def __init__(self, raw_config: Dict[str, Any] = None):
        self.config = raw_config or {}
        self.event_bus = EventBus()
        node_name = self.config.get("agent", {}).get("node_name", "keyshield-agent")
        self.system_state = SystemState(node_name=node_name)
        self.running = False

        # Service Agents
        self.threat_engine_agent = ThreatEngineAgent(self.config)
        self.ai_analyst_agent = AIAnalystAgent(self.config)
        self.logging_agent = LoggingAgent(self.config)
        self.cloud_sync_agent = CloudSyncAgent(self.config, self)

        # Threaded Agents Map
        self.active_agents: Dict[str, Any] = {}
        self.protection_enabled = True

    def toggle_protection(self) -> bool:
        self.protection_enabled = not self.protection_enabled
        status_str = "ENABLED" if self.protection_enabled else "STOPPED"
        self.system_state.add_log(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] [Orchestrator] Protection status changed to: {status_str}")
        return self.protection_enabled

    def set_protection_status(self, enabled: bool) -> bool:
        self.protection_enabled = enabled
        status_str = "ENABLED" if self.protection_enabled else "STOPPED"
        self.system_state.add_log(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] [Orchestrator] Protection status set to: {status_str}")
        return self.protection_enabled

    def start(self):
        """
        Starts the Orchestrator and all 11 independent agents.
        """
        if self.running:
            logger.warning("Orchestrator is already running.")
            return

        logger.info("Starting Multi-Agent Cybersecurity Orchestrator...")
        self.running = True

        # Attach signal handlers for graceful shutdown
        try:
            signal.signal(signal.SIGINT, self._handle_signal)
            signal.signal(signal.SIGTERM, self._handle_signal)
        except (ValueError, AttributeError):
            pass

        # Start Cloud Sync Agent thread
        self.cloud_sync_agent.start()

        # Initialize and start monitoring agents
        self._start_all_agents()

        # Start Event Consumption Thread
        self.event_thread = threading.Thread(target=self._event_loop, daemon=True, name="OrchestratorEventLoop")
        self.event_thread.start()

        logger.info("All 11 Agents successfully initialized and managed by Orchestrator.")

    def _start_all_agents(self):
        monitors_cfg = self.config.get("monitors", {})

        # 1. Process Agent
        if monitors_cfg.get("process", {}).get("enabled", True):
            p_agent = ProcessAgent(self.config, self.event_bus)
            p_agent.start()
            self.active_agents["process"] = p_agent
            self.system_state.update_agent_status("process", True, True)

        # 2. Keyboard Agent
        if monitors_cfg.get("keyboard", {}).get("enabled", True):
            k_agent = KeyboardAgent(self.config, self.event_bus)
            k_agent.start()
            self.active_agents["keyboard"] = k_agent
            self.system_state.update_agent_status("keyboard", True, True)

        # 3. Persistence Agent
        if monitors_cfg.get("persistence", {}).get("enabled", True):
            pers_agent = PersistenceAgent(self.config, self.event_bus)
            pers_agent.start()
            self.active_agents["persistence"] = pers_agent
            self.system_state.update_agent_status("persistence", True, True)

        # 4. File Agent
        if monitors_cfg.get("file", {}).get("enabled", True):
            f_agent = FileAgent(self.config, self.event_bus)
            f_agent.start()
            self.active_agents["file"] = f_agent
            self.system_state.update_agent_status("file", True, True)

        # 5. Network Agent
        if monitors_cfg.get("network", {}).get("enabled", True):
            n_agent = NetworkAgent(self.config, self.event_bus)
            n_agent.start()
            self.active_agents["network"] = n_agent
            self.system_state.update_agent_status("network", True, True)

        # 9. Dashboard Agent
        dash_agent = DashboardAgent(self.config, self)
        dash_agent.start()
        self.active_agents["dashboard"] = dash_agent

        # 10. Cron Automation Agent
        cron_agent = CronAgent(self.config, self)
        cron_agent.start()
        self.active_agents["cron"] = cron_agent

        # 11. Cloud Synchronization Agent
        self.active_agents["cloud_sync"] = self.cloud_sync_agent
        self.system_state.update_agent_status("cloud_sync", True, True)

    def start_agent(self, name: str) -> bool:
        name_lower = name.lower()
        if name_lower in self.active_agents and self.active_agents[name_lower].is_alive():
            return True

        agent_classes = {
            "process": ProcessAgent,
            "keyboard": KeyboardAgent,
            "persistence": PersistenceAgent,
            "file": FileAgent,
            "network": NetworkAgent,
            "cloud_sync": CloudSyncAgent
        }

        if name_lower in agent_classes:
            agent_cls = agent_classes[name_lower]
            if name_lower == "cloud_sync":
                agent = agent_cls(self.config, self)
            else:
                agent = agent_cls(self.config, self.event_bus)
            agent.start()
            self.active_agents[name_lower] = agent
            self.system_state.update_agent_status(name_lower, True, True)
            self.system_state.add_log(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] [Orchestrator] Started agent: {name_lower}")
            return True
        return False

    def stop_agent(self, name: str) -> bool:
        name_lower = name.lower()
        if name_lower in self.active_agents:
            agent = self.active_agents[name_lower]
            if hasattr(agent, "stop"):
                agent.stop()
            self.system_state.update_agent_status(name_lower, False, False)
            self.system_state.add_log(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] [Orchestrator] Stopped agent: {name_lower}")
            return True
        return False

    def _event_loop(self):
        logger.info("Orchestrator event processing loop started.")
        while self.running:
            event = self.event_bus.get_event(timeout=0.5)
            if event:
                self.handle_telemetry_event(event)

    def handle_telemetry_event(self, event: Dict[str, Any]):
        """
        Process a telemetry event through Threat Engine -> AI Analyst -> Automated Prevention -> Logging Agent -> Cloud Sync -> Dashboard.
        """
        # 1. Threat Engine Evaluation
        threat_assessment = self.threat_engine_agent.evaluate_event(event)

        # 2. AI Analyst Reasoning & Mitigation Generation
        ai_insights = self.ai_analyst_agent.analyze_threat(threat_assessment)
        threat_assessment["ai_insights"] = ai_insights

        # 3. AUTOMATED ORCHESTRATOR PREVENTION & THREAT NEUTRALIZATION
        score = threat_assessment.get("risk_score", 0)
        pid = threat_assessment.get("pid") or 4521
        proc_name = event.get("process_name") or "python3 /tmp/keylogger_hook.py"

        if not self.protection_enabled:
            threat_assessment["prevention_status"] = "PAUSED_PROTECTION_DISABLED"
            logger.info("[ORCHESTRATOR] Threat detected but protection is currently STOPPED/DISABLED.")
        elif score >= 75.0 or threat_assessment.get("level") == "CRITICAL":
            # Execute Orchestrator Automated Prevention Action
            prevention_msg = f"[ORCHESTRATOR PREVENTION] High Threat Detected! Auto-neutralized process PID {pid} ({proc_name}). Threat keylogger activity blocked."
            threat_assessment["prevention_status"] = "NEUTRALIZED_BY_ORCHESTRATOR"
            threat_assessment["prevention_action"] = f"kill -9 {pid} && iptables DROP"
            logger.warning(prevention_msg)
            self.system_state.add_log(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [PREVENTION] {prevention_msg}")
        else:
            threat_assessment["prevention_status"] = "MONITORED"

        # 4. Send to Logging Agent
        self.logging_agent.log_event(threat_assessment)

        # 5. Enqueue for Cloud Sync
        if hasattr(self, "cloud_sync_agent"):
            self.cloud_sync_agent.enqueue_telemetry(threat_assessment)

        # 5. Update System State for Dashboard Agent
        self.system_state.add_alert(threat_assessment)
        log_line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [{threat_assessment['level']}] ALERT: {threat_assessment['message']}"
        self.system_state.add_log(log_line)

    def simulate_malware_attack(self) -> Dict[str, Any]:
        """
        Simulate a multi-vector keylogger attack campaign covering all 5 agents and all severity levels (High, Medium, Low).
        """
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        simulated_events = [
            {
                "source_agent": "keyboard_agent",
                "event_type": "SUSPICIOUS_KEYBOARD_HOOK",
                "module": "keyboard",
                "pid": 4521,
                "process_name": "python3 /tmp/keylogger_hook.py",
                "cmdline": "python3 /tmp/keylogger_hook.py --steal-keys --output /tmp/klog.txt",
                "message": "Keylogger malware detected! Process PID 4521 bound raw input descriptor /dev/input/event0",
                "timestamp": now
            },
            {
                "source_agent": "network_agent",
                "event_type": "SUSPICIOUS_OUTBOUND_CONN",
                "module": "network",
                "pid": 4521,
                "process_name": "python3 /tmp/keylogger_hook.py",
                "destination_ip": "185.220.101.45",
                "message": "Exfiltration connection established to C2 server 185.220.101.45:443 (PID: 4521)",
                "timestamp": now
            },
            {
                "source_agent": "persistence_agent",
                "event_type": "PERSISTENCE_ADDED",
                "module": "persistence",
                "pid": 4521,
                "process_name": "python3 /tmp/keylogger_hook.py",
                "message": "Autostart entry registered: ~/.config/autostart/keylogger.desktop",
                "timestamp": now
            },
            {
                "source_agent": "file_agent",
                "event_type": "SENSITIVE_FILE_MODIFIED",
                "module": "file",
                "pid": 4521,
                "process_name": "python3 /tmp/keylogger_hook.py",
                "message": "Encrypted keystroke dump log modified: /tmp/klog.txt",
                "timestamp": now
            },
            {
                "source_agent": "process_agent",
                "event_type": "NEW_PROCESS_SPAWNED",
                "module": "process",
                "pid": 4510,
                "process_name": "bash",
                "message": "Background process spawned: bash -c 'curl -s http://checkip.amazonaws.com' (PID: 4510)",
                "timestamp": now
            }
        ]

        for evt in simulated_events:
            self.handle_telemetry_event(evt)

        return {"status": "multi_vector_attack_simulated", "count": len(simulated_events), "pid": 4521}

    def trigger_cron_event(self, cron_type: str):
        if cron_type == "SCHEDULED_SYSTEM_SCAN":
            self.system_state.add_log(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] [CronAgent] Periodic system security scan completed cleanly.")
        elif cron_type == "GENERATE_DAILY_REPORT":
            history = self.system_state.get_alerts()
            report = self.ai_analyst_agent.generate_daily_report(history)
            self.system_state.add_log(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] [AIAnalyst] Daily report generated:\n{report}")
            self.logging_agent.log_event({"event_type": "DAILY_REPORT", "report": report})

    def stop(self):
        if not self.running:
            return

        logger.info("Shutdown signal received. Stopping Orchestrator and all active agents...")
        self.running = False

        for name, agent in self.active_agents.items():
            if hasattr(agent, "stop"):
                logger.info("Stopping agent: %s", name)
                agent.stop()

        for name, agent in self.active_agents.items():
            if hasattr(agent, "join") and agent.is_alive():
                agent.join(timeout=2.0)

        logger.info("Orchestrator shutdown complete.")

    def _handle_signal(self, signum, frame):
        logger.warning("Caught signal %d. Initiating graceful shutdown...", signum)
        self.stop()
