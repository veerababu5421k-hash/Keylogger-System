"""
Agent 5: Network Monitor Agent
Monitors outgoing connections, suspicious IPs/ports, and data exfiltration patterns.
Sends Network Event ONLY to Orchestrator via EventBus.
"""

import time
import threading
import psutil
from typing import Dict, Any, Set
from src.agents.network_agent.config import NetworkAgentConfig
from src.agents.network_agent.logger import get_network_logger

class NetworkAgent(threading.Thread):
    def __init__(self, raw_config: Dict[str, Any] = None, event_bus = None):
        super().__init__(daemon=True, name="NetworkAgent")
        self.config = NetworkAgentConfig(raw_config)
        self.logger = get_network_logger()
        self.event_bus = event_bus
        self.running = False
        self._reported_conns: Set[str] = set()

    def start(self):
        self.logger.info("Initializing Network Monitor Agent...")
        self.running = True
        super().start()

    def stop(self):
        self.logger.info("Stopping Network Monitor Agent...")
        self.running = False

    def run(self):
        self.logger.info("Network Monitor Agent loop running.")
        while self.running:
            try:
                self._inspect_network_connections()
            except Exception as e:
                self.logger.error("Error checking network connections: %s", e)
            time.sleep(self.config.scan_interval)

    def _inspect_network_connections(self):
        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, PermissionError):
            return

        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                pid = conn.pid
                conn_key = f"{pid}:{remote_ip}:{remote_port}"

                is_blacklisted_ip = remote_ip in self.config.blacklisted_ips
                is_suspicious_port = remote_port in self.config.suspicious_ports

                if (is_blacklisted_ip or is_suspicious_port) and conn_key not in self._reported_conns:
                    proc_name = "Unknown"
                    if pid:
                        try:
                            proc_name = psutil.Process(pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    event = {
                        "source_agent": "network_agent",
                        "event_type": "SUSPICIOUS_NETWORK_CONNECTION",
                        "module": "network",
                        "pid": pid,
                        "process_name": proc_name,
                        "destination_ip": remote_ip,
                        "port": remote_port,
                        "status": conn.status,
                        "message": f"Process {proc_name} (PID {pid}) connected to suspicious external endpoint {remote_ip}:{remote_port}",
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    }
                    self.logger.warning("Suspicious connection detected: PID %s -> %s:%d", pid, remote_ip, remote_port)
                    if self.event_bus:
                        self.event_bus.publish(event)
                    self._reported_conns.add(conn_key)
