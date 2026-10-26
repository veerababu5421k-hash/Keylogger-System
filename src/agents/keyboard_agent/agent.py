"""
Agent 2: Keyboard Activity Agent
Monitors keyboard-related hooks, processes opening /dev/input/event*, and excessive input access.
Sends Keyboard Event ONLY to Orchestrator via EventBus.
"""

import os
import glob
import time
import threading
import psutil
from typing import Dict, Any
from src.agents.keyboard_agent.config import KeyboardAgentConfig
from src.agents.keyboard_agent.logger import get_keyboard_logger

class KeyboardAgent(threading.Thread):
    def __init__(self, raw_config: Dict[str, Any] = None, event_bus = None):
        super().__init__(daemon=True, name="KeyboardAgent")
        self.config = KeyboardAgentConfig(raw_config)
        self.logger = get_keyboard_logger()
        self.event_bus = event_bus
        self.running = False
        self._whitelisted_pids = set()

    def start(self):
        self.logger.info("Initializing Keyboard Activity Agent...")
        self.running = True
        super().start()

    def stop(self):
        self.logger.info("Stopping Keyboard Activity Agent...")
        self.running = False

    def run(self):
        self.logger.info("Keyboard Activity Agent loop running.")
        while self.running:
            try:
                self._inspect_input_file_descriptors()
            except Exception as e:
                self.logger.error("Error checking keyboard hooks: %s", e)
            time.sleep(self.config.scan_interval)

    def _inspect_input_file_descriptors(self):
        """
        Scans processes accessing /dev/input/event* devices.
        Flag non-whitelisted user processes reading raw keyboard devices.
        """
        input_devs = glob.glob("/dev/input/event*")
        if not input_devs:
            return

        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                # Skip known display servers / system daemons
                pname = (proc.info['name'] or "").lower()
                if pname in ["xorg", "gnome-shell", "wayland", "systemd", "kwin", "hyprland"]:
                    continue

                pid = proc.info['pid']
                # Check open file descriptors
                open_files = proc.open_files()
                for f in open_files:
                    if any(dev in f.path for dev in input_devs):
                        cmdline = " ".join(proc.info['cmdline'] or [])
                        event = {
                            "source_agent": "keyboard_agent",
                            "event_type": "SUSPICIOUS_KEYBOARD_HOOK",
                            "module": "keyboard",
                            "pid": pid,
                            "process_name": proc.info['name'],
                            "cmdline": cmdline,
                            "device_node": f.path,
                            "message": f"Process {proc.info['name']} (PID {pid}) opened raw input device {f.path}",
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                        }
                        self.logger.warning("Unauthorized keyboard device access by PID %d (%s)", pid, proc.info['name'])
                        if self.event_bus:
                            self.event_bus.publish(event)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
