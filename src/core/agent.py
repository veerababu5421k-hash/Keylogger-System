import time
import signal
import threading
from src.core.logger import get_logger
from src.core.api import ThreadedApiServer
from src.core.threat_engine import ThreatEngine
from src.monitors.process_monitor import ProcessMonitor
from src.monitors.keyboard_monitor import KeyboardMonitor
from src.monitors.persistence_monitor import PersistenceMonitor
from src.monitors.file_monitor import FileMonitor
from src.monitors.network_monitor import NetworkMonitor

class SecureShieldAgent:
    """
    Main orchestrator class for the SecureShield AI agent.
    Manages the lifecycle (startup, active loop, and teardown) of behavioral monitors.
    """
    def __init__(self, config):
        self.config = config
        self.logger = get_logger()
        self.running = False
        self.monitors = []
        self.api_server = None
        self.threat_engine = ThreatEngine(self.config)
        
        # Pull tick interval from config (how often the main thread runs health checks)
        self.tick_interval = self.config.get("agent", {}).get("tick_interval", 5.0)
        self.node_name = self.config.get("agent", {}).get("node_name", "secureshield-agent")

    def start(self):
        """
        Starts the agent loop and initializes background threads for all active monitors.
        """
        if self.running:
            self.logger.warning("Agent is already running.")
            return

        self.logger.info("Starting SecureShield AI Agent on node: %s", self.node_name)
        self.running = True

        # Register POSIX signal handlers for graceful termination
        # SIGINT = Ctrl+C, SIGTERM = systemctl stop or system termination
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        # Start REST API Server in a background thread
        self.api_server = ThreadedApiServer(self)
        self.api_server.start()

        # Initialize and start active monitors
        self._initialize_monitors()

        # Start the main execution thread loop
        self._run_loop()

    def _run_loop(self):
        """
        Main execution loop. Periodically performs health checks and monitors thread statuses.
        """
        self.logger.info("Main agent loop entered successfully.")
        
        while self.running:
            try:
                # Perform a basic heartbeat log (useful to know the agent is alive)
                self.logger.debug("Agent heartbeat tick...")
                
                # Check health of child threads (if any are dead, restart or log alerts)
                self._check_monitors_health()
                
                # Sleep for the configured interval to reduce CPU utilization
                time.sleep(self.tick_interval)
                
            except Exception as e:
                self.logger.error("Error occurred in main agent execution loop: %s", e)
                
        self.logger.info("Main agent loop exited.")

    def stop(self):
        """
        Stops the agent and requests all background monitor threads to shut down gracefully.
        """
        if not self.running:
            self.logger.warning("Agent is not running.")
            return

        self.logger.info("Shutdown request received. Terminating SecureShield Agent...")
        self.running = False

        # Stop the API server
        if self.api_server:
            self.api_server.stop()

        # Loop through all started monitors and tell them to stop
        for monitor_thread in self.monitors:
            self.logger.info("Requesting monitor '%s' to stop...", monitor_thread.name)
            # Instruct the thread to terminate (details will be added in monitor modules)
            if hasattr(monitor_thread, 'stop'):
                monitor_thread.stop()

        # Wait for all monitor threads to completely exit (join) to prevent zombies
        for monitor_thread in self.monitors:
            self.logger.info("Waiting for monitor '%s' to terminate...", monitor_thread.name)
            monitor_thread.join(timeout=3.0)

        self.logger.info("SecureShield AI Agent successfully terminated.")

    def _handle_signal(self, signum, frame):
        """
        Internal handler for OS signals (SIGINT, SIGTERM).
        """
        signal_name = "SIGINT (Ctrl+C)" if signum == signal.SIGINT else "SIGTERM"
        self.logger.warning("Captured OS signal: %s", signal_name)
        self.stop()

    def _check_monitors_health(self):
        """
        Verifies that all monitoring threads are active.
        """
        for thread in self.monitors:
            if not thread.is_alive():
                self.logger.error("Security Monitor thread '%s' has crashed or stopped!", thread.name)
                # Future logic: attempt to restart the thread or raise system alerts

    def _initialize_monitors(self):
        """
        Dynamically initializes and starts monitors that are enabled in the configuration.
        """
        monitors_config = self.config.get("monitors", {})
        
        # Mapping of monitor configuration key to class
        monitor_classes = {
            "process": ProcessMonitor,
            "keyboard": KeyboardMonitor,
            "persistence": PersistenceMonitor,
            "file": FileMonitor,
            "network": NetworkMonitor
        }
        
        for key, monitor_class in monitor_classes.items():
            settings = monitors_config.get(key, {})
            if settings.get("enabled", False):
                try:
                    self.logger.info("Starting monitor: %s", key.upper())
                    monitor_instance = monitor_class(self.config, self.threat_engine)
                    monitor_instance.start()
                    self.monitors.append(monitor_instance)
                except Exception as e:
                    self.logger.error("Failed to start monitor '%s': %s", key, e, exc_info=True)

    def start_monitor(self, name):
        """
        Starts a specific monitor thread if it is not already running.
        """
        from src.monitors.process_monitor import ProcessMonitor
        from src.monitors.keyboard_monitor import KeyboardMonitor
        from src.monitors.persistence_monitor import PersistenceMonitor
        from src.monitors.file_monitor import FileMonitor
        from src.monitors.network_monitor import NetworkMonitor

        monitor_classes = {
            "process": ProcessMonitor,
            "keyboard": KeyboardMonitor,
            "persistence": PersistenceMonitor,
            "file": FileMonitor,
            "network": NetworkMonitor
        }

        if name not in monitor_classes:
            return False

        # Check if already running (thread active and in list)
        running_names = {t.name.lower() for t in self.monitors if t.is_alive()}
        if f"{name}monitor" in running_names:
            return True

        try:
            self.logger.info("Starting monitor dynamically via API: %s", name.upper())
            monitor_class = monitor_classes[name]
            monitor_instance = monitor_class(self.config, self.threat_engine)
            monitor_instance.start()
            self.monitors.append(monitor_instance)
            return True
        except Exception as e:
            self.logger.error("Failed to start monitor '%s' dynamically: %s", name, e, exc_info=True)
            return False

    def stop_monitor(self, name):
        """
        Stops a specific monitor thread if it is running.
        """
        target_name = f"{name}monitor"
        stopped = False

        for t in list(self.monitors):
            if t.name.lower() == target_name:
                self.logger.info("Stopping monitor dynamically via API: %s", name.upper())
                t.stop()
                # Join thread briefly
                t.join(timeout=1.0)
                if t in self.monitors:
                    self.monitors.remove(t)
                stopped = True

        return stopped