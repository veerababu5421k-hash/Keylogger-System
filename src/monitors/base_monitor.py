import time
import threading
import logging
from abc import ABC, abstractmethod

class BaseMonitor(threading.Thread, ABC):
    """
    Abstract Base Class for all SecureShield behavioral monitors.
    Manages the thread execution lifecycle, polling intervals, and error logging.
    """
    def __init__(self, name, config):
        super().__init__()
        self.name = name
        self.config = config
        self.running = False
        self.logger = logging.getLogger("SecureShield")
        
        # Determine scan interval from config based on monitor name (fallback to 5s)
        monitor_key = self.name.lower().replace("monitor", "").strip()
        self.scan_interval = self.config.get("monitors", {}).get(monitor_key, {}).get("scan_interval", 5.0)

    def start(self):
        """
        Starts the monitor thread.
        """
        self.logger.info("Initializing monitor thread '%s'...", self.name)
        self.running = True
        super().start()

    def run(self):
        """
        Core loop that periodically executes the scanner implementation.
        """
        self.logger.info("Security Monitor thread '%s' started.", self.name)
        
        while self.running:
            try:
                # Perform the specific monitor verification checks
                self.scan()
            except Exception as e:
                self.logger.error("Error in monitor '%s' scan loop: %s", self.name, e, exc_info=True)
                
            # Perform a interruptible sleep
            time.sleep(self.scan_interval)

        self.logger.info("Security Monitor thread '%s' stopped cleanly.", self.name)

    def stop(self):
        """
        Requests the thread to terminate.
        """
        self.logger.info("Stop requested for monitor '%s'.", self.name)
        self.running = False

    @abstractmethod
    def scan(self):
        """
        Check for anomalies. Must be overridden by subclasses.
        """
        pass
