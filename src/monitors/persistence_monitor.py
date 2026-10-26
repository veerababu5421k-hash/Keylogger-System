import os
from src.monitors.base_monitor import BaseMonitor

class PersistenceMonitor(BaseMonitor):
    """
    Inspects standard auto-start and service startup pathways (systemd, sysvinit, autostart)
    to check for newly registered startup scripts or system service tampering.
    """
    def __init__(self, config, threat_engine):
        super().__init__("PersistenceMonitor", config)
        self.threat_engine = threat_engine
        
        persist_config = self.config.get("monitors", {}).get("persistence", {})
        self.monitored_paths = persist_config.get("monitored_paths", ["/etc/systemd/system", "/etc/init.d"])
        
        # Clean paths (expand user directory ~)
        self.monitored_paths = [os.path.expanduser(p) for p in self.monitored_paths]
        
        # Initialize file snapshots state (path -> mtime)
        self.file_snapshots = {}
        self._take_snapshot(first_run=True)

    def _take_snapshot(self, first_run=False):
        """
        Scans monitored paths and updates baseline timestamps.
        Flags changes if not on the initial run.
        """
        for path in self.monitored_paths:
            if not os.path.exists(path):
                continue
                
            try:
                for root, dirs, files in os.walk(path):
                    for file in files: #files in the error order 
                        full_path = os.path.join(root, file)
                        try:
                            mtime = os.path.getmtime(full_path)
                            
                            if not first_run:
                                if full_path not in self.file_snapshots:
                                    # New file detected!
                                    self.threat_engine.report_event(
                                        monitor="persistence",
                                        message=f"New persistence entry detected in startup path: '{full_path}'",
                                        risk_score=70.0,
                                        extra_info={"file_path": full_path, "status": "CREATED"}
                                    )
                                elif self.file_snapshots[full_path] != mtime:
                                    # Modified file detected!
                                    self.threat_engine.report_event(
                                        monitor="persistence",
                                        message=f"Tampering detected: Startup file '{full_path}' has been modified",
                                        risk_score=60.0,
                                        extra_info={"file_path": full_path, "status": "MODIFIED"}
                                    )
                            
                            self.file_snapshots[full_path] = mtime
                        except OSError:
                            continue
            except Exception as e:
                self.logger.debug("Error taking snapshot of persistence path %s: %s", path, e)

    def scan(self):
        """
        Audits startup paths for added/modified binaries or unit settings.
        """
        self._take_snapshot(first_run=False)
