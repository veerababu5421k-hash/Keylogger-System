import os
import hashlib
from src.monitors.base_monitor import BaseMonitor

class FileMonitor(BaseMonitor):
    """
    Monitors critical Linux identity files (/etc/passwd, /etc/shadow, /etc/sudoers)
    for changes in integrity hashes to prevent credential harvesting or privilege hijack.
    """
    def __init__(self, config, threat_engine):
        super().__init__("FileMonitor", config)
        self.threat_engine = threat_engine
        
        file_config = self.config.get("monitors", {}).get("file", {})
        self.monitored_files = file_config.get("monitored_files", ["/etc/passwd", "/etc/shadow", "/etc/sudoers"])
        
        # Baseline integrity store (file -> sha256 hash)
        self.file_hashes = {}
        self._initialize_baselines()

    def _calculate_sha256(self, filepath):
        """
        Computes SHA-256 hash for a target file.
        """
        if not os.path.exists(filepath):
            return None
            
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                # Read file in chunks to prevent large memory load
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except PermissionError:
            self.logger.debug("Access denied reading file baseline: %s", filepath)
            return "permission_denied"
        except OSError as e:
            self.logger.debug("Failed to calculate SHA-256 for %s: %s", filepath, e)
            return None

    def _initialize_baselines(self):
        """
        Sets baseline values for all configured targets.
        """
        for path in self.monitored_files:
            current_hash = self._calculate_sha256(path)
            if current_hash:
                self.file_hashes[path] = current_hash

    def scan(self):
        """
        Compares current hashes to baseline. Raises warnings on discrepancy.
        """
        for path in self.monitored_files:
            if not os.path.exists(path):
                continue
                
            current_hash = self._calculate_sha256(path)
            if not current_hash:
                continue

            if path not in self.file_hashes:
                # File newly added to monitoring list
                self.file_hashes[path] = current_hash
            elif self.file_hashes[path] != current_hash:
                # File hash mismatch! Tampering alert
                self.threat_engine.report_event(
                    monitor="file",
                    message=f"Critical File Modified: Security baseline hash for '{path}' has changed!",
                    risk_score=90.0,
                    extra_info={"file_path": path, "previous_hash": self.file_hashes[path], "new_hash": current_hash}
                )
                self.file_hashes[path] = current_hash
