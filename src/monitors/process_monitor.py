import os
import psutil
from src.monitors.base_monitor import BaseMonitor

class ProcessMonitor(BaseMonitor):
    """
    Scans the Linux process table to check for resource-heavy processes,
    unauthorized binary paths (e.g. running from /tmp), and parent hierarchy.
    """
    def __init__(self, config, threat_engine):
        super().__init__("ProcessMonitor", config)
        self.threat_engine = threat_engine
        
        proc_config = self.config.get("monitors", {}).get("process", {})
        self.cpu_threshold = proc_config.get("cpu_threshold", 80.0)
        self.memory_threshold = proc_config.get("memory_threshold", 15.0)
        self.whitelist_names = set(proc_config.get("whitelist_names", ["systemd", "bash", "sshd"]))
        self.whitelist_pids = set(proc_config.get("whitelist_pids", []))
        self.my_pid = os.getpid()

    def scan(self):
        """
        Iterates active processes and audits resource thresholds and execution locations.
        """
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent', 'cmdline']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                name = pinfo['name']
                exe = pinfo['exe'] or ""
                cmdline = pinfo['cmdline'] or []

                # Skip whitelist targets and own agent PID
                if pid == self.my_pid or pid in self.whitelist_pids or name in self.whitelist_names:
                    continue

                # 1. Audit high CPU utilization
                cpu = proc.cpu_percent(interval=None)
                if cpu > self.cpu_threshold:
                    self.threat_engine.report_event(
                        monitor="process",
                        message=f"Process '{name}' (PID {pid}) exceeded CPU threshold: {cpu}% > {self.cpu_threshold}%",
                        risk_score=40.0,
                        pid=pid,
                        extra_info={"cpu_percent": cpu, "cmdline": " ".join(cmdline)}
                    )

                # 2. Audit high Memory utilization
                mem = pinfo['memory_percent']
                if mem > self.memory_threshold:
                    self.threat_engine.report_event(
                        monitor="process",
                        message=f"Process '{name}' (PID {pid}) exceeded Memory threshold: {mem}% > {self.memory_threshold}%",
                        risk_score=35.0,
                        pid=pid,
                        extra_info={"memory_percent": mem, "cmdline": " ".join(cmdline)}
                    )

                # 3. Check for suspicious executable paths (e.g. running from temp mount points)
                suspicious_dirs = ["/tmp", "/var/tmp", "/dev/shm", "/run/user"]
                for sdir in suspicious_dirs:
                    if exe.startswith(sdir):
                        self.threat_engine.report_event(
                            monitor="process",
                            message=f"Suspicious Execution Location: Process '{name}' (PID {pid}) is running from temporary path '{exe}'",
                            risk_score=75.0,
                            pid=pid,
                            extra_info={"exe_path": exe, "cmdline": " ".join(cmdline)}
                        )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
