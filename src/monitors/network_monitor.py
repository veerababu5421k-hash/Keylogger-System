import psutil
from src.monitors.base_monitor import BaseMonitor

class NetworkMonitor(BaseMonitor):
    """
    Monitors outbound TCP/UDP connections to identify exfiltration patterns
    and connections opened by untrusted local processes.
    """
    def __init__(self, config, threat_engine):
        super().__init__("NetworkMonitor", config)
        self.threat_engine = threat_engine
        
        net_config = self.config.get("monitors", {}).get("network", {})
        self.whitelist_ips = set(net_config.get("whitelist_ips", ["127.0.0.1", "0.0.0.0"]))

    def scan(self):
        """
        Polls active internet connections and alerts on unwhitelisted external targets.
        """
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                # We are primarily interested in active established connections
                if conn.status != 'ESTABLISHED':
                    continue

                raddr = conn.raddr
                if not raddr:
                    continue

                dest_ip = raddr.ip
                dest_port = raddr.port
                pid = conn.pid

                # Skip local loopbacks and whitelisted IP destinations
                if dest_ip in self.whitelist_ips or dest_ip.startswith("127.") or dest_ip == "::1":
                    continue

                # Identify owning process name
                proc_name = "unknown"
                if pid:
                    try:
                        proc_name = psutil.Process(pid).name()
                    except psutil.NoSuchProcess:
                        continue

                # Flag suspicious outbound connection
                self.threat_engine.report_event(
                    monitor="network",
                    message=f"Suspicious Outbound Connection: Process '{proc_name}' (PID {pid}) connected to external IP '{dest_ip}:{dest_port}'",
                    risk_score=55.0,
                    pid=pid,
                    extra_info={"destination_ip": dest_ip, "port": dest_port, "protocol": "TCP" if conn.type == 1 else "UDP"}
                )

        except psutil.AccessDenied:
            self.logger.debug("Access denied scanning network connections. Run as superuser.")
        except Exception as e:
            self.logger.error("Error checking network connections: %s", e)
