# SecureShield AI - System Architecture

This document describes the high-level design, component boundaries, and data flows within **SecureShield AI**.

---

## 1. High-Level Design Diagram

The diagram below represents the logical flow of metrics and alerts from the operating system to the local logs and the cloud backend.

```
+---------------------------------------------------------------------------------+
|                               LINUX KERNEL & OS                                 |
|  [procfs]          [/dev/input/event*]     [System Files]      [Sockets/Net]    |
+------+----------------------+--------------------+--------------------+---------+
       |                      |                    |                    |
       v                      v                    v                    v
+------+----------------------+--------------------+--------------------+---------+
|                         SECURESHIELD DETECTION MONITORS                         |
|  [Process Monitor]  [Keyboard Monitor]   [File Monitor]     [Network Monitor]   |
|  - CPU/Memory       - Key Rate           - Integrity        - Exfil IPs         |


|  - Process Trees    - Hook Detection     - Registry / Cron  - Open Sockets      |
+------+----------------------+--------------------+--------------------+---------+
       |                      |                    |                    |
       |               (Structured Events & Metrics)                    |
       +----------------------+--------------------+--------------------+
                              |
                              v
+-----------------------------+---------------------------------------------------+
|                        AGENT CORE & THREAT ENGINE                               |
|                                                                                 |
|   +-----------------------+              +---------------------------------+    |
|   | Configuration Manager |              |  Threat Detection Engine (v1)   |    |
|   | - Load YAML Settings  |              |  - Rules-based evaluation       |    |
|   | - Maintain Whitelists |              |  - Risk scoring aggregation     |    |
|   +-----------+-----------+              +----------------+----------------+    |
|               |                                           |                     |
|               v                                           v                     |
|   +-------------------------------------------------------+----------------+    |
|   |                      Agent Core / Main Thread                          |    |
|   |                      - Safe lifecycle manager                          |    |
|   |                      - Coordinates threads & structured logger         |    |
|   +--------------------------------------+---------------------------------+    |
+------------------------------------------|--------------------------------------+
                                           v
+------------------------------------------|--------------------------------------+
|                     AI SECURITY ANALYST & LOGGING                               |
|                                                                                 |
|   +--------------------------------------+---------------------------------+    |
|   |                      Structured Logging System                         |    |
|   |                      - Structured JSON File Output                     |    |
|   +--------------------------------------+---------------------------------+    |
|                                          |                                      |
|                                          v                                      |
|   +--------------------------------------+---------------------------------+    |
|   |                         AI Security Analyst                             |    |
|   |                         - Large Language Model Interface                |    |
|   |                         - Explains complex Linux security flags         |    |
|   +--------------------------------------+---------------------------------+    |
+------------------------------------------|--------------------------------------+
                                           v
+------------------------------------------v--------------------------------------+
|                            AUTOMATION & INTEGRATION                             |
|  - Cron Daemon: Runs daily summaries, log rotation, and agent health checks     |
|  - Cloud Sync: Periodically pushes alerts to remote API                        |
+---------------------------------------------------------------------------------+
```

---

## 2. Component Breakdown

### A. Agent Core (`src/core/`)
*   **Agent Lifecycle (`agent.py`):** Responsible for initializing config files, spawning child threads for monitors, implementing safe signal handlers (e.g., `SIGINT`, `SIGTERM` to capture `Ctrl+C` and system shutdown requests), and exiting gracefully without leaving orphaned threads.
*   **Config Manager (`config.py`):** Parses JSON or YAML configuration files. It supports live reloading, whitelists (e.g., processes or network IPs that are known to be safe), and dynamic sensitivity thresholds.
*   **Logging System (`logger.py`):** Generates dual-channel logs:
    1.  *Standard Output / Debug Logs:* For developers to watch agent operations in real-time.
    2.  *Structured JSON Logs:* Machine-readable files containing specific keys (`timestamp`, `module`, `risk_score`, `pid`, `details`) to facilitate easy parsing by the Threat Engine, Cron jobs, and the AI Analyst.

### B. Monitors (`src/monitors/`)
*   **Process Monitor (`process_monitor.py`):** Uses the `psutil` library to scan `/proc`. It tracks active processes, flag processes running from hidden locations (like `/tmp`), calculates parenting structures (Process Hierarchy), and flags processes consuming abnormal CPU or RAM.
*   **Keyboard Monitor (`keyboard_monitor.py`):** Reads the Linux input subsystem device nodes. It measures typing speed and patterns to identify programmatic hooks (e.g., secondary readers reading keyboard input).
*   **Persistence Monitor (`persistence_monitor.py`):** Inspects typical auto-start locations on Linux. This includes systemd directories (`/etc/systemd/system`), Cron directories (`/etc/cron*`), and system-wide startup folders to detect keyloggers attempting to survive system reboots.
*   **File Monitor (`file_monitor.py`):** Utilizes file monitoring hooks or polling to track modifications of critical files (e.g., `/etc/passwd`, `/etc/shadow`) and tracks the creation of large text logs that could indicate a keylogger caching keystrokes.
*   **Network Monitor (`network_monitor.py`):** Monitors network sockets to identify active connections. It cross-references connection endpoints against a security reputation list or reports unknown external outbound traffic that could indicate exfiltration.

### C. Threat Engine & AI (`src/core/`)
*   **Threat Engine (`threat_engine.py`):** Aggregates events from all monitors. It maintains a **state table** of active threats. The threat scoring algorithm adds weights based on combining signals (e.g., a process with 1.0 typing rate is normal, but a process reading keystrokes *and* opening a network socket triggers a high-severity alert).
*   **AI Security Analyst (`ai_analyst.py`):** Interfaces with AI models to explain triggered alerts. It processes JSON alert strings, explains the risk in simple language, suggests mitigation commands (e.g., `kill -9`), and helps junior security operations center (SOC) analysts react to the threat.

---

## 3. Data Flow Steps

1.  **Metric Gathering:** The monitors poll or hook system resources, pushing events into an internal thread-safe queue.
2.  **Risk Aggregation:** The Threat Engine polls the queue, checks active rules, updates the process risk profiles, and updates the threat state.
3.  **Alert Dispatch:** If a process crosses the risk threshold, an Alert event is generated.
4.  **Logging:** The logger writes the alert event to the JSON log file (`logs/alerts.json`).
5.  **AI Analysis:** On-demand or scheduled cron tasks pass new alert logs to the AI Security Analyst to compile threat explanations.
6.  **Report & Sync:** Cron tasks rotate old logs and sync threat intelligence reports to the cloud backend.
