# ACADEMIC MAJOR PROJECT REPORT
## KeyShield AI: Multi-Agent Behavior-Based Keylogger Detection and Prevention Platform

---

### 1. ABSTRACT
Modern software keyloggers present a critical threat to endpoint security on Linux systems by covertly capturing raw keystrokes, personal credentials, and session tokens. Traditional signature-based antivirus solutions often fail to detect novel or custom-built keylogger scripts because they lack static signature entries. 

This project presents **KeyShield AI**, a production-oriented, multi-agent cybersecurity platform designed to detect software keyloggers through behavioral analysis rather than signature matching. By deploying 11 isolated monitoring and service agents coordinated strictly through a central Orchestrator, KeyShield AI captures real-time process, input device (`/dev/input/`), persistence, file, and network telemetry. The platform integrates a deterministic Threat Scoring Engine with a local Artificial Intelligence (AI) Security Analyst (powered by Ollama / `qwen2.5-coder:3b` and Gemini AI) to deliver clear incident explanations, risk assessments, and user-confirmed defensive mitigation commands.

---

### 2. INTRODUCTION
Linux endpoint security requires continuous, low-overhead monitoring of hardware event streams and system calls. Software keyloggers typically exhibit a distinct behavioral footprint:
1. Binding raw input character devices under `/dev/input/event*`.
2. Establishing hidden persistence via systemd units or autostart configurations.
3. Modifying local keystroke log dumps.
4. Exfiltrating stolen telemetry over unauthorized outbound sockets.

KeyShield AI addresses these threats using a modular **Multi-Agent Architecture** where specialized agents continuously monitor system subsystems and stream telemetry to a central Orchestrator.

---

### 3. PROBLEM STATEMENT
Existing Linux endpoint security tools suffer from key limitations:
- **Signature Reliance**: Signature scanners fail against zero-day keyloggers written in Python, C, or Go.
- **High Noise & Cryptic Logs**: Conventional SIEM tools produce high volumes of raw log entries that require specialized security expertise to interpret.
- **Lack of Autonomous / Assisted Remediation**: Security tools often detect keyloggers without offering immediate, user-safe defensive mitigation workflows.

---

### 4. EXISTING SYSTEM VS. PROPOSED SYSTEM

| Feature | Existing Systems (Antivirus / Signature Scanners) | Proposed System (KeyShield AI) |
| :--- | :--- | :--- |
| **Detection Method** | Static file hash comparison (YARA / ClamAV) | Real-time behavioral correlation (Input + Process + Network + Persistence) |
| **Zero-Day Keylogger Protection** | Poor (Requires pre-existing malware signature) | Excellent (Detects raw input binding & exfiltration behavior) |
| **Architecture** | Monolithic background daemon | Multi-Agent Architecture (11 isolated agent threads) |
| **Incident Explanation** | Cryptic error code or file path | Human-readable AI Security Analyst explanations |
| **Mitigation Workflow** | Immediate blind deletion or manual shell lookup | Proposed mitigation commands with explicit user confirmation |
| **Cloud Telemetry** | Full system uploads / privacy risk | Privacy-aware sanitized telemetry (No raw keystrokes uploaded) |

---

### 5. OBJECTIVES
1. Build an 11-agent modular architecture where no monitoring agent communicates directly with another.
2. Implement raw input device stream monitoring on Linux (`/dev/input/event*`) while strictly respecting user privacy (zero raw keystroke logging).
3. Develop a deterministic behavioral Threat Engine to compute transparent risk scores (0 to 100).
4. Integrate a local AI Security Analyst to explain security alerts and propose defensive shell commands (`kill -9 PID`, firewall rules).
5. Build an interactive web dashboard (React + Vite) with active protection toggles, real-time threat timelines, and command execution confirmation.
6. Provide full REST API backend and cloud synchronization capabilities.

---

### 6. SYSTEM ARCHITECTURE

```
+-----------------------------------------------------------------------+
|                         MONITORING AGENTS                             |
|  [Process]   [Keyboard]   [Persistence]   [File]   [Network]          |
+-----+------------+--------------+------------+--------+---------------+
      |            |              |            |        |
      +------------+-------+------+------------+--------+
                           |
                           v
+-----------------------------------------------------------------------+
|                    CENTRAL ORCHESTRATOR & EVENTBUS                   |
|  - Lifecycle Management & Heartbeat Tracking                          |
|  - Agent Status: RUNNING / STOPPED / ERROR / DEGRADED                |
+-----+--------------------+-------------------+------------------------+
      |                    |                   |
      v                    v                   v
+--------------+   +---------------+   +---------------+
| Threat Engine|   | AI Analyst    |   | Logging Agent |
| (0-100 Score)|   | (Ollama/Gemini|   | (Structured)  |
+--------------+   +---------------+   +---------------+
      |                    |                   |
      +--------------------+-------------------+
                           |
                           v
+-----------------------------------------------------------------------+
|                DASHBOARD UI & CLOUD BACKEND API                       |
|  - React + Vite Dashboard (http://localhost:5173)                     |
|  - FastAPI Backend REST Server (http://localhost:8000)                |
|  - Cloud Sync Agent (Agent 11) & SQLite/PostgreSQL Database           |
+-----------------------------------------------------------------------+
```

---

### 7. TECHNOLOGY STACK
- **Core Agent Logic**: Python 3.10+ (`threading.Thread`, `psutil`, `evdev`, `PyYAML`, `requests`, `sqlalchemy`)
- **Backend REST API**: FastAPI, Uvicorn, Pydantic, SQLite / PostgreSQL
- **Frontend Dashboard**: React 19, Vite, Vanilla CSS design system
- **AI / LLM Engine**: Ollama (`qwen2.5-coder:3b`) with Google GenAI Cloud Fallback
- **System Automation**: Bash shell scripts, Linux Crontab

---

### 8. MODULE DESCRIPTIONS (ALL 11 AGENTS)

1. **Process Monitor Agent**: Scans process table (`/proc`), collecting PIDs, parent PIDs, execution paths, CPU/memory usage, and flagging unwhitelisted background binaries.
2. **Keyboard Monitor Agent**: Hooks into `/dev/input/event*` subsystem to detect unauthorized input access and abnormally high keystroke rates without storing actual typed keys.
3. **Persistence Monitor Agent**: Scans system autostart directories (`~/.config/autostart`, `/etc/systemd/system`) to detect newly registered startup services.
4. **File Activity Agent**: Monitors security-sensitive directories (`/etc/passwd`, `/etc/sudoers`, `/tmp/`) for unauthorized modifications or keylogger dump creation.
5. **Network Monitor Agent**: Inspects active socket connections (`psutil.net_connections`), detecting suspicious outbound connections to external command-and-control (C2) servers.
6. **Threat Engine Agent**: Evaluates correlated monitoring events using deterministic heuristic weights to calculate normalized risk scores and threat levels (LOW, MEDIUM, HIGH, CRITICAL).
7. **AI Security Analyst Agent**: Passes structured incident payloads to the LLM to generate human explanations, risk breakdowns, and defensive mitigation recommendations.
8. **Logging Agent**: Writes structured JSON alert files (`logs/alerts.json`) and standard operational logs with automatic file rotation.
9. **Dashboard Agent**: Runs FastAPI REST endpoints serving live system metrics, agent health, incident history, and interactive AI chat to the web frontend.
10. **Cron Automation Agent**: Manages background periodic security scans, log cleanup, and daily security report summaries.
11. **Cloud Synchronization Agent**: Queues sanitized, non-sensitive security telemetry and synchronizes events with remote backend servers.

---

### 9. TEST CASES & VERIFICATION RESULTS

| Test Suite | Module Tested | Test Focus | Result |
| :--- | :--- | :--- | :--- |
| `test_orchestrator` | Central Orchestrator | Agent startup, event bus routing, protection toggling | **PASS** |
| `test_process_agent` | Process Monitor | CPU/Memory tracking, unwhitelisted PID flagging | **PASS** |
| `test_keyboard_agent` | Keyboard Monitor | Input descriptor stream tracking & rate thresholds | **PASS** |
| `test_threat_engine_agent` | Threat Engine | Risk score computation & CRITICAL level classification | **PASS** |
| `test_ai_analyst_agent` | AI Security Analyst | Prompt construction & fallback reasoning execution | **PASS** |
| `test_cloud_sync_agent` | Cloud Sync Agent | Privacy sanitization & offline telemetry queueing | **PASS** |
| `test_failure_resilience` | System Resilience | Graceful degradation when AI or Cloud is offline | **PASS** |

---

### 10. EXPECTED OUTCOMES
- Real-time detection and automated containment of software keyloggers on Linux.
- Zero raw keystroke exposure, maintaining user privacy.
- User-friendly web dashboard displaying real-time agent status, threat timelines, and AI-assisted mitigation.

---

### 11. CONCLUSION
KeyShield AI demonstrates that combining a **Multi-Agent Architecture** with deterministic threat scoring and local AI models provides superior zero-day software keylogger protection compared to static antivirus solutions.

---

### 12. FUTURE SCOPE
- Windows (`SetWindowsHookEx`) and macOS (`CGEventTap`) agent porting.
- Advanced machine learning behavioral baseline models.
- Enterprise multi-tenant cloud console deployment.

---

### 13. REFERENCES
1. Linux Input Subsystem Documentation: `kernel.org/doc/Documentation/input/input.txt`
2. MITRE ATT&CK Framework: Technique T1056.001 (Input Capture: Keylogging)
3. FastAPI Documentation: `fastapi.tiangolo.com`
4. Ollama Open Source LLM Runner: `ollama.com`
