# SecureShield AI 🛡️🤖

**SecureShield AI** is an intelligent, behavior-based keylogger detection and prevention platform for Linux systems.

Rather than relying strictly on known file hashes or static antivirus signatures, SecureShield AI uses a **Multi-Agent Architecture** to monitor physical keyboard access, process spawning, persistence hooks, sensitive file modifications, and network connections—processing alerts via a deterministic **Threat Engine** and an **AI Security Analyst**.

---

## 📂 Multi-Agent System Layout

```
major-project/
├── backend/            # FastAPI Cloud REST API & SQLAlchemy Database Models
├── common/             # Standardized SecurityEvent schemas & Pydantic models
├── config/             # Agent runtime settings and YAML whitelists
├── cron/               # Cron installer script & automated summary jobs
├── docs/               # Architecture docs & Academic Major Project Report
├── frontend/           # React 19 + Vite Web Dashboard
├── logs/               # Application event files & SQLite database
├── scripts/            # Environment verification & master install scripts
├── src/
│   ├── agents/         # 11 Independent Agents (Process, Keyboard, File, Network,
│   │                   # Persistence, Threat Engine, AI Analyst, Logging, Dashboard,
│   │                   # Cron Automation, Cloud Sync)
│   ├── core/           # Core configurations, logger, and threat rules
│   ├── monitors/       # Subsystem monitor primitives
│   └── orchestrator/   # Central Orchestrator & EventBus
└── tests/              # Unit & Integration test suite (33 passing tests)
```

---

## 🚀 Quick Start Guide

### 1. Automated Installation
Run the master installer script to verify dependencies and set up the environment:
```bash
./scripts/install.sh
```

### 2. Run Backend Security Agent
Start the central Orchestrator, monitoring agents, and local API server:
```bash
python3 src/agent.py
```

### 3. Run Frontend Web Dashboard
In a second terminal window, start the React + Vite UI:
```bash
cd frontend
npm run dev
```
Open your browser and navigate to `http://localhost:5173`.

### 4. Run Automated Test Suite
```bash
python3 -m unittest discover -s tests
```

---

## 🛡️ Key Features

- **11 Independent Agents**: Multi-threaded architecture with zero agent-to-agent direct dependencies.
- **Privacy-Aware Keylogger Detection**: Monitors raw input device descriptors (`/dev/input/event*`) without recording or storing user keystrokes.
- **Deterministic Threat Scoring**: Heuristic risk evaluation producing transparent scores (0–100) and risk categories (LOW, MEDIUM, HIGH, CRITICAL).
- **AI Security Analyst**: Interactive chat and incident explanations powered by Ollama (`qwen2.5-coder:3b`) or Gemini AI.
- **Defensive Mitigation Command System**: Proposed mitigation commands (e.g. `kill -9 PID`, `iptables DROP`) with explicit user authorization before execution.
- **Synthetic Malware Attack Simulation**: Trigger full end-to-end test threat campaigns with one click from the dashboard.
- **Cloud Telemetry Synchronization**: Securely syncs sanitized security events to central management servers.

---

## 📄 Documentation

- **Academic Major Project Report**: [docs/academic-report.md](docs/academic-report.md)
- **Architecture Documentation**: [docs/architecture.md](docs/architecture.md)
- **Requirements & Verification**: [docs/requirements.md](docs/requirements.md)
- **AI Security Analyst Design**: [docs/ai-analyst.md](docs/ai-analyst.md)
