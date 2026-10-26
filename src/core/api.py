import os
import json
import psutil
import logging
import threading
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime

# Retrieve parent logger
logger = logging.getLogger("SecureShield")

app = FastAPI(title="SecureShield AI Agent API")

# Enable CORS for local React dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Reference to the running orchestrator agent
_agent = None
_start_time = datetime.now()

def set_agent_instance(agent):
    global _agent
    _agent = agent

class MonitorControl(BaseModel):
    name: str
    action: str  # "start" or "stop"

@app.get("/api/status")
def get_status():
    """
    Returns high-level system information, uptime, resource consumption, and running status.
    """
    if not _agent:
        raise HTTPException(status_code=503, detail="Agent is initializing...")

    # Calculate uptime
    uptime_seconds = (datetime.now() - _start_time).total_seconds()
    
    # Process-specific and system-wide metrics
    try:
        proc = psutil.Process(os.getpid())
        agent_cpu = proc.cpu_percent(interval=None)
        agent_mem = proc.memory_info().rss / (1024 * 1024)  # MB
    except Exception:
        agent_cpu = 0.0
        agent_mem = 0.0

    system_cpu = psutil.cpu_percent()
    system_mem = psutil.virtual_memory().percent

    # Count total alert logs
    alert_file = _agent.config.get("logging", {}).get("alert_file", "logs/alerts.json")
    alert_count = 0
    if os.path.exists(alert_file):
        try:
            with open(alert_file, "r") as f:
                alert_count = sum(1 for line in f if line.strip())
        except Exception:
            pass

    return {
        "status": "RUNNING" if _agent.running else "STOPPED",
        "node_name": _agent.node_name,
        "uptime": uptime_seconds,
        "metrics": {
            "agent_cpu_percent": agent_cpu,
            "agent_memory_mb": agent_mem,
            "system_cpu_percent": system_cpu,
            "system_memory_percent": system_mem
        },
        "alert_count": alert_count,
        "tick_interval": _agent.tick_interval
    }

class MockAlertPayload(BaseModel):
    module: str
    level: str
    risk_score: float
    message: str
    extra_data: dict = None

@app.post("/api/alerts/mock")
def trigger_mock_alert(payload: MockAlertPayload):
    """
    Allows the frontend to trigger a mock alert logged directly to logs/alerts.json.
    """
    if not _agent:
        raise HTTPException(status_code=503, detail="Agent is initializing...")

    from src.core.logger import log_security_alert
    pid_val = payload.extra_data.get("pid") if payload.extra_data else None
    
    log_security_alert(
        module_name=payload.module,
        message=payload.message,
        risk_score=payload.risk_score,
        pid=pid_val,
        extra_info=payload.extra_data
    )
    return {"status": "success", "message": "Mock alert written to logs."}

@app.get("/api/monitors")
def get_monitors():
    """
    Returns active behavioral monitors and their configuration statuses.
    """
    if not _agent:
        raise HTTPException(status_code=503, detail="Agent is initializing...")

    monitor_states = []
    
    # Pre-populate configurations list from agent.yaml config to show overall structure
    monitors_config = _agent.config.get("monitors", {})
    
    # Check currently running threads in agent.monitors (e.g. 'KeyboardMonitor', 'ProcessMonitor')
    running_names = {thread.name.lower() for thread in _agent.monitors if thread.is_alive()}

    for key, settings in monitors_config.items():
        # key is e.g. 'keyboard', key + 'monitor' is 'keyboardmonitor'
        monitor_name_target = f"{key}monitor"
        monitor_states.append({
            "name": key.capitalize() + " Monitor",
            "key": key,
            "enabled_config": settings.get("enabled", False),
            "running": monitor_name_target in running_names
        })

    return monitor_states

@app.get("/api/alerts")
def get_alerts():
    """
    Reads structured JSON threat alerts from alerts.json and returns them in reverse order.
    """
    if not _agent:
        raise HTTPException(status_code=503, detail="Agent is initializing...")

    alert_file = _agent.config.get("logging", {}).get("alert_file", "logs/alerts.json")
    alerts = []

    if os.path.exists(alert_file):
        try:
            with open(alert_file, "r") as f:
                for line in f:
                    if line.strip():
                        try:
                            alerts.append(json.loads(line))
                        except Exception:
                            pass
        except Exception as e:
            logger.error("Failed to read alerts log file: %s", e)
            raise HTTPException(status_code=500, detail="Could not read alert log file.")

    # Return the latest 50 alerts first
    return alerts[::-1][:50]

@app.get("/api/logs")
def get_logs():
    """
    Reads operational log files and returns the last 100 lines.
    """
    if not _agent:
        raise HTTPException(status_code=503, detail="Agent is initializing...")

    log_file = _agent.config.get("logging", {}).get("log_file", "logs/agent.log")
    lines = []

    if os.path.exists(log_file):
        try:
            with open(log_file, "r") as f:
                lines = f.readlines()
        except Exception as e:
            logger.error("Failed to read operational log file: %s", e)
            raise HTTPException(status_code=500, detail="Could not read operational log file.")

    # Get last 100 log lines
    return [line.strip() for line in lines[-100:]]

@app.post("/api/control")
def control_monitor(cmd: MonitorControl):
    """
    Enables/disables security monitors dynamically and restarts/terminates their background threads.
    """
    if not _agent:
        raise HTTPException(status_code=503, detail="Agent is initializing...")

    monitors_config = _agent.config.get("monitors", {})
    if cmd.name not in monitors_config:
        raise HTTPException(status_code=404, detail=f"Monitor '{cmd.name}' not found.")

    enabled = (cmd.action == "start")
    monitors_config[cmd.name]["enabled"] = enabled
    
    # Start or stop thread dynamically
    if enabled:
        success = _agent.start_monitor(cmd.name)
    else:
        success = _agent.stop_monitor(cmd.name)
        
    if not success:
        logger.error("Failed to dynamically modify thread status for '%s'", cmd.name)
        # Raise HTTP exception only if we fail to stop or start a monitor that should be controllable
        raise HTTPException(status_code=500, detail=f"Could not change monitor status for '{cmd.name}'")
        
    logger.info("API Command: Set monitor '%s' state to: %s", cmd.name, cmd.action.upper())
    
    return {
        "monitor": cmd.name,
        "status": "STARTED" if enabled else "STOPPED",
        "message": f"Successfully requested to {cmd.action} monitor '{cmd.name}'"
    }

class ChatPrompt(BaseModel):
    prompt: str
    context_alert: dict = None

@app.post("/api/chat")
def chat_with_analyst(payload: ChatPrompt):
    """
    Sends the user question and the alert context to the AI analyst.
    """
    if not _agent:
        raise HTTPException(status_code=503, detail="Agent is initializing...")

    from src.core.ai_analyst import AiAnalyst
    analyst = AiAnalyst(_agent.config)
    
    # Construct combined prompt
    prompt_context = "The user is asking a question about a security alert. "
    if payload.context_alert:
        prompt_context += f"\nSecurity Alert Context:\n{json.dumps(payload.context_alert, indent=2)}\n"
    prompt_context += f"\nUser Question: {payload.prompt}\n\nPlease reply as a cybersecurity assistant."

    try:
        # Check if analyst is enabled and has a valid client (Gemini) or is running via Ollama
        has_active_provider = False
        if analyst.enabled:
            if analyst.provider == "gemini" and analyst.client:
                has_active_provider = True
            elif analyst.provider == "ollama":
                has_active_provider = True

        if has_active_provider:
            reply_text = analyst.generate_text(prompt_context)
        else:
            # Fallback offline simulation replies
            reply_text = f"I am running in offline fallback mode. For your query '{payload.prompt}', please investigate the associated process/files. Let me know if you need specific commands."
        
        return {"reply": reply_text}
    except Exception as e:
        logger.error("Failed to chat with AI analyst: %s", e)
        return {"reply": f"AI interface offline error: {e}"}

class ThreadedApiServer(threading.Thread):
    """
    Runs the uvicorn FastAPI app inside a separate thread to avoid blocking the agent orchestrator loop.
    """
    def __init__(self, agent_instance, host="0.0.0.0", port=8000):
        super().__init__()
        self.agent = agent_instance
        self.host = host
        self.port = port
        self.name = "ApiServer"
        self.daemon = True
        set_agent_instance(agent_instance)
        
        # Configure Uvicorn server properly
        self.config = uvicorn.Config(
            app=app,
            host=self.host,
            port=self.port,
            log_level="warning",
            loop="asyncio"
        )
        self.server = uvicorn.Server(self.config)

    def run(self):
        logger.info("Starting REST API server on http://%s:%d", self.host, self.port)
        self.server.run()

    def stop(self):
        logger.info("Stopping REST API server...")
        self.server.should_exit = True
