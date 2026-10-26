"""
Agent 9: Dashboard Agent
Provides REST API & Server endpoints for web dashboard visualization.
Displays live processes, threat score, active alerts, AI analysis, agent status, and system health.
Communicates ONLY with Orchestrator.
"""

import time
import threading
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional, List

from src.agents.dashboard_agent.config import DashboardAgentConfig
from src.agents.dashboard_agent.logger import get_dashboard_logger

class ChatRequest(BaseModel):
    prompt: str
    context_alert: Optional[Dict[str, Any]] = None

class ControlRequest(BaseModel):
    name: str
    action: str  # "start" or "stop"

class MockAlertRequest(BaseModel):
    module: str
    level: str
    risk_score: float
    message: str
    extra_data: Optional[Dict[str, Any]] = None

class DashboardAgent(threading.Thread):
    def __init__(self, raw_config: Dict[str, Any] = None, orchestrator = None):
        super().__init__(daemon=True, name="DashboardAgent")
        self.config = DashboardAgentConfig(raw_config)
        self.logger = get_dashboard_logger()
        self.orchestrator = orchestrator
        self.server = None
        self.app = FastAPI(title="KeyShield AI Dashboard API", version="2.0.0")

        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        self._setup_routes()

    def _setup_routes(self):
        @self.app.get("/api/status")
        def get_status():
            if self.orchestrator and hasattr(self.orchestrator, "system_state"):
                self.orchestrator.system_state.refresh_metrics()
                summary = self.orchestrator.system_state.get_summary()
                summary["agent_live"] = True
                summary["protection_enabled"] = getattr(self.orchestrator, "protection_enabled", True)
                return summary
            return {"status": "STOPPED", "agent_live": False, "node_name": "keyshield", "uptime": 0, "alert_count": 0, "protection_enabled": True, "metrics": {}}

        @self.app.get("/api/protection")
        def get_protection():
            if self.orchestrator and hasattr(self.orchestrator, "protection_enabled"):
                return {"protection_enabled": self.orchestrator.protection_enabled}
            return {"protection_enabled": True}

        @self.app.post("/api/protection/toggle")
        def toggle_protection():
            if self.orchestrator and hasattr(self.orchestrator, "toggle_protection"):
                enabled = self.orchestrator.toggle_protection()
                return {"protection_enabled": enabled}
            return {"protection_enabled": True}

        @self.app.get("/api/monitors")
        def get_monitors():
            if self.orchestrator and hasattr(self.orchestrator, "system_state"):
                return self.orchestrator.system_state.get_monitors_list()
            return []

        @self.app.get("/api/alerts")
        def get_alerts():
            if self.orchestrator and hasattr(self.orchestrator, "system_state"):
                return self.orchestrator.system_state.get_alerts()
            return []

        @self.app.get("/api/logs")
        def get_logs():
            if self.orchestrator and hasattr(self.orchestrator, "system_state"):
                return self.orchestrator.system_state.get_logs()
            return []

        @self.app.post("/api/chat")
        def chat_with_ai(req: ChatRequest):
            if self.orchestrator and hasattr(self.orchestrator, "ai_analyst_agent"):
                reply = self.orchestrator.ai_analyst_agent.generate_chat_response(
                    req.prompt, req.context_alert
                )
                return {"reply": reply}
            return {"reply": "AI Security Analyst Agent is currently unavailable."}

        @self.app.post("/api/control")
        def control_agent(req: ControlRequest):
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="Orchestrator not attached.")
            if req.action == "start":
                success = self.orchestrator.start_agent(req.name)
            elif req.action == "stop":
                success = self.orchestrator.stop_agent(req.name)
            else:
                raise HTTPException(status_code=400, detail="Invalid action.")
            return {"status": "success" if success else "failed", "agent": req.name, "action": req.action}

        @self.app.post("/api/simulate_malware")
        def simulate_malware():
            if self.orchestrator:
                res = self.orchestrator.simulate_malware_attack()
                return res
            return {"status": "error", "message": "Orchestrator unavailable"}

        @self.app.post("/api/alerts/mock")
        def trigger_mock_alert(req: MockAlertRequest):
            if self.orchestrator:
                event = {
                    "source_agent": "dashboard_mock",
                    "event_type": f"MOCK_{req.module.upper()}_EVENT",
                    "module": req.module,
                    "level": req.level,
                    "risk_score": req.risk_score,
                    "message": req.message,
                    "pid": req.extra_data.get("pid") if req.extra_data else 9999,
                    "extra_data": req.extra_data or {},
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                }
                self.orchestrator.handle_telemetry_event(event)
                return {"status": "alert_dispatched"}
            return {"status": "error"}

        @self.app.post("/api/alerts/mock_all")
        def trigger_mock_all_alerts():
            if self.orchestrator:
                res = self.orchestrator.simulate_malware_attack()
                return res
            return {"status": "error", "message": "Orchestrator unavailable"}

        @self.app.post("/api/cron/trigger")
        def trigger_cron(req: dict):
            cron_type = req.get("cron_type", "SCHEDULED_SYSTEM_SCAN")
            if self.orchestrator and hasattr(self.orchestrator, "trigger_cron_event"):
                self.orchestrator.trigger_cron_event(cron_type)
                return {"status": "success", "cron_type": cron_type}
            return {"status": "error", "message": "Orchestrator unavailable"}

    def run(self):
        self.logger.info("Starting Dashboard API Server on http://%s:%d", self.config.host, self.config.port)
        config = uvicorn.Config(app=self.app, host=self.config.host, port=self.config.port, log_level="warning")
        self.server = uvicorn.Server(config)
        self.server.run()

    def stop(self):
        self.logger.info("Stopping Dashboard API Server...")
        if self.server:
            self.server.should_exit = True
