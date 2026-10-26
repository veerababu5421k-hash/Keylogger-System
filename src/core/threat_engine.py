import os
import logging
from src.core.logger import log_security_alert

logger = logging.getLogger("SecureShield")

# Global Registry of active threat metrics by PID
_threat_state = {}

class ThreatEngine:
    """
    Evaluates events reported by monitors, updates process threat scores,
    and raises structured alerts when risk scores exceed the threshold.
    """
    def __init__(self, config):
        self.config = config
        self.alert_threshold = self.config.get("threat_engine", {}).get("alert_risk_threshold", 50.0)
        self.logger = logging.getLogger("SecureShield")

    def report_event(self, monitor, message, risk_score, pid=None, extra_info=None):
        """
        Reports an event from a monitor, aggregates the risk, and decides if we should raise an alert.
        """
        if extra_info is None:
            extra_info = {}

        self.logger.debug("Threat event received: Monitor=%s PID=%s Score=%.1f Msg=%s", monitor, pid, risk_score, message)

        if not pid:
            # System-wide alert with no process ID
            if risk_score >= self.alert_threshold:
                log_security_alert(
                    module_name=monitor,
                    message=message,
                    risk_score=risk_score,
                    pid=None,
                    extra_info=extra_info
                )
            return

        # PID-based alert: aggregate risk score
        pid = int(pid)
        if pid not in _threat_state:
            _threat_state[pid] = {
                "pid": pid,
                "score": 0.0,
                "events": [],
                "first_seen": os.path.exists(f"/proc/{pid}") if os.path.isdir("/proc") else True
            }

        state = _threat_state[pid]
        
        # Avoid duplicate events from the same monitor for clean calculations
        existing = [e for e in state["events"] if e["monitor"] == monitor and e["message"] == message]
        if not existing:
            state["events"].append({
                "monitor": monitor,
                "message": message,
                "risk_score": risk_score,
                "extra_info": extra_info
            })
            # Recompute total score (bounded at 100.0)
            # Use a weighted aggregation model: base score + fractional parts of subsequent scores
            scores = sorted([e["risk_score"] for e in state["events"]], reverse=True)
            total_score = scores[0]
            for s in scores[1:]:
                total_score += (100.0 - total_score) * (s / 100.0) * 0.4
            
            state["score"] = min(total_score, 100.0)

            # Raise security alert if total score crosses threshold
            if state["score"] >= self.alert_threshold:
                # Merge details of all aggregated events
                summary_msg = f"Aggregated Threat Alert for PID {pid}: " + " | ".join([e["message"] for e in state["events"]])
                merged_extra = {"events_count": len(state["events"])}
                for e in state["events"]:
                    if e["extra_info"]:
                        merged_extra.update(e["extra_info"])

                log_security_alert(
                    module_name=monitor,
                    message=summary_msg,
                    risk_score=state["score"],
                    pid=pid,
                    extra_info=merged_extra
                )

def get_threat_state():
    """
    Exposes aggregated threat state table for API endpoint queries.
    """
    return list(_threat_state.values())

def clear_threat_state():
    """
    Helper to reset threat registers (useful for unit tests).
    """
    global _threat_state
    _threat_state = {}
