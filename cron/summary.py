#!/usr/bin/env python3
import os
import sys
import json
from datetime import datetime, timedelta

# Import project pathways
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.core.config import load_config
from src.core.ai_analyst import AiAnalyst

def run_daily_summary():
    print("[*] Starting SecureShield AI Daily Security Summary Scheduler...")
    config = load_config()
    alert_file = config.get("logging", {}).get("alert_file", "logs/alerts.json")
    
    if not os.path.exists(alert_file):
        print(f"[-] Alerts file '{alert_file}' does not exist yet. No events to aggregate.")
        return

    # 1. Parse alerts from the last 24 hours
    now = datetime.now()
    yesterday = now - timedelta(days=1)
    
    daily_alerts = []
    total_parsed = 0

    try:
        with open(alert_file, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    alert = json.loads(line)
                    total_parsed += 1
                    
                    # Parse timestamp (ISO format)
                    alert_time = datetime.fromisoformat(alert.get("timestamp"))
                    if alert_time >= yesterday:
                        daily_alerts.append(alert)
                except Exception:
                    pass
    except Exception as e:
        print(f"[-] Error reading alerts file: {e}")
        return

    print(f"[*] Total alerts parsed: {total_parsed} | Last 24 hours: {len(daily_alerts)}")

    # 2. Compile metrics
    modules_count = {}
    critical_alerts = []
    high_risk_pids = set()

    for alert in daily_alerts:
        mod = alert.get("module", "unknown")
        modules_count[mod] = modules_count.get(mod, 0) + 1
        
        score = alert.get("risk_score", 0.0)
        if score >= 75.0:
            critical_alerts.append(alert)
        if alert.get("pid"):
            high_risk_pids.add(alert.get("pid"))

    # 3. Instantiate AI Analyst for incident briefing
    analyst = AiAnalyst(config)
    ai_brief = "No critical alerts triggered. System state stable."
    
    if critical_alerts:
        ai_brief_request = {
            "summary": f"Last 24 hours report: {len(daily_alerts)} alerts, {len(critical_alerts)} critical alerts.",
            "top_critical_incidents": critical_alerts[:5]
        }
        try:
            # We can use the analyst interface to formulate a general brief
            brief_resp = analyst.analyze_incident({
                "module": "threat_summary",
                "message": f"Daily security audit compiled {len(critical_alerts)} critical system anomalies.",
                "risk_score": max([a.get("risk_score", 0.0) for a in critical_alerts]),
                "extra_info": ai_brief_request
            })
            ai_brief = brief_resp.get("analysis", ai_brief)
        except Exception as e:
            ai_brief = f"AI Analyst offline. Summary error: {e}"

    # 4. Generate Markdown Daily Security Report
    reports_dir = os.path.join(PROJECT_ROOT, "logs")
    os.makedirs(reports_dir, exist_ok=True)
    report_filename = f"daily_report_{now.strftime('%Y-%m-%d')}.md"
    report_path = os.path.join(reports_dir, report_filename)

    report_content = f"""# SecureShield AI - Daily Security Report
Date: {now.strftime('%Y-%m-%d %H:%M:%S')}
Audit window: {yesterday.strftime('%Y-%m-%d %H:%M:%S')} to {now.strftime('%Y-%m-%d %H:%M:%S')}

## 📊 Summary Statistics
- **Total Alerts in Period**: {len(daily_alerts)}
- **Critical/High-Risk Incidents**: {len(critical_alerts)}
- **Unique Suspicious PIDs**: {len(high_risk_pids)}

### Threat Distribution by Module
"""
    for mod, count in modules_count.items():
        report_content += f"- **{mod.upper()}**: {count} alert(s)\n"
    if not modules_count:
        report_content += "- *No anomalies logged.*\n"

    report_content += f"""
## 🤖 AI Security Briefing
> {ai_brief}

## 🚨 Critical Detections Log
"""
    if not critical_alerts:
        report_content += "*No critical alerts logged in this period.*\n"
    else:
        for idx, alert in enumerate(critical_alerts, 1):
            report_content += f"""
### {idx}. [{alert.get('module').upper()}] Risk Score: {alert.get('risk_score')}%
- **Timestamp**: {alert.get('timestamp')}
- **PID**: {alert.get('pid') or 'N/A'}
- **Message**: {alert.get('message')}
- **Details**: {json.dumps(alert.get('extra_data', {}), indent=2)}
"""

    try:
        with open(report_path, "w") as rf:
            rf.write(report_content)
        print(f"[+] Security report generated successfully: {report_path}")
    except OSError as e:
        print(f"[-] Failed to write daily report file: {e}")

    # 5. Simple Log Rotation
    # If the alert file exceeds 10MB, rotate it
    try:
        if os.path.exists(alert_file) and os.path.getsize(alert_file) > 10 * 1024 * 1024:
            backup_path = f"{alert_file}.{now.strftime('%Y%m%d%H%M%S')}.bak"
            os.rename(alert_file, backup_path)
            print(f"[+] Log rotation: Backed up alerts log file to {backup_path}")
    except Exception as e:
        print(f"[-] Log rotation failed: {e}")

if __name__ == "__main__":
    run_daily_summary()
