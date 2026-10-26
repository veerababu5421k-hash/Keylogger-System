#!/usr/bin/env bash
# ==============================================================================
# SecureShield AI - Cron Automation Installer Script
# Configures scheduled security tasks (scans, log rotation, daily reports).
# Provides full transparency without silent crontab modification.
# ==============================================================================

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_EXEC="$(which python3)"

echo "🛡️ SecureShield AI - Cron Automation Manager"
echo "------------------------------------------------"
echo "Project Root: $PROJECT_ROOT"
echo "Python Exec : $PYTHON_EXEC"
echo ""

CRON_JOB_1="*/15 * * * * cd \"$PROJECT_ROOT\" && $PYTHON_EXEC -c \"from src.orchestrator.orchestrator import Orchestrator; Orchestrator().trigger_cron_event('SCHEDULED_SYSTEM_SCAN')\" >> logs/cron.log 2>&1"
CRON_JOB_2="0 0 * * * cd \"$PROJECT_ROOT\" && $PYTHON_EXEC cron/summary.py >> logs/daily_summary.log 2>&1"

show_preview() {
    echo "📋 Scheduled Crontab Entries Preview:"
    echo "------------------------------------------------"
    echo "1. System Security Scan (Every 15 min):"
    echo "   $CRON_JOB_1"
    echo ""
    echo "2. Daily AI Security Report (Midnight):"
    echo "   $CRON_JOB_2"
    echo "------------------------------------------------"
}

install_cron() {
    show_preview
    echo "Installing crontab entries..."
    (crontab -l 2>/dev/null | grep -v "SecureShield"; echo "# SecureShield AI Scheduled Tasks"; echo "$CRON_JOB_1"; echo "$CRON_JOB_2") | crontab -
    echo "✅ Crontab successfully installed!"
}

uninstall_cron() {
    echo "Removing SecureShield AI crontab entries..."
    crontab -l 2>/dev/null | grep -v "SecureShield" | crontab -
    echo "✅ SecureShield AI crontab entries removed!"
}

case "$1" in
    install)
        install_cron
        ;;
    uninstall)
        uninstall_cron
        ;;
    preview)
        show_preview
        ;;
    *)
        echo "Usage: $0 {install|uninstall|preview}"
        exit 1
        ;;
esac
