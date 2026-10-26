#!/bin/bash

# Compute path of summary script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SUMMARY_SCRIPT="$PROJECT_ROOT/cron/summary.py"

echo "[*] Setting up KeyShield AI daily summary crontab entry..."

if [ ! -f "$SUMMARY_SCRIPT" ]; then
    echo "[-] Error: Summary script not found at $SUMMARY_SCRIPT"
    exit 1
fi

# Make summary script executable
chmod +x "$SUMMARY_SCRIPT"

# Check if entry already exists in crontab
CRON_LINE="0 0 * * * /usr/bin/python3 $SUMMARY_SCRIPT >> $PROJECT_ROOT/logs/cron.log 2>&1"

if crontab -l 2>/dev/null | grep -F "$SUMMARY_SCRIPT" >/dev/null; then
    echo "[+] Crontab entry already exists. No actions required."
else
    # Append new cron job to existing crontab
    (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
    echo "[+] Crontab updated successfully. Daily summary registered at midnight (00:00)."
    echo "    Cron job details: $CRON_LINE"
fi

exit 0
