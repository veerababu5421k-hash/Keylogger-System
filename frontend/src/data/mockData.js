// Sentinel AI - Data Models & Mock Datasets for all 16 pages

export const initialAgents = [
  {
    id: 'process',
    name: 'Process Monitor Agent',
    type: 'agent',
    status: 'Running',
    uptime: '1d 6h 32m',
    heartbeat: '1.2s ago',
    eventsGenerated: 1245,
    cpu: '0.4%',
    memory: '18.4 MB',
    target: '/proc table monitoring & PID tracking',
    description: 'Cataloging user-space processes, tracking parent-child process trees, and identifying unwhitelisted binary executions.'
  },
  {
    id: 'keyboard',
    name: 'Keyboard Hook Agent',
    type: 'agent',
    status: 'Running',
    uptime: '1d 6h 32m',
    heartbeat: '0.8s ago',
    eventsGenerated: 1892,
    cpu: '0.2%',
    memory: '12.1 MB',
    target: '/dev/input/event* character devices',
    description: 'Monitors raw input event descriptor access and ioctl calls without recording keystrokes. Privacy-enforced.'
  },
  {
    id: 'file',
    name: 'File Activity Agent',
    type: 'agent',
    status: 'Running',
    uptime: '1d 6h 32m',
    heartbeat: '1.5s ago',
    eventsGenerated: 1532,
    cpu: '0.3%',
    memory: '14.8 MB',
    target: '/tmp, /var/log, ~/.Xauthority, system log paths',
    description: 'Detects unauthorized log file creation, keylogger file dumping, and sensitive credential store tampering.'
  },
  {
    id: 'network',
    name: 'Network Monitor Agent',
    type: 'agent',
    status: 'Running',
    uptime: '1d 6h 28m',
    heartbeat: '1.1s ago',
    eventsGenerated: 984,
    cpu: '0.5%',
    memory: '21.0 MB',
    target: 'Outbound TCP/UDP sockets & DNS lookups',
    description: 'Monitors outbound sockets for unwhitelisted remote Command & Control (C2) IP communication and exfiltration.'
  },
  {
    id: 'persistence',
    name: 'Persistence Agent',
    type: 'agent',
    status: 'Running',
    uptime: '1d 6h 27m',
    heartbeat: '2.0s ago',
    eventsGenerated: 421,
    cpu: '0.1%',
    memory: '9.6 MB',
    target: '~/.config/autostart, /etc/xdg/autostart, systemd',
    description: 'Tracks additions to autostart desktop entries, systemd user services, and cron jobs to prevent keylogger reboot survival.'
  },
  {
    id: 'threat_engine',
    name: 'Threat Engine Matrix Agent',
    type: 'engine',
    status: 'Running',
    uptime: '1d 6h 32m',
    heartbeat: '0.5s ago',
    eventsGenerated: 202,
    cpu: '0.8%',
    memory: '34.2 MB',
    target: 'Rule Heuristic Evaluation Engine',
    description: 'Calculates multi-vector risk scores from aggregated telemetry streams using weighted threat heuristics.'
  },
  {
    id: 'ai_analyst',
    name: 'AI Security Analyst Agent',
    type: 'ai',
    status: 'Running',
    uptime: '1d 6h 30m',
    heartbeat: '1.0s ago',
    eventsGenerated: 128,
    cpu: '1.2%',
    memory: '142.0 MB',
    target: 'Ollama LLM (qwen2.5-coder:3b)',
    description: 'Translates technical alerts into plain language explanations, generates mitigation options, and powers interactive analyst chat.'
  },
  {
    id: 'logging',
    name: 'Logging Agent',
    type: 'service',
    status: 'Running',
    uptime: '1d 6h 32m',
    heartbeat: '0.4s ago',
    eventsGenerated: 2841,
    cpu: '0.2%',
    memory: '16.5 MB',
    target: 'Local Syslog & Circular Buffer',
    description: 'Maintains structured security log audit trails, manages log rotation, and formats JSON/Syslog outputs.'
  },
  {
    id: 'cron',
    name: 'Cron Automation Agent',
    type: 'service',
    status: 'Running',
    uptime: '1d 6h 32m',
    heartbeat: '5.0s ago',
    eventsGenerated: 57,
    cpu: '0.1%',
    memory: '8.2 MB',
    target: 'System Scheduler (crontab)',
    description: 'Schedules automated health checks, daily security digests, and periodic background threat scans.'
  }
];

export const initialEvents = [
  {
    id: 'EVT-1001',
    time: '09:42:11 PM',
    agent: 'Process Monitor',
    event: 'Process Created',
    process: 'bash (PID: 5110)',
    details: 'New process spawned via python3 runner',
    severity: 'Low',
    score: 25,
    pid: 5110
  },
  {
    id: 'EVT-1002',
    time: '09:42:01 PM',
    agent: 'Network Monitor',
    event: 'Outbound Connection',
    process: 'python3 (PID: 4458)',
    details: '185.220.101.45:443 (Blocked Destination)',
    severity: 'High',
    score: 85,
    pid: 4458
  },
  {
    id: 'EVT-1003',
    time: '09:41:58 PM',
    agent: 'File Activity',
    event: 'File Modified',
    process: 'python3 (PID: 4458)',
    details: '/tmp/klog_dump.txt created and modified',
    severity: 'Medium',
    score: 65,
    pid: 4458
  },
  {
    id: 'EVT-1004',
    time: '09:41:52 PM',
    agent: 'Keyboard Agent',
    event: 'Suspicious Hook',
    process: 'unknown (PID: 4458)',
    details: 'Access bound to /dev/input/event3 descriptor',
    severity: 'High',
    score: 92,
    pid: 4458
  },
  {
    id: 'EVT-1005',
    time: '09:41:45 PM',
    agent: 'Persistence Agent',
    event: 'Startup Entry Added',
    process: 'systemd32',
    details: '~/.config/autostart/keylogger.desktop',
    severity: 'Medium',
    score: 60,
    pid: 4458
  },
  {
    id: 'EVT-1006',
    time: '09:41:35 PM',
    agent: 'Process Monitor',
    event: 'Terminated Process',
    process: 'python3 (PID: 4521)',
    details: 'Process terminated cleanly by user confirmation',
    severity: 'Low',
    score: 10,
    pid: 4521
  },
  {
    id: 'EVT-1007',
    time: '09:41:30 PM',
    agent: 'Network Monitor',
    event: 'DNS Query',
    process: 'firefox (PID: 3842)',
    details: 'api.github.com (Whitelisted)',
    severity: 'Low',
    score: 5,
    pid: 3842
  },
  {
    id: 'EVT-1008',
    time: '09:41:25 PM',
    agent: 'File Activity',
    event: 'File Created',
    process: 'vscode (PID: 2901)',
    details: '/tmp/demo.log created',
    severity: 'Low',
    score: 8,
    pid: 2901
  },
  {
    id: 'EVT-1009',
    time: '09:41:19 PM',
    agent: 'Keyboard Agent',
    event: 'Input Monitoring App',
    process: 'unknown (PID: 4458)',
    details: 'Raw keyboard access requested',
    severity: 'High',
    score: 88,
    pid: 4458
  }
];

export const initialThreats = [
  {
    id: 'TH-001',
    title: 'Suspicious Keyboard Hook Detected',
    process: 'unknown (PID: 4458)',
    score: 68,
    severity: 'High',
    status: 'Open',
    detectedAt: 'Sep 14, 2026 09:41:52 PM',
    agent: 'Keyboard Agent',
    details: 'Process bound raw input descriptors (/dev/input/event*) and initiated autostart persistence.'
  },
  {
    id: 'TH-002',
    title: 'Outbound Socket to Suspicious C2 Server',
    process: 'python3 (PID: 4458)',
    score: 85,
    severity: 'High',
    status: 'Investigating',
    detectedAt: 'Sep 14, 2026 09:42:01 PM',
    agent: 'Network Monitor',
    details: 'Attempted exfiltration socket connection to known malicious IP 185.220.101.45 on port 443.'
  },
  {
    id: 'TH-003',
    title: 'Persistence Entry Added to ~/.config/autostart',
    process: 'systemd32',
    score: 60,
    severity: 'Medium',
    status: 'Open',
    detectedAt: 'Sep 14, 2026 09:41:45 PM',
    agent: 'Persistence Agent',
    details: 'Created desktop autostart entry keylogger.desktop pointing to executable script in /tmp.'
  },
  {
    id: 'TH-004',
    title: 'Unusual Keystroke File Modification',
    process: 'bash (PID: 5110)',
    score: 48,
    severity: 'Medium',
    status: 'Open',
    detectedAt: 'Sep 14, 2026 09:41:12 PM',
    agent: 'File Activity Agent',
    details: 'Rapid append writes to hidden file /tmp/.klog_data without standard terminal descriptor.'
  },
  {
    id: 'TH-005',
    title: 'Suspicious Process Behavior (Input Monitoring)',
    process: 'node (PID: 3341)',
    score: 71,
    severity: 'High',
    status: 'Open',
    detectedAt: 'Sep 14, 2026 09:38:15 PM',
    agent: 'Process Monitor',
    details: 'Process attempting to read raw device nodes without graphical window focus.'
  },
  {
    id: 'TH-006',
    title: 'Abnormal Network Activity Detected',
    process: 'chrome (PID: 2891)',
    score: 46,
    severity: 'Medium',
    status: 'Resolved',
    detectedAt: 'Sep 14, 2026 09:14:02 PM',
    agent: 'Network Monitor',
    details: 'High frequency DNS lookups to unverified domain list. Evaluated and verified benign.'
  }
];

export const initialIncident = {
  id: 'TH-001',
  title: 'Suspicious Keyboard Hook Detected',
  detectedAt: 'Sep 14, 2026 09:41:52 PM',
  process: 'unknown (PID: 4458)',
  threatScore: 68,
  confidence: '87%',
  severity: 'High Risk',
  status: 'Open',
  agent: 'Keyboard Monitor Agent',
  eventType: 'Input Monitoring',
  pid: 4458,
  description: 'A process is attempting to access global keyboard hooks which is commonly used by software keyloggers to capture user input.',
  possibleImpact: [
    'Capture sensitive information (passwords, credentials, private messages)',
    'Monitor user activity and active browser window titles',
    'Data exfiltration over covert network sockets'
  ],
  evidence: [
    { type: 'Keyboard Behavior', detail: 'Bound raw character stream descriptor (/dev/input/event3)', risk: 'Critical' },
    { type: 'Process Activity', detail: 'Unwhitelisted binary running from temporary path /tmp/keylogger_hook.py', risk: 'High' },
    { type: 'Persistence Entry', detail: 'Created autostart desktop file ~/.config/autostart/keylogger.desktop', risk: 'Medium' },
    { type: 'Network Connection', detail: 'Established outbound socket to remote C2 server 185.220.101.45:443', risk: 'High' }
  ],
  aiAnalysis: `Threat Analysis:
This process is exhibiting behavior commonly associated with software keyloggers. It is attempting to access global keyboard hooks to intercept raw keystrokes from the Linux character device subsystem (/dev/input/event*). The process path is unwhitelisted and does not match common trusted desktop applications.

Key Findings:
• Global keyboard hook bound to character stream
• Running from temporary directory (/tmp/keylogger_hook.py)
• Autostart persistence mechanism created
• Outbound network connection attempted to C2 IP 185.220.101.45`,
  recommendations: [
    'Terminate the suspicious process PID 4458 immediately.',
    'Block outbound destination IP 185.220.101.45 via UFW firewall rules.',
    'Remove autostart entry ~/.config/autostart/keylogger.desktop.',
    'Scan system for related file artifacts in /tmp.'
  ],
  mitigationCommands: [
    { id: 'cmd-1', label: 'Terminate Process', command: 'kill -9 4458', target: 'PID: 4458', recommended: true },
    { id: 'cmd-2', label: 'Block Network Access', command: 'sudo ufw deny out to 185.220.101.45', target: 'IP: 185.220.101.45', recommended: true },
    { id: 'cmd-3', label: 'Remove Persistence Entry', command: 'rm -f ~/.config/autostart/keylogger.desktop', target: '~/.config/autostart/', recommended: true },
    { id: 'cmd-4', label: 'Scan for Related Files', command: 'ls -la /tmp/*klog*', target: 'Path: /tmp', recommended: false }
  ],
  timeline: [
    { time: '09:41:45 PM', event: 'Autostart entry created in ~/.config/autostart/keylogger.desktop' },
    { time: '09:41:52 PM', event: 'Raw keyboard input descriptor bound (/dev/input/event3)' },
    { time: '09:41:58 PM', event: 'Local file dump initialized in /tmp/klog_dump.txt' },
    { time: '09:42:01 PM', event: 'Outbound socket connection attempt to 185.220.101.45:443' },
    { time: '09:42:02 PM', event: 'Threat Engine calculated risk score 85.0 (CRITICAL)' },
    { time: '09:42:05 PM', event: 'AI Analyst generated incident report TH-001' }
  ]
};

export const initialLogs = [
  { id: 1, time: '09:42:11 PM', level: 'INFO', agent: 'Process Agent', process: 'bash (PID: 5110)', message: 'Process created: /bin/bash (PID: 5110)' },
  { id: 2, time: '09:42:01 PM', level: 'CRITICAL', agent: 'Network Agent', process: 'python3 (PID: 4458)', message: 'Connection to suspicious IP 185.220.101.45:443 blocked by firewall policy' },
  { id: 3, time: '09:41:58 PM', level: 'WARN', agent: 'File Agent', process: 'python3 (PID: 4458)', message: 'File modified: /tmp/klog_dump.txt' },
  { id: 4, time: '09:41:52 PM', level: 'CRITICAL', agent: 'Keyboard Agent', process: 'unknown (PID: 4458)', message: 'Suspicious keyboard hook detected on /dev/input/event3 (PID: 4458)' },
  { id: 5, time: '09:41:45 PM', level: 'WARN', agent: 'Persistence Agent', process: 'systemd32', message: 'Startup entry added: ~/.config/autostart/keylogger.desktop' },
  { id: 6, time: '09:41:35 PM', level: 'INFO', agent: 'Cron Agent', process: 'systemd', message: 'Scheduled security scan executed cleanly' },
  { id: 7, time: '09:41:30 PM', level: 'WARN', agent: 'Threat Engine', process: 'Orchestrator', message: 'High risk behavior detected (Score: 85.0)' },
  { id: 8, time: '09:41:25 PM', level: 'INFO', agent: 'AI Analyst', process: 'Ollama Engine', message: 'Analysis completed for threat incident TH-001' },
  { id: 9, time: '09:41:19 PM', level: 'INFO', agent: 'Cloud Agent', process: 'CloudSync', message: 'Sanitized security telemetry synchronized to cloud endpoint' }
];

export const initialReports = [
  {
    id: 'REP-001',
    title: 'Daily Security Report',
    date: 'Sep 14, 2026',
    threatsCount: 12,
    highSeverityCount: 4,
    status: 'Generated',
    healthScore: '98%',
    summary: 'Daily breakdown of security incidents, agent activity, and threat neutralization results.'
  },
  {
    id: 'REP-002',
    title: 'Weekly Security Digest',
    date: 'Sep 08 - Sep 14, 2026',
    threatsCount: 45,
    highSeverityCount: 11,
    status: 'Generated',
    healthScore: '96%',
    summary: 'Comprehensive 7-day trend analysis of keylogger attempts, persistence removal, and network socket blocks.'
  },
  {
    id: 'REP-003',
    title: 'Threat Incident Deep-Dive',
    date: 'Sep 14, 2026',
    threatsCount: 6,
    highSeverityCount: 3,
    status: 'Generated',
    healthScore: '94%',
    summary: 'Detailed technical analysis of Threat TH-001 and multi-vector attack footprints.'
  },
  {
    id: 'REP-004',
    title: 'Agent Activity & Health Audit',
    date: 'Sep 14, 2026',
    threatsCount: 0,
    highSeverityCount: 0,
    status: 'Generated',
    healthScore: '100%',
    summary: 'System uptime metrics, scan loop frequencies, and agent heartbeat records for all 9 monitoring units.'
  }
];

export const initialCloudState = {
  status: 'Connected',
  targetEndpoint: 'https://api.sentinel-cloud.net/v1/telemetry',
  lastSync: 'Sep 14, 2026 09:35 PM',
  nextSync: 'In 24 minutes',
  eventsSynced: 124,
  deviceId: 'SENTINEL-DEV-001',
  syncFrequency: 'Every 30 minutes',
  syncedItems: [
    { name: 'Threat Events (Sanitized)', enabled: true },
    { name: 'System Logs (Non-Sensitive)', enabled: true },
    { name: 'Agent Health Status', enabled: true },
    { name: 'Generated Security Reports', enabled: true },
    { name: 'Device Telemetry Information', enabled: true }
  ],
  privacyNotice: 'Privacy Guaranteed: Sentinel AI never records or uploads raw keystrokes. Only sanitized behavioral security telemetry is synchronized.'
};

export const initialSettings = {
  systemName: 'Sentinel AI Local Agent',
  theme: 'Dark (SOC Standard)',
  nodeIdentifier: 'sentinel-local-node-01',
  processInterval: '2.0s',
  networkInterval: '2.0s',
  filePaths: '/tmp, /var/log, ~/.config/autostart',
  highThreatThreshold: 75,
  mediumThreatThreshold: 50,
  aiProvider: 'Local Ollama LLM',
  aiModel: 'qwen2.5-coder:3b',
  mitigationMode: 'User Authorization Required (Strict Confirm)',
  c2Blacklist: '185.220.101.45, 192.168.1.100',
  autoCheckUpdates: true,
  minimizeToSystemTray: true,
  startOnBoot: true
};

export const initialUserProfile = {
  name: 'Veera Babu',
  email: 'veera.babu@example.com',
  role: 'Administrator',
  memberSince: 'Aug 20, 2026',
  lastLogin: 'Sep 14, 2026 09:41 PM',
  avatarText: 'VB',
  twoFactorEnabled: true,
  activeSessions: [
    { device: 'Linux Workstation (Ubuntu 24.04 LTS)', ip: '127.0.0.1 (Local)', current: true },
    { device: 'Sentinel Cloud Mobile Console', ip: '192.168.1.105', current: false }
  ]
};

export const initialDocs = [
  {
    id: 'getting-started',
    title: 'Getting Started with Sentinel AI',
    content: `Sentinel AI is a behavior-based cybersecurity system designed to detect and neutralize software keyloggers on Linux systems without logging raw keystrokes.

Key Features:
1. Behavior-Based Detection: Monitors process creation, input device binding (/dev/input/event*), file tampering, and outbound network sockets.
2. Centralized Orchestrator Architecture: All monitoring agents send telemetry through the Orchestrator bus to the Threat Engine.
3. Local AI Security Analyst: Integrated with local Ollama LLM (qwen2.5-coder:3b) to provide clear explanations and defensive action recommendations.
4. User Authorization Required: Potentially destructive actions (killing processes, blocking IPs) require explicit user confirmation.`
  },
  {
    id: 'monitoring-agents',
    title: 'Monitoring Agents Architecture',
    content: `Sentinel AI utilizes 9 independent monitoring agents:
- Process Monitor Agent: Catalogs user-space processes and tracks parent PIDs.
- Keyboard Hook Agent: Inspects raw character device stream bindings safely.
- File Activity Agent: Detects keystroke file dumps and log file modifications.
- Network Monitor Agent: Checks outbound sockets against C2 threat blacklists.
- Persistence Agent: Tracks autostart desktop files and systemd service additions.
- Threat Engine Agent: Evaluates weighted heuristics to calculate real-time threat scores.
- AI Security Analyst Agent: Generates natural language incident analysis.
- Logging Agent: Maintains structured circular audit logs.
- Cron Automation Agent: Schedules periodic security scans.`
  },
  {
    id: 'mitigation-safety',
    title: 'Defensive Actions & Safety Protocols',
    content: `Safety Policy:
- Sentinel AI NEVER automatically executes shell commands without explicit user consent.
- All defensive actions (terminate process, deny network IP, delete autostart entry) present a clear confirmation dialog before execution.
- Executed actions are recorded in an audit trail for accountability.`
  }
];
