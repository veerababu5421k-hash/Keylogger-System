import React, { useState, useEffect, useRef } from 'react';
import './App.css';
import {
  initialAgents,
  initialEvents,
  initialThreats,
  initialIncident,
  initialLogs,
  initialReports,
  initialCloudState,
  initialSettings,
  initialUserProfile,
  initialDocs
} from './data/mockData';

const API_BASE = 'http://localhost:8000/api';

const formatTimeNow = () => {
  const d = new Date();
  return d.toLocaleTimeString([], { hour12: true });
};

export default function App() {
  // Navigation & Workspace State (16 Pages)
  const [activeTab, setActiveTab] = useState('dashboard');
  const [liveMode, setLiveMode] = useState(false);
  const [protectionActive, setProtectionActive] = useState(true);
  const [uptime, setUptime] = useState(10152); // ~2h 49m
  const [threatScore, setThreatScore] = useState(68);
  const [searchQuery, setSearchQuery] = useState('');
  const [preventionBanner, setPreventionBanner] = useState(null);
  
  // Datasets
  const [agents, setAgents] = useState(initialAgents);
  const [recentEvents, setRecentEvents] = useState(initialEvents);
  const [threats, setThreats] = useState(initialThreats);
  const [selectedIncident, setSelectedIncident] = useState(initialIncident);
  const [logs, setLogs] = useState(initialLogs);
  const [reports, setReports] = useState(initialReports);
  const [cloudState, setCloudState] = useState(initialCloudState);
  const [settings, setSettings] = useState(initialSettings);
  const [userProfile, setUserProfile] = useState(initialUserProfile);
  const [docs] = useState(initialDocs);

  // Active Sub-tabs & Modals
  const [incidentTab, setIncidentTab] = useState('overview'); // overview, evidence, ai, mitigation, timeline
  const [aiSubTab, setAiSubTab] = useState('analysis'); // analysis, chat
  const [reportsTab, setReportsTab] = useState('daily');
  const [settingsTab, setSettingsTab] = useState('general');
  const [profileTab, setProfileTab] = useState('profile');
  const [docsTab, setDocsTab] = useState('getting-started');

  // Confirmation Modal State
  const [confirmModal, setConfirmModal] = useState(null); // { title, command, actionName, onConfirm }

  // AI Chat State
  const [chatHistory, setChatHistory] = useState([
    { sender: 'user', text: 'Why was process PID 4458 flagged as a keylogger?' },
    { sender: 'ai', text: 'Sentinel AI detected raw input character stream binding (/dev/input/event3), autostart entry creation in ~/.config/autostart, and an outbound socket to C2 server 185.220.101.45.' }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [isChatLoading, setIsChatLoading] = useState(false);
  const chatBottomRef = useRef(null);

  // Filters
  const [logFilterLevel, setLogFilterLevel] = useState('ALL');
  const [logFilterAgent, setLogFilterAgent] = useState('ALL');
  const [eventFilterAgent, setEventFilterAgent] = useState('ALL');
  const [eventFilterSeverity, setEventFilterSeverity] = useState('ALL');
  const [isMonitoringPaused, setIsMonitoringPaused] = useState(false);

  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatHistory, isChatLoading]);

  // Live Backend Polling Integration
  const fetchLiveData = async () => {
    if (isMonitoringPaused) return;
    try {
      const res = await fetch(`${API_BASE}/status`);
      if (res.ok) {
        const data = await res.json();
        setLiveMode(data.agent_live !== false);
        setUptime(data.uptime || 10152);
        if (data.protection_enabled !== undefined) {
          setProtectionActive(data.protection_enabled);
        }
      } else {
        setLiveMode(false);
      }

      const alertsRes = await fetch(`${API_BASE}/alerts`);
      if (alertsRes.ok) {
        const alertsData = await alertsRes.json();
        if (Array.isArray(alertsData) && alertsData.length > 0) {
          const mappedEvents = alertsData.map((a, i) => ({
            id: `EVT-API-${i}`,
            time: a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : formatTimeNow(),
            agent: (a.module || "process").replace("_", " ").toUpperCase(),
            event: a.extra_data?.event_type || a.message?.split(':')[0] || "Alert Triggered",
            process: `PID: ${a.pid || 4521}`,
            details: a.message || `Process PID: ${a.pid}`,
            severity: a.level === "CRITICAL" || a.risk_score >= 80 ? "High" : a.risk_score >= 50 ? "Medium" : "Low",
            score: a.risk_score || 75,
            pid: a.pid || 4521
          }));
          setRecentEvents(mappedEvents);
        }
      }

      const logsRes = await fetch(`${API_BASE}/logs`);
      if (logsRes.ok) {
        const logsData = await logsRes.json();
        if (Array.isArray(logsData) && logsData.length > 0) {
          const mappedLogs = logsData.map((line, idx) => ({
            id: idx,
            time: formatTimeNow(),
            level: line.includes('CRITICAL') || line.includes('PREVENTION') ? 'CRITICAL' : line.includes('WARNING') ? 'WARN' : 'INFO',
            agent: 'Syslog',
            process: 'Orchestrator',
            message: line
          }));
          setLogs(mappedLogs);
        }
      }
    } catch {
      setLiveMode(false);
    }
  };

  useEffect(() => {
    fetchLiveData();
    const interval = setInterval(fetchLiveData, 2500);
    return () => clearInterval(interval);
  }, [isMonitoringPaused]);

  // Actions
  const toggleProtection = async () => {
    const nextState = !protectionActive;
    setProtectionActive(nextState);

    if (liveMode) {
      try {
        await fetch(`${API_BASE}/protection/toggle`, { method: 'POST' });
      } catch (err) {
        console.error("Failed to toggle backend protection:", err);
      }
    }

    if (!nextState) {
      setPreventionBanner("🛑 PROTECTION PAUSED: Active threat neutralization is PAUSED.");
    } else {
      setPreventionBanner("🛡️ PROTECTION ACTIVE: Multi-agent threat monitoring & defensive neutralization are ACTIVE.");
      setTimeout(() => setPreventionBanner(null), 4000);
    }
  };

  const executeDefensiveCommand = (commandName, commandStr) => {
    setConfirmModal({
      title: `Confirm Security Action: ${commandName}`,
      command: commandStr,
      actionName: commandName,
      onConfirm: () => {
        setPreventionBanner(`✅ ACTION EXECUTED: '${commandStr}' recorded in audit trail.`);
        setLogs(prev => [
          {
            id: Date.now(),
            time: formatTimeNow(),
            level: 'CRITICAL',
            agent: 'Defensive Action',
            process: 'User Confirmed',
            message: `Executed command: ${commandStr}`
          },
          ...prev
        ]);
        setConfirmModal(null);
        setTimeout(() => setPreventionBanner(null), 4000);
      }
    });
  };

  const triggerAttackSimulation = async () => {
    if (!protectionActive) {
      setPreventionBanner("⚠️ Cannot trigger simulation: System Protection is currently PAUSED.");
      setTimeout(() => setPreventionBanner(null), 4000);
      return;
    }

    setPreventionBanner("🔥 SIMULATION INITIATED: Injecting synthetic keylogger telemetry pipeline...");
    if (liveMode) {
      try {
        await fetch(`${API_BASE}/simulate_malware`, { method: 'POST' });
        fetchLiveData();
      } catch (err) {
        console.error("Malware simulation failed:", err);
      }
    } else {
      const timeStr = formatTimeNow();
      const simEvent = {
        id: `EVT-SIM-${Date.now()}`,
        time: timeStr,
        agent: 'Keyboard Agent',
        event: 'Malware Keylogger Hook',
        process: 'python3 /tmp/keylogger_hook.py (PID: 4458)',
        details: '/dev/input/event3 descriptor access attempt',
        severity: 'High',
        score: 95,
        pid: 4458
      };
      setRecentEvents(prev => [simEvent, ...prev]);
      setThreatScore(95);
      setLogs(prev => [
        {
          id: Date.now(),
          time: timeStr,
          level: 'CRITICAL',
          agent: 'Threat Engine',
          process: 'PID: 4458',
          message: 'Keylogger multi-vector attack detected (Score 95.0)'
        },
        ...prev
      ]);
    }

    setTimeout(() => {
      setPreventionBanner("🛡️ THREAT NEUTRALIZED: Simulated keylogger PID 4458 process & sockets blocked!");
      setTimeout(() => setPreventionBanner(null), 4000);
    }, 1000);
  };

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const userMsg = { sender: 'user', text: chatInput };
    setChatHistory(prev => [...prev, userMsg]);
    const prompt = chatInput;
    setChatInput('');
    setIsChatLoading(true);

    if (liveMode) {
      try {
        const res = await fetch(`${API_BASE}/chat`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ prompt, context_alert: selectedIncident })
        });
        if (res.ok) {
          const data = await res.json();
          setChatHistory(prev => [...prev, { sender: 'ai', text: data.reply }]);
        } else {
          setChatHistory(prev => [...prev, { sender: 'ai', text: 'Error contacting Sentinel AI backend.' }]);
        }
      } catch {
        setChatHistory(prev => [...prev, { sender: 'ai', text: 'Unable to communicate with local Ollama service.' }]);
      }
    } else {
      setTimeout(() => {
        let reply = `Sentinel AI Analysis: Process PID 4458 bound raw character device descriptors (/dev/input/event3) and attempted exfiltration to 185.220.101.45. Recommend executing 'kill -9 4458' after user confirmation.`;
        if (prompt.toLowerCase().includes('hello') || prompt.toLowerCase().includes('hi')) {
          reply = "Greetings! I am Sentinel AI, your behavior-based security analyst. How can I assist with threat investigation?";
        }
        setChatHistory(prev => [...prev, { sender: 'ai', text: reply }]);
      }, 500);
    }
    setIsChatLoading(false);
  };

  // Nav Items
  const navigationItems = [
    { id: 'dashboard', label: 'Dashboard', icon: '📊' },
    { id: 'live_monitoring', label: 'Live Monitoring', icon: '⚡' },
    { id: 'agents', label: 'Agents', icon: '🛡️' },
    { id: 'threats', label: 'Threats', icon: '🎯', badge: threats.filter(t => t.status === 'Open').length },
    { id: 'incident_details', label: 'Incident Details', icon: '📌' },
    { id: 'ai_analyst', label: 'AI Security Analyst', icon: '🤖' },
    { id: 'mitigation', label: 'Mitigation', icon: '🛠️' },
    { id: 'logs', label: 'Logs', icon: '📋' },
    { id: 'reports', label: 'Reports', icon: '📄' },
    { id: 'cloud_sync', label: 'Cloud Sync', icon: '☁️' },
    { id: 'settings', label: 'Settings', icon: '⚙️' },
    { id: 'profile', label: 'User Profile', icon: '👤' },
    { id: 'test_mode', label: 'Mock / Test Mode', icon: '🧪' },
    { id: 'documentation', label: 'Help & Docs', icon: '❓' }
  ];

  // Filtering
  const filteredEvents = recentEvents.filter(evt => {
    if (eventFilterAgent !== 'ALL' && !evt.agent.toLowerCase().includes(eventFilterAgent.toLowerCase())) return false;
    if (eventFilterSeverity !== 'ALL' && evt.severity.toLowerCase() !== eventFilterSeverity.toLowerCase()) return false;
    if (searchQuery && !JSON.stringify(evt).toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  const filteredLogs = logs.filter(log => {
    if (logFilterLevel !== 'ALL' && log.level !== logFilterLevel) return false;
    if (logFilterAgent !== 'ALL' && !log.agent.toLowerCase().includes(logFilterAgent.toLowerCase())) return false;
    if (searchQuery && !JSON.stringify(log).toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="sentinel-app">
      {/* TOP HEADER BAR */}
      <header className="top-header-bar">
        <div className="top-left-brand">
          <div className="brand-shield-icon">🛡️</div>
          <div className="brand-text-stack">
            <span className="brand-title">Sentinel AI</span>
            <span className="brand-subtitle">Behavior-Based Keylogger Detection</span>
          </div>
        </div>

        <div className="top-search-wrapper">
          <input
            type="text"
            className="top-search-input"
            placeholder="Search processes, alerts, or ask AI..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="top-tagline-text" style={{ display: 'none', minWidth: '240px' }}>
          DETECT | ANALYZE | EXPLAIN | PROTECT
        </div>

        <div className="top-right-meta">
          <div className="date-time-display">
            <span>📅 {new Date().toLocaleDateString()}</span>
            <span>⏱️ {formatTimeNow()}</span>
          </div>

          <div className="status-pill-live">
            <span className="dot-pulse-green"></span>
            <span>{liveMode ? 'AGENT LIVE' : 'SIMULATION MODE'}</span>
          </div>

          <button 
            className="btn-action-secondary"
            onClick={() => setActiveTab('login')}
            style={{ padding: '4px 10px', fontSize: '10px' }}
          >
            🔒 Sign Out
          </button>
        </div>
      </header>

      {/* BANNER NOTIFICATION */}
      {preventionBanner && (
        <div style={{
          background: 'linear-gradient(90deg, #0F172A, #1E293B)',
          borderBottom: '2px solid #3B82F6',
          color: '#60A5FA',
          padding: '8px 16px',
          textAlign: 'center',
          fontSize: '11px',
          fontWeight: '700',
          fontFamily: 'var(--font-mono)'
        }}>
          {preventionBanner}
        </div>
      )}

      {/* WORKSPACE BODY */}
      <div className="app-workspace-body">
        {/* PERSISTENT LEFT SIDEBAR */}
        <aside className="sidebar-sticky">
          <div style={{ fontSize: '10px', fontWeight: '800', color: 'var(--accent-blue-bright)', letterSpacing: '1px', fontFamily: 'var(--font-mono)', paddingLeft: '4px' }}>
            NAVIGATION MODULES
          </div>

          <nav className="sidebar-nav-list">
            {navigationItems.map(item => (
              <button
                key={item.id}
                className={`sidebar-nav-button ${activeTab === item.id ? 'active' : ''}`}
                onClick={() => setActiveTab(item.id)}
              >
                <div className="nav-item-left">
                  <span className="nav-item-icon">{item.icon}</span>
                  <span>{item.label}</span>
                </div>
                {item.badge > 0 && (
                  <span className="sidebar-badge-count">{item.badge}</span>
                )}
              </button>
            ))}
          </nav>

          <div className="sidebar-footer-card">
            <div className="sidebar-user-row">
              <div className="user-avatar-badge">{userProfile.avatarText}</div>
              <div className="user-info-stack">
                <span className="user-name-text">{userProfile.name}</span>
                <span className="user-role-text">{userProfile.role}</span>
              </div>
            </div>

            <button
              className={`btn-action-${protectionActive ? 'danger' : 'primary'}`}
              style={{ width: '100%', justifyContent: 'center', padding: '6px' }}
              onClick={toggleProtection}
            >
              <span>{protectionActive ? '🛑 Pause Protection' : '▶️ Resume Protection'}</span>
            </button>

            <div className="sidebar-version-tag">
              <span>Status: {protectionActive ? 'ENABLED' : 'PAUSED'}</span>
              <span>v1.0.0</span>
            </div>
          </div>
        </aside>

        {/* MAIN VIEW AREA */}
        <main className="main-view-container">

          {/* PAGE 01: DASHBOARD */}
          {activeTab === 'dashboard' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="section-header-banner">
                <div>
                  <div className="section-title-large">📊 SENTINEL AI SECURITY DASHBOARD</div>
                  <div className="section-subtitle">Behavior-based software keylogger threat detection & mitigation telemetry</div>
                </div>
                <button className="btn-action-primary" onClick={triggerAttackSimulation}>
                  🔥 Trigger Attack Simulation
                </button>
              </div>

              {/* OVERVIEW STAT CARDS */}
              <div className="metrics-quad-grid">
                <div className="stat-card-box">
                  <div className="stat-card-top">
                    <span className="stat-title">Overall Threat Level</span>
                    <span style={{ fontSize: '18px' }}>🛡️</span>
                  </div>
                  <div className="stat-val-large" style={{ color: 'var(--accent-red)' }}>HIGH</div>
                  <div className="stat-sub-detail">Score: {threatScore} / 100</div>
                  <div className="progress-bar-thin">
                    <div className="progress-fill-red" style={{ width: `${threatScore}%` }}></div>
                  </div>
                </div>

                <div className="stat-card-box">
                  <div className="stat-card-top">
                    <span className="stat-title">Active Alerts</span>
                    <span style={{ fontSize: '18px' }}>🔔</span>
                  </div>
                  <div className="stat-val-large">{threats.filter(t => t.status === 'Open').length}</div>
                  <div className="stat-sub-detail">High Risk Incidents</div>
                </div>

                <div className="stat-card-box">
                  <div className="stat-card-top">
                    <span className="stat-title">Monitored Processes</span>
                    <span style={{ fontSize: '18px' }}>📈</span>
                  </div>
                  <div className="stat-val-large">143</div>
                  <div className="stat-sub-detail">Active user-space PIDs</div>
                </div>

                <div className="stat-card-box">
                  <div className="stat-card-top">
                    <span className="stat-title">System Uptime</span>
                    <span style={{ fontSize: '18px' }}>⏱️</span>
                  </div>
                  <div className="stat-val-large" style={{ fontSize: '18px' }}>1d 6h 32m</div>
                  <div className="stat-sub-detail">Continuous agent uptime</div>
                </div>
              </div>

              {/* AGENT STATUS ROW */}
              <div className="panel-card">
                <div className="panel-card-header">
                  <span className="panel-card-title">🛡️ Monitoring Agents Health Matrix</span>
                  <button className="btn-action-secondary" onClick={() => setActiveTab('agents')}>
                    Manage All 9 Agents →
                  </button>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px' }}>
                  {agents.map(ag => (
                    <div key={ag.id} style={{ background: '#070B14', border: '1px solid var(--card-border)', padding: '12px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '12px', fontWeight: '700', color: '#FFF' }}>{ag.name}</div>
                      <div style={{ fontSize: '10px', color: 'var(--accent-green)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
                        ● {ag.status} (Events: {ag.eventsGenerated})
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* SPLIT GRID: RECENT EVENTS & AI ANALYST PREVIEW */}
              <div className="layout-split-grid">
                <div className="panel-card">
                  <div className="panel-card-header">
                    <span className="panel-card-title">⚡ Recent Security Event Stream</span>
                    <button className="btn-action-secondary" onClick={() => setActiveTab('live_monitoring')}>
                      View Live Monitoring →
                    </button>
                  </div>
                  <div className="custom-table-container">
                    <table className="styled-table">
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Agent</th>
                          <th>Event Type</th>
                          <th>Process</th>
                          <th>Severity</th>
                        </tr>
                      </thead>
                      <tbody>
                        {recentEvents.slice(0, 6).map((row, idx) => (
                          <tr key={idx} onClick={() => setActiveTab('incident_details')}>
                            <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{row.time}</td>
                            <td style={{ fontWeight: '600', color: 'var(--accent-blue-bright)' }}>{row.agent}</td>
                            <td>{row.event}</td>
                            <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>{row.process}</td>
                            <td><span className={`badge-tag ${row.severity.toLowerCase()}`}>{row.severity}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="panel-card">
                  <div className="panel-card-header">
                    <span className="panel-card-title">🤖 AI Analyst Summary</span>
                    <button className="btn-action-secondary" onClick={() => setActiveTab('ai_analyst')}>
                      Console →
                    </button>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-main)', lineHeight: '1.6', background: '#070B14', padding: '12px', borderRadius: '6px', border: '1px solid var(--card-border)' }}>
                    <strong>Incident TH-001 Footprint:</strong><br />
                    Process PID 4458 bound raw character device descriptors (/dev/input/event*) and initiated autostart persistence in ~/.config/autostart. Recommended defensive termination.
                  </div>
                  <div style={{ marginTop: '12px', display: 'flex', gap: '8px' }}>
                    <button 
                      className="btn-action-danger" 
                      style={{ flex: 1, justifyContent: 'center' }}
                      onClick={() => executeDefensiveCommand('Terminate Keylogger', 'kill -9 4458')}
                    >
                      kill -9 4458
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* PAGE 02: LIVE MONITORING */}
          {activeTab === 'live_monitoring' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="section-header-banner">
                <div>
                  <div className="section-title-text">⚡ REAL-TIME MONITORING STREAM</div>
                  <div className="section-subtitle">Privacy-aware behavioral telemetry stream (zero raw keystrokes captured)</div>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button 
                    className={`btn-action-${isMonitoringPaused ? 'primary' : 'secondary'}`}
                    onClick={() => setIsMonitoringPaused(!isMonitoringPaused)}
                  >
                    {isMonitoringPaused ? '▶️ Resume Stream' : '⏸️ Pause Stream'}
                  </button>
                  <button className="btn-action-secondary" onClick={() => setRecentEvents([])}>
                    🗑️ Clear Events
                  </button>
                </div>
              </div>

              {/* FILTERS ROW */}
              <div style={{ display: 'flex', gap: '12px', alignItems: 'center', background: 'var(--bg-card)', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--card-border)' }}>
                <span style={{ fontSize: '11px', fontWeight: '700', color: 'var(--accent-blue-bright)', fontFamily: 'var(--font-mono)' }}>FILTERS:</span>
                <select className="select-dropdown-small" value={eventFilterAgent} onChange={(e) => setEventFilterAgent(e.target.value)}>
                  <option value="ALL">All Agents</option>
                  <option value="Process">Process Agent</option>
                  <option value="Keyboard">Keyboard Agent</option>
                  <option value="File">File Activity</option>
                  <option value="Network">Network Monitor</option>
                  <option value="Persistence">Persistence Agent</option>
                </select>

                <select className="select-dropdown-small" value={eventFilterSeverity} onChange={(e) => setEventFilterSeverity(e.target.value)}>
                  <option value="ALL">All Severities</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>

              <div className="panel-card">
                <div className="custom-table-container">
                  <table className="styled-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Agent</th>
                        <th>Event Type</th>
                        <th>Target Process</th>
                        <th>Telemetry Details</th>
                        <th>Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredEvents.map((row, idx) => (
                        <tr key={idx}>
                          <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{row.time}</td>
                          <td style={{ fontWeight: '600', color: 'var(--accent-blue-bright)' }}>{row.agent}</td>
                          <td>{row.event}</td>
                          <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>{row.process}</td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>{row.details}</td>
                          <td><span className={`badge-tag ${row.severity.toLowerCase()}`}>{row.severity}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* PAGE 03: AGENTS */}
          {activeTab === 'agents' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="section-header-banner">
                <div>
                  <div className="section-title-large">🛡️ AGENT MANAGEMENT & ARCHITECTURE</div>
                  <div className="section-subtitle">Lifecycle management for all 9 independent monitoring and analytics agents</div>
                </div>
              </div>

              {/* ORCHESTRATOR DIAGRAM */}
              <div className="orchestrator-flow-box">
                <div style={{ fontSize: '11px', fontWeight: '800', color: 'var(--accent-blue-bright)', fontFamily: 'var(--font-mono)' }}>
                  DECOUPLED MULTI-AGENT ARCHITECTURE (ZERO AGENT-TO-AGENT DIRECT CONNECTIONS)
                </div>
                <div className="flow-node-row">
                  <span className="flow-node-pill">Process Agent</span>
                  <span className="flow-node-pill">Keyboard Agent</span>
                  <span className="flow-node-pill">File Agent</span>
                  <span className="flow-node-pill">Network Agent</span>
                  <span className="flow-node-pill">Persistence Agent</span>
                </div>
                <div className="flow-arrow-down">⬇️ (Telemetry Event Bus) ⬇️</div>
                <div className="flow-hub-orchestrator">CENTRAL ORCHESTRATOR BUS</div>
                <div className="flow-arrow-down">⬇️ (Evaluated Stream) ⬇️</div>
                <div className="flow-node-row">
                  <span className="flow-node-pill" style={{ borderColor: 'var(--accent-red)' }}>Threat Engine Matrix</span>
                  <span className="flow-node-pill" style={{ borderColor: 'var(--accent-indigo)' }}>AI Security Analyst</span>
                  <span className="flow-node-pill" style={{ borderColor: 'var(--accent-green)' }}>Logging & Cloud Sync</span>
                </div>
              </div>

              {/* AGENTS GRID */}
              <div className="agents-cards-grid">
                {agents.map(ag => (
                  <div key={ag.id} className="agent-card-box">
                    <div className="agent-card-header">
                      <div className="agent-title-text">{ag.name}</div>
                      <span className="badge-tag running">{ag.status}</span>
                    </div>

                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{ag.description}</div>

                    <div className="agent-stats-list">
                      • Uptime: <strong>{ag.uptime}</strong><br />
                      • Heartbeat: <strong>{ag.heartbeat}</strong><br />
                      • Events Generated: <strong>{ag.eventsGenerated}</strong><br />
                      • Subsystem: <strong>{ag.target}</strong><br />
                      • CPU: <strong>{ag.cpu}</strong> | RAM: <strong>{ag.memory}</strong>
                    </div>

                    <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
                      <button className="btn-action-secondary" style={{ flex: 1, justifyContent: 'center' }} onClick={() => setPreventionBanner(`⚡ Manual scan triggered for ${ag.name}`)}>
                        ⚡ Scan
                      </button>
                      <button className="btn-action-secondary" style={{ flex: 1, justifyContent: 'center' }} onClick={() => setActiveTab('logs')}>
                        📋 Logs
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* PAGE 04: THREATS */}
          {activeTab === 'threats' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="section-header-banner">
                <div>
                  <div className="section-title-large">🎯 THREAT INCIDENT MANAGEMENT</div>
                  <div className="section-subtitle">Catalog of detected software keylogger footprints and risk evaluations</div>
                </div>
              </div>

              <div className="panel-card">
                <div className="custom-table-container">
                  <table className="styled-table">
                    <thead>
                      <tr>
                        <th>Threat ID</th>
                        <th>Threat Title</th>
                        <th>Affected Process</th>
                        <th>Score</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Detected At</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {threats.map((row, idx) => (
                        <tr key={idx}>
                          <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-blue-bright)', fontWeight: '700' }}>{row.id}</td>
                          <td style={{ fontWeight: '700' }}>{row.title}</td>
                          <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>{row.process}</td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontWeight: '800', color: 'var(--accent-red)' }}>{row.score}/100</td>
                          <td><span className={`badge-tag ${row.severity.toLowerCase()}`}>{row.severity}</span></td>
                          <td><span className={`badge-tag ${row.status.toLowerCase()}`}>{row.status}</span></td>
                          <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{row.detectedAt}</td>
                          <td>
                            <button className="btn-action-secondary" style={{ padding: '4px 8px', fontSize: '10px' }} onClick={() => { setSelectedIncident(initialIncident); setActiveTab('incident_details'); }}>
                              Investigate →
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* PAGE 05: INCIDENT DETAILS */}
          {activeTab === 'incident_details' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="section-header-banner">
                <div>
                  <div className="section-title-large">📌 INCIDENT BREAKDOWN: {selectedIncident.id}</div>
                  <div className="section-subtitle">{selectedIncident.title} ({selectedIncident.detectedAt})</div>
                </div>
                <button className="btn-action-secondary" onClick={() => setActiveTab('threats')}>
                  ← Back to Threats
                </button>
              </div>

              {/* METADATA GRID */}
              <div className="metrics-quad-grid">
                <div className="stat-card-box">
                  <div className="stat-title">Threat Score</div>
                  <div className="stat-val-large" style={{ color: 'var(--accent-red)' }}>{selectedIncident.threatScore} / 100</div>
                  <div className="stat-sub-detail">Confidence: {selectedIncident.confidence}</div>
                </div>
                <div className="stat-card-box">
                  <div className="stat-title">Risk Level</div>
                  <div className="stat-val-large" style={{ color: 'var(--accent-red)' }}>HIGH</div>
                  <div className="stat-sub-detail">Input Hook & C2 Socket</div>
                </div>
                <div className="stat-card-box">
                  <div className="stat-title">Target Process</div>
                  <div className="stat-val-large" style={{ fontSize: '16px' }}>PID: {selectedIncident.pid}</div>
                  <div className="stat-sub-detail">python3 /tmp/keylogger_hook.py</div>
                </div>
                <div className="stat-card-box">
                  <div className="stat-title">Incident Status</div>
                  <div className="stat-val-large" style={{ color: 'var(--accent-yellow)', fontSize: '18px' }}>OPEN</div>
                  <div className="stat-sub-detail">Action Required</div>
                </div>
              </div>

              {/* INCIDENT TABS */}
              <div className="panel-card">
                <div className="tabs-header-row">
                  {['overview', 'evidence', 'ai_analysis', 'mitigation', 'timeline'].map(t => (
                    <button key={t} className={`tab-btn ${incidentTab === t ? 'active' : ''}`} onClick={() => setIncidentTab(t)}>
                      {t.toUpperCase().replace('_', ' ')}
                    </button>
                  ))}
                </div>

                <div style={{ marginTop: '16px' }}>
                  {incidentTab === 'overview' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      <p style={{ fontSize: '12px', color: 'var(--text-main)', lineHeight: '1.6' }}>{selectedIncident.description}</p>
                      <div style={{ fontSize: '12px', fontWeight: '700', color: 'var(--accent-blue-bright)' }}>Possible Impact:</div>
                      <ul style={{ paddingLeft: '20px', fontSize: '11px', color: 'var(--text-dim)', lineHeight: '1.8' }}>
                        {selectedIncident.possibleImpact.map((item, i) => <li key={i}>{item}</li>)}
                      </ul>
                    </div>
                  )}

                  {incidentTab === 'evidence' && (
                    <div className="custom-table-container">
                      <table className="styled-table">
                        <thead>
                          <tr>
                            <th>Behavioral Indicator</th>
                            <th>Subsystem Telemetry Detail</th>
                            <th>Risk Contribution</th>
                          </tr>
                        </thead>
                        <tbody>
                          {selectedIncident.evidence.map((ev, i) => (
                            <tr key={i}>
                              <td style={{ fontWeight: '700', color: 'var(--accent-blue-bright)' }}>{ev.type}</td>
                              <td style={{ fontFamily: 'var(--font-mono)' }}>{ev.detail}</td>
                              <td><span className={`badge-tag ${ev.risk.toLowerCase()}`}>{ev.risk}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {incidentTab === 'ai_analysis' && (
                    <pre style={{ background: '#070B14', padding: '14px', borderRadius: '6px', border: '1px solid var(--card-border)', color: '#60A5FA', fontSize: '11px', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap' }}>
                      {selectedIncident.aiAnalysis}
                    </pre>
                  )}

                  {incidentTab === 'mitigation' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      {selectedIncident.mitigationCommands.map((cmd) => (
                        <div key={cmd.id} className="command-copy-row">
                          <div>
                            <div style={{ color: '#FFF', fontWeight: '700' }}>{cmd.label}</div>
                            <div style={{ color: 'var(--accent-blue-bright)', fontSize: '11px', marginTop: '2px' }}>{cmd.command}</div>
                          </div>
                          <button className="btn-action-danger" onClick={() => executeDefensiveCommand(cmd.label, cmd.command)}>
                            Confirm Action
                          </button>
                        </div>
                      ))}
                    </div>
                  )}

                  {incidentTab === 'timeline' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {selectedIncident.timeline.map((step, i) => (
                        <div key={i} style={{ display: 'flex', gap: '12px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                          <span style={{ color: 'var(--text-muted)', minWidth: '100px' }}>{step.time}</span>
                          <span style={{ color: '#FFF' }}>{step.event}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* PAGE 06: AI SECURITY ANALYST */}
          {activeTab === 'ai_analyst' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="section-header-banner">
                <div>
                  <div className="section-title-large">🤖 AI SECURITY ANALYST CONSOLE</div>
                  <div className="section-subtitle">Local Ollama LLM (qwen2.5-coder:3b) reasoning & defensive analyst chat</div>
                </div>
              </div>

              <div className="panel-card">
                <div className="tabs-header-row">
                  <button className={`tab-btn ${aiSubTab === 'analysis' ? 'active' : ''}`} onClick={() => setAiSubTab('analysis')}>
                    TECHNICAL EXPLANATION & MITIGATION
                  </button>
                  <button className={`tab-btn ${aiSubTab === 'chat' ? 'active' : ''}`} onClick={() => setAiSubTab('chat')}>
                    INTERACTIVE ANALYST CHAT
                  </button>
                </div>

                {aiSubTab === 'analysis' ? (
                  <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <div className="layout-split-grid">
                      <div style={{ background: '#070B14', padding: '16px', borderRadius: '8px', border: '1px solid var(--card-border)' }}>
                        <div style={{ fontSize: '13px', fontWeight: '700', color: 'var(--accent-blue-bright)', marginBottom: '8px' }}>
                          Incident Footprint & Technical Explanation
                        </div>
                        <p style={{ fontSize: '11px', color: '#FFF', lineHeight: '1.6' }}>
                          The process <strong>'python3 /tmp/keylogger_hook.py (PID: 4458)'</strong> bound raw character device descriptors (/dev/input/event3), established autostart persistence in ~/.config/autostart, and opened an unwhitelisted remote socket to C2 server 185.220.101.45:443.
                        </p>
                      </div>

                      <div style={{ background: '#070B14', padding: '16px', borderRadius: '8px', border: '1px solid var(--card-border)' }}>
                        <div style={{ fontSize: '13px', fontWeight: '700', color: 'var(--accent-red)', marginBottom: '8px' }}>
                          Threat Assessment
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-dim)', lineHeight: '1.8', fontFamily: 'var(--font-mono)' }}>
                          • Risk Score: <strong style={{ color: 'var(--accent-red)' }}>68 / 100 (HIGH)</strong><br />
                          • Confidence: <strong>87%</strong><br />
                          • Attack Vector: <strong>Software Keylogger Hook</strong>
                        </div>
                      </div>
                    </div>

                    <div style={{ fontSize: '12px', fontWeight: '700', color: '#FFF' }}>Proposed Defensive Commands (Require User Confirmation):</div>
                    {selectedIncident.mitigationCommands.map((cmd) => (
                      <div key={cmd.id} className="command-copy-row">
                        <span>{cmd.command}</span>
                        <button className="btn-action-primary" onClick={() => executeDefensiveCommand(cmd.label, cmd.command)}>
                          Execute Command
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    <div className="ai-chat-box-area">
                      {chatHistory.map((msg, i) => (
                        <div key={i} className={msg.sender === 'user' ? 'chat-bubble-user' : 'chat-bubble-ai'}>
                          {msg.text}
                        </div>
                      ))}
                      {isChatLoading && <div className="chat-bubble-ai" style={{ opacity: 0.6 }}>Ollama reasoning in progress...</div>}
                      <div ref={chatBottomRef} />
                    </div>

                    <form className="chat-input-wrapper" onSubmit={handleSendMessage}>
                      <input
                        type="text"
                        className="chat-input-field"
                        placeholder="Ask Sentinel AI anything about keylogger detection..."
                        value={chatInput}
                        onChange={(e) => setChatInput(e.target.value)}
                        disabled={isChatLoading}
                      />
                      <button type="submit" className="btn-action-primary" disabled={isChatLoading}>Send</button>
                    </form>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* PAGE 07: MITIGATION */}
          {activeTab === 'mitigation' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="section-header-banner">
                <div>
                  <div className="section-title-large">🛠️ DEFENSIVE MITIGATION CONTROL</div>
                  <div className="section-subtitle">Explicit user-authorized threat neutralization and audit trail</div>
                </div>
              </div>

              <div className="panel-card">
                <div style={{ fontSize: '13px', fontWeight: '700', color: 'var(--accent-red)', marginBottom: '12px' }}>
                  ⚠️ DEFENSIVE ACTIONS REQUIRE EXPLICIT CONFIRMATION BEFORE EXECUTION
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '14px' }}>
                  {[
                    { action: 'Terminate Keylogger Process', cmd: 'kill -9 4458', desc: 'Safely terminate process PID 4458 running from /tmp.' },
                    { action: 'Block Outbound Network IP', cmd: 'sudo ufw deny out to 185.220.101.45', desc: 'Add UFW firewall rule blocking communication to remote C2 server.' },
                    { action: 'Remove Autostart Persistence', cmd: 'rm -f ~/.config/autostart/keylogger.desktop', desc: 'Delete autostart desktop entry preventing reboot survival.' }
                  ].map((item, idx) => (
                    <div key={idx} style={{ background: '#070B14', padding: '14px', borderRadius: '8px', border: '1px solid var(--card-border)' }}>
                      <div style={{ fontSize: '13px', fontWeight: '700', color: '#FFF' }}>{item.action}</div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', margin: '4px 0 10px 0' }}>{item.desc}</div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--accent-blue-bright)', marginBottom: '10px' }}>{item.cmd}</div>
                      <button className="btn-action-danger" style={{ width: '100%', justifyContent: 'center' }} onClick={() => executeDefensiveCommand(item.action, item.cmd)}>
                        Confirm & Execute
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* PAGE 08: LOGS */}
          {activeTab === 'logs' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="section-header-banner">
                <div>
                  <div className="section-title-large">📋 LOGGING TERMINAL & AUDIT TRAIL</div>
                  <div className="section-subtitle">Real-time log console inspection and historical audit logs</div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                <select className="select-dropdown-small" value={logFilterLevel} onChange={(e) => setLogFilterLevel(e.target.value)}>
                  <option value="ALL">All Levels</option>
                  <option value="INFO">INFO</option>
                  <option value="WARN">WARN</option>
                  <option value="CRITICAL">CRITICAL</option>
                </select>
              </div>

              <div className="panel-card">
                <div className="custom-table-container">
                  <table className="styled-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Level</th>
                        <th>Agent Source</th>
                        <th>Process</th>
                        <th>Log Message</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredLogs.map((row, idx) => (
                        <tr key={idx}>
                          <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{row.time}</td>
                          <td><span className={`badge-tag ${row.level.toLowerCase()}`}>{row.level}</span></td>
                          <td style={{ fontWeight: '700', color: 'var(--accent-blue-bright)' }}>{row.agent}</td>
                          <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>{row.process}</td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{row.message}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* PAGE 09: REPORTS */}
          {activeTab === 'reports' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="section-header-banner">
                <div>
                  <div className="section-title-large">📄 SECURITY DIGEST REPORTS</div>
                  <div className="section-subtitle">Generated academic and operational security summary reports</div>
                </div>
                <button className="btn-action-primary" onClick={() => setPreventionBanner("📄 Security Report generated cleanly.")}>
                  Generate Report
                </button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
                {reports.map((rep) => (
                  <div key={rep.id} className="panel-card">
                    <div style={{ fontSize: '14px', fontWeight: '700', color: '#FFF' }}>{rep.title}</div>
                    <div style={{ fontSize: '10px', color: 'var(--accent-blue-bright)', fontFamily: 'var(--font-mono)', margin: '4px 0 8px 0' }}>{rep.date}</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', lineHeight: '1.5' }}>{rep.summary}</div>
                    <div style={{ display: 'flex', gap: '8px', marginTop: '14px' }}>
                      <button className="btn-action-secondary" style={{ flex: 1, justifyContent: 'center' }}>View Report</button>
                      <button className="btn-action-secondary" style={{ flex: 1, justifyContent: 'center' }}>Download PDF</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* PAGE 10: CLOUD SYNC */}
          {activeTab === 'cloud_sync' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="section-header-banner">
                <div>
                  <div className="section-title-large">☁️ CLOUD SYNCHRONIZATION</div>
                  <div className="section-subtitle">Sanitized threat telemetry cloud endpoint synchronization</div>
                </div>
                <button className="btn-action-primary" onClick={() => setPreventionBanner("☁️ Telemetry synchronized cleanly to cloud endpoint.")}>
                  Sync Now
                </button>
              </div>

              <div className="panel-card">
                <div style={{ fontSize: '13px', fontWeight: '700', color: 'var(--accent-green)', marginBottom: '8px' }}>
                  ● Connected to Sentinel Cloud Endpoint
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', lineHeight: '1.8' }}>
                  • Target URL: <strong>{cloudState.targetEndpoint}</strong><br />
                  • Last Sync: <strong>{cloudState.lastSync}</strong><br />
                  • Device ID: <strong>{cloudState.deviceId}</strong>
                </div>

                <div style={{ background: '#070B14', padding: '12px', borderRadius: '6px', border: '1px solid var(--card-border)', marginTop: '14px', fontSize: '11px', color: 'var(--accent-blue-bright)' }}>
                  🔒 {cloudState.privacyNotice}
                </div>
              </div>
            </div>
          )}

          {/* PAGE 11: SETTINGS */}
          {activeTab === 'settings' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="section-header-banner">
                <div>
                  <div className="section-title-large">⚙️ GLOBAL PLATFORM SETTINGS</div>
                  <div className="section-subtitle">Agent parameters, threat thresholds, and local AI model options</div>
                </div>
                <button className="btn-action-primary" onClick={() => setPreventionBanner("⚙️ Platform configuration saved successfully.")}>
                  Save Settings
                </button>
              </div>

              <div className="panel-card">
                <div className="tabs-header-row">
                  {['general', 'monitoring', 'ai_llm', 'appearance'].map(st => (
                    <button key={st} className={`tab-btn ${settingsTab === st ? 'active' : ''}`} onClick={() => setSettingsTab(st)}>
                      {st.toUpperCase()}
                    </button>
                  ))}
                </div>

                <div style={{ marginTop: '16px' }}>
                  {settingsTab === 'general' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      <div className="setting-item-row">
                        <div className="setting-label-stack">
                          <span className="setting-title">System Identifier Name</span>
                          <span className="setting-desc">Node identifier for this installation</span>
                        </div>
                        <input type="text" className="setting-input-text" value={settings.nodeIdentifier} onChange={(e) => setSettings({ ...settings, nodeIdentifier: e.target.value })} />
                      </div>
                    </div>
                  )}

                  {settingsTab === 'ai_llm' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      <div className="setting-item-row">
                        <div className="setting-label-stack">
                          <span className="setting-title">Local Ollama Model</span>
                          <span className="setting-desc">Local LLM model powering analyst explanations</span>
                        </div>
                        <select className="select-dropdown-small" value={settings.aiModel} onChange={(e) => setSettings({ ...settings, aiModel: e.target.value })}>
                          <option>qwen2.5-coder:3b</option>
                          <option>llama3:8b</option>
                          <option>mistral:7b</option>
                        </select>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* PAGE 12: PROFILE */}
          {activeTab === 'profile' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="section-header-banner">
                <div>
                  <div className="section-title-large">👤 USER PROFILE & SECURITY</div>
                  <div className="section-subtitle">Account credentials, session management, and two-factor options</div>
                </div>
              </div>

              <div className="panel-card">
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '16px' }}>
                  <div className="user-avatar-badge" style={{ width: '54px', height: '54px', fontSize: '20px' }}>{userProfile.avatarText}</div>
                  <div>
                    <div style={{ fontSize: '16px', fontWeight: '800', color: '#FFF' }}>{userProfile.name}</div>
                    <div style={{ fontSize: '11px', color: 'var(--accent-blue-bright)' }}>{userProfile.email} ({userProfile.role})</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* PAGE 13: MOCK / TEST MODE */}
          {activeTab === 'test_mode' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="section-header-banner">
                <div>
                  <div className="section-title-large">🧪 MOCK / ATTACK SIMULATION MODE</div>
                  <div className="section-subtitle">Safely demonstrate the detection pipeline without executing real malware</div>
                </div>
              </div>

              <div className="panel-card">
                <div style={{ background: 'rgba(59, 130, 246, 0.12)', padding: '12px 16px', borderRadius: '6px', border: '1px solid var(--card-border)', fontSize: '11px', color: 'var(--accent-blue-bright)', fontWeight: '700' }}>
                  ⚠️ Simulation Mode Active: Events are synthetic for academic demonstration and testing. No real malware is executed.
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px', marginTop: '16px' }}>
                  <button className="btn-action-primary" style={{ padding: '14px', justifyContent: 'center' }} onClick={triggerAttackSimulation}>
                    🔥 Full Keylogger Campaign
                  </button>
                  <button className="btn-action-secondary" style={{ padding: '14px', justifyContent: 'center' }} onClick={() => setPreventionBanner("🧪 Simulated Process Hook Event injected.")}>
                    ⚡ Process Hook Event
                  </button>
                  <button className="btn-action-secondary" style={{ padding: '14px', justifyContent: 'center' }} onClick={() => setPreventionBanner("🧪 Simulated Network Socket Event injected.")}>
                    🌐 Network C2 Event
                  </button>
                  <button className="btn-action-secondary" style={{ padding: '14px', justifyContent: 'center' }} onClick={() => setPreventionBanner("🧪 Simulated File Tampering Event injected.")}>
                    📁 File Tamper Event
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* PAGE 14: DOCUMENTATION */}
          {activeTab === 'documentation' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="section-header-banner">
                <div>
                  <div className="section-title-large">❓ HELP & DOCUMENTATION</div>
                  <div className="section-subtitle">Knowledge base, monitoring mechanics, and mitigation guides</div>
                </div>
              </div>

              <div className="panel-card">
                <div className="tabs-header-row">
                  {docs.map(d => (
                    <button key={d.id} className={`tab-btn ${docsTab === d.id ? 'active' : ''}`} onClick={() => setDocsTab(d.id)}>
                      {d.title}
                    </button>
                  ))}
                </div>

                <div style={{ marginTop: '16px' }}>
                  {docs.find(d => d.id === docsTab) && (
                    <pre style={{ background: '#070B14', padding: '16px', borderRadius: '8px', border: '1px solid var(--card-border)', color: '#FFF', fontSize: '12px', fontFamily: 'var(--font-sans)', lineHeight: '1.7', whiteSpace: 'pre-wrap' }}>
                      {docs.find(d => d.id === docsTab).content}
                    </pre>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* PAGE 15: LOGIN PAGE */}
          {activeTab === 'login' && (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '70vh' }}>
              <div className="panel-card" style={{ width: '100%', maxWidth: '400px', padding: '32px' }}>
                <div style={{ textAlign: 'center', marginBottom: '24px' }}>
                  <div className="brand-shield-icon" style={{ width: '48px', height: '48px', margin: '0 auto 12px auto', fontSize: '24px' }}>🛡️</div>
                  <div style={{ fontSize: '20px', fontWeight: '800', color: '#FFF' }}>Sentinel AI Login</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>Behavior-Based Keylogger Detection</div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  <div>
                    <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Email Address</label>
                    <input type="email" className="setting-input-text" style={{ width: '100%', marginTop: '4px' }} defaultValue="veera.babu@example.com" />
                  </div>
                  <div>
                    <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Password</label>
                    <input type="password" className="setting-input-text" style={{ width: '100%', marginTop: '4px' }} defaultValue="••••••••••••" />
                  </div>
                  <button className="btn-action-primary" style={{ width: '100%', justifyContent: 'center', padding: '10px' }} onClick={() => setActiveTab('dashboard')}>
                    Sign In
                  </button>
                  <div style={{ textAlign: 'center', fontSize: '11px', color: 'var(--text-muted)', marginTop: '8px' }}>
                    Need an account? <span style={{ color: 'var(--accent-blue-bright)', cursor: 'pointer' }} onClick={() => setActiveTab('signup')}>Register here</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* PAGE 16: SIGN UP PAGE */}
          {activeTab === 'signup' && (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '70vh' }}>
              <div className="panel-card" style={{ width: '100%', maxWidth: '400px', padding: '32px' }}>
                <div style={{ textAlign: 'center', marginBottom: '24px' }}>
                  <div className="brand-shield-icon" style={{ width: '48px', height: '48px', margin: '0 auto 12px auto', fontSize: '24px' }}>🛡️</div>
                  <div style={{ fontSize: '20px', fontWeight: '800', color: '#FFF' }}>Create Sentinel AI Account</div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  <div>
                    <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Full Name</label>
                    <input type="text" className="setting-input-text" style={{ width: '100%', marginTop: '4px' }} placeholder="Veera Babu" />
                  </div>
                  <div>
                    <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Email Address</label>
                    <input type="email" className="setting-input-text" style={{ width: '100%', marginTop: '4px' }} placeholder="veera.babu@example.com" />
                  </div>
                  <div>
                    <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Password</label>
                    <input type="password" className="setting-input-text" style={{ width: '100%', marginTop: '4px' }} placeholder="••••••••••••" />
                  </div>
                  <button className="btn-action-primary" style={{ width: '100%', justifyContent: 'center', padding: '10px' }} onClick={() => setActiveTab('dashboard')}>
                    Create Account
                  </button>
                  <div style={{ textAlign: 'center', fontSize: '11px', color: 'var(--text-muted)', marginTop: '8px' }}>
                    Already registered? <span style={{ color: 'var(--accent-blue-bright)', cursor: 'pointer' }} onClick={() => setActiveTab('login')}>Sign In</span>
                  </div>
                </div>
              </div>
            </div>
          )}

        </main>
      </div>

      {/* DEFENSIVE ACTION CONFIRMATION MODAL */}
      {confirmModal && (
        <div className="modal-backdrop-overlay">
          <div className="modal-dialog-box">
            <div className="modal-header-title">
              <span>⚠️</span> {confirmModal.title}
            </div>
            <div className="modal-body-text">
              Potentially destructive security actions require explicit confirmation before execution. Please review the target shell command below:
            </div>
            <div className="modal-command-preview">
              {confirmModal.command}
            </div>
            <div className="modal-actions-row">
              <button className="btn-action-secondary" onClick={() => setConfirmModal(null)}>
                Cancel
              </button>
              <button className="btn-action-danger" onClick={confirmModal.onConfirm}>
                Confirm & Execute
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
