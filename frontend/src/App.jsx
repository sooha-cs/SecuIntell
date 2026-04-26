import { useState, useEffect, useRef, useCallback } from "react";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from "recharts";

// ── Config ────────────────────────────────────────────────────────────────────
const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ── Color helpers ─────────────────────────────────────────────────────────────
const SEV_COLOR = { CRITICAL:"#ff3355", HIGH:"#ff7700", MEDIUM:"#f0c020", LOW:"#3d9bff" };
const TIER_BAR_COLOR = (score) =>
  score >= 80 ? "#ff3355" : score >= 60 ? "#ff7700" : score >= 35 ? "#f0c020" : "#3d9bff";

// ── Mock data ─────────────────────────────────────────────────────────────────
const IPS = () => `${rand(10,210)}.${rand(0,255)}.${rand(0,255)}.${rand(1,254)}`;
const rand = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;

const EVENT_TYPES = [
  "AUTH_FAILURE","BRUTE_FORCE","PORT_SCAN","MALWARE_DETECTED",
  "PRIVILEGE_ESCALATION","DATA_EXFILTRATION","LATERAL_MOVEMENT",
  "DNS_ANOMALY","FIREWALL_BLOCK","AUTH_SUCCESS",
];
const HOSTS = ["prod-server-01","db-master","vpn-gateway","dev-box-07","k8s-node-03","web-lb-01"];
const USERS = ["root","admin","ubuntu","svc_account","deploy","backup_user"];
const MSGS = {
  AUTH_FAILURE:         (ip) => `Failed SSH login for user root from ${ip}`,
  BRUTE_FORCE:          (ip) => `Brute-force attack detected from ${ip} — ${rand(200,999)} attempts`,
  PORT_SCAN:            (ip) => `Port scan detected from ${ip} targeting internal network`,
  MALWARE_DETECTED:     ()   => `Malware signature matched on ${HOSTS[rand(0,5)]} — quarantined`,
  PRIVILEGE_ESCALATION: ()   => `User escalated privileges via sudo on ${HOSTS[rand(0,5)]}`,
  DATA_EXFILTRATION:    (ip) => `Unusual outbound data volume to ${ip}`,
  LATERAL_MOVEMENT:     (ip) => `Lateral movement detected: ${ip} → 10.0.0.${rand(1,50)}`,
  DNS_ANOMALY:          (ip) => `Suspicious DNS query to unknown resolver ${ip}`,
  FIREWALL_BLOCK:       (ip) => `Inbound connection from ${ip} blocked on port ${rand(20,9000)}`,
  AUTH_SUCCESS:         (ip) => `Successful login for admin from ${ip}`,
};

function makeAlert(i) {
  const type = EVENT_TYPES[rand(0, EVENT_TYPES.length - 1)];
  const sevList = ["CRITICAL","CRITICAL","HIGH","HIGH","HIGH","MEDIUM","MEDIUM","LOW"];
  const sev = sevList[rand(0, sevList.length - 1)];
  const score = { CRITICAL: rand(72,100), HIGH: rand(52,76), MEDIUM: rand(28,58), LOW: rand(4,32) }[sev];
  const ip = IPS();
  const ago = rand(0, 120);
  const ts = new Date(Date.now() - ago * 60000);

  return {
    id: `alert_${String(i).padStart(4,"0")}`,
    message: MSGS[type]?.(ip) ?? `Security event from ${ip}`,
    severity: sev,
    event_type: type,
    source_ip: ip,
    hostname: HOSTS[rand(0, HOSTS.length - 1)],
    user: USERS[rand(0, USERS.length - 1)],
    risk_score: score,
    risk_tier: sev,
    is_anomalous: Math.random() > 0.72,
    status: ["open","open","open","investigating","resolved"][rand(0,4)],
    created_at: ts.toISOString(),
    timestamp: ts.toISOString(),
    mitre_matches: [{
      technique_id: ["T1110","T1046","T1021","T1041","T1548"][rand(0,4)],
      technique: ["Brute Force","Network Service Discovery","Remote Services","Exfiltration","Abuse Elevation"][rand(0,4)],
      tactic: ["Credential Access","Discovery","Lateral Movement","Exfiltration","Privilege Escalation"][rand(0,4)],
      tactic_id: "TA0006",
      severity_weight: rand(1,4),
      mitigations: ["MFA","Account lockout","Network segmentation"],
    }],
    rule_matches: [{
      rule_id: `R00${rand(1,9)}`,
      rule_name: type.replace(/_/g," ").toLowerCase().replace(/\b\w/g, c => c.toUpperCase()),
      severity: sev, tactic: "Credential Access", technique: "T1110",
    }],
  };
}

const MOCK_ALERTS    = Array.from({ length: 40 }, (_, i) => makeAlert(i));
const MOCK_INCIDENTS = [
  { id:"inc0", incident_id:"INC-2024001", title:"Brute-Force Leading to Lateral Movement",   severity:"CRITICAL", tactic:"Lateral Movement",    source_ip:"10.4.2.88",   alert_count:7,  chain_name:"Credential Brute-Force → Lateral Movement", status:"open",         first_seen: new Date(Date.now()-7200000).toISOString(), last_seen: new Date(Date.now()-600000).toISOString(),  created_at: new Date(Date.now()-7200000).toISOString() },
  { id:"inc1", incident_id:"INC-2024002", title:"Privilege Escalation + Data Exfiltration",  severity:"CRITICAL", tactic:"Exfiltration",         source_ip:"10.1.5.22",   alert_count:5,  chain_name:"Privilege Escalation → Exfiltration",       status:"investigating",first_seen: new Date(Date.now()-3600000).toISOString(), last_seen: new Date(Date.now()-1200000).toISOString(), created_at: new Date(Date.now()-3600000).toISOString() },
  { id:"inc2", incident_id:"INC-2024003", title:"Malware Detected with Suspected C2 Channel",severity:"HIGH",     tactic:"Command and Control",  source_ip:"10.8.3.11",   alert_count:4,  chain_name:"Malware → C2",                             status:"open",         first_seen: new Date(Date.now()-1800000).toISOString(), last_seen: new Date(Date.now()-300000).toISOString(),  created_at: new Date(Date.now()-1800000).toISOString() },
  { id:"inc3", incident_id:"INC-2024004", title:"Sustained Port Scanning Campaign",          severity:"HIGH",     tactic:"Discovery",           source_ip:"192.168.1.45",alert_count:12, chain_name:"Scanning Storm",                            status:"open",         first_seen: new Date(Date.now()-5400000).toISOString(), last_seen: new Date(Date.now()-900000).toISOString(),  created_at: new Date(Date.now()-5400000).toISOString() },
  { id:"inc4", incident_id:"INC-2024005", title:"Multiple Auth Failures from Single IP",     severity:"MEDIUM",   tactic:"Credential Access",    source_ip:"172.16.0.5",  alert_count:3,  chain_name:null,                                        status:"resolved",     first_seen: new Date(Date.now()-10800000).toISOString(),last_seen: new Date(Date.now()-3600000).toISOString(), created_at: new Date(Date.now()-10800000).toISOString() },
];

function makeTimelineData() {
  return Array.from({ length: 24 }, (_, i) => {
    const h = new Date(); h.setHours(h.getHours() - (23 - i)); h.setMinutes(0,0,0);
    return { time: `${String(h.getHours()).padStart(2,"0")}:00`, critical: rand(0,4), high: rand(0,10), medium: rand(0,16), low: rand(0,8) };
  });
}

const MITRE_TACTICS = [
  { tactic:"Initial Access",       tactic_id:"TA0001", count:12, techniques:["T1078","T1190","T1566"] },
  { tactic:"Execution",            tactic_id:"TA0002", count:4,  techniques:["T1059","T1204"] },
  { tactic:"Persistence",          tactic_id:"TA0003", count:2,  techniques:["T1547"] },
  { tactic:"Privilege Escalation", tactic_id:"TA0004", count:9,  techniques:["T1548","T1068","T1078.003"] },
  { tactic:"Defense Evasion",      tactic_id:"TA0005", count:3,  techniques:["T1562","T1070"] },
  { tactic:"Credential Access",    tactic_id:"TA0006", count:18, techniques:["T1110","T1003","T1552"] },
  { tactic:"Discovery",            tactic_id:"TA0007", count:14, techniques:["T1046","T1082","T1087"] },
  { tactic:"Lateral Movement",     tactic_id:"TA0008", count:7,  techniques:["T1021","T1550.002"] },
  { tactic:"Collection",           tactic_id:"TA0009", count:2,  techniques:["T1005"] },
  { tactic:"Exfiltration",         tactic_id:"TA0010", count:5,  techniques:["T1041","T1567"] },
  { tactic:"Command and Control",  tactic_id:"TA0011", count:6,  techniques:["T1071.004","T1573"] },
  { tactic:"Impact",               tactic_id:"TA0040", count:3,  techniques:["T1486","T1489"] },
];

// ── Fake AI explain generator (offline mode) ─────────────────────────────────
function fakeExplain(alert) {
  const tactics = alert.mitre_matches?.[0]?.tactic || "Unknown";
  const tech    = alert.mitre_matches?.[0]?.technique_id || "TXXXX";
  const conf    = alert.risk_score >= 70 ? "HIGH" : alert.risk_score >= 40 ? "MEDIUM" : "LOW";
  return {
    summary: `${alert.severity} alert: ${alert.event_type?.replace(/_/g," ")} from ${alert.source_ip}`,
    what_happened: `A ${alert.severity.toLowerCase()}-severity ${alert.event_type?.replace(/_/g," ").toLowerCase()} was detected originating from ${alert.source_ip} against ${alert.hostname}. The system matched ${alert.rule_matches?.length || 1} detection rule(s) and${alert.is_anomalous ? " behavioural analysis also flagged this event as a statistical anomaly." : " no anomaly was detected."}`,
    why_it_matters: `This event maps to MITRE ATT&CK technique ${tech} under the ${tactics} tactic. With a risk score of ${alert.risk_score}/100, ${alert.risk_score >= 60 ? "immediate response is strongly recommended" : "this warrants timely investigation"}. If left unaddressed this activity could indicate an active intrusion.`,
    attack_stage: tactics,
    confidence: conf,
    recommended_actions: [
      `Block source IP ${alert.source_ip} at the perimeter firewall`,
      `Lock or audit the account '${alert.user}' for unauthorised activity`,
      `Review logs on ${alert.hostname} for the past 24 hours`,
    ],
    analyst_notes: `Generated in offline mode — set GEMINI_API_KEY or OPENAI_API_KEY in backend .env for LLM-powered analysis. False positive likelihood is ${alert.risk_score >= 60 ? "LOW given multiple indicators" : "MODERATE — investigate before escalating"}.`,
    llm_provider: "offline",
    risk_score: alert.risk_score,
    risk_tier: alert.risk_tier || alert.severity,
    score_breakdown: {
      base_severity: { CRITICAL:40, HIGH:28, MEDIUM:16, LOW:6 }[alert.severity] || 6,
      anomaly_bonus: alert.is_anomalous ? 12 : 0,
      mitre_bonus: (alert.mitre_matches?.[0]?.severity_weight || 1) * 2,
      privilege_factor: ["root","admin"].includes(alert.user) ? 8 : 0,
      asset_factor: alert.hostname?.includes("prod") ? 8 : 0,
      incident_factor: 0, off_hours_factor: 0, recurrence_factor: 0,
    },
    mitre_matches: alert.mitre_matches || [],
    suggested_actions: [
      { priority:1, action:`Block ${alert.source_ip} at perimeter firewall`, rationale:"Stop ongoing attack immediately.", time_est:"~5 min", category:"Containment" },
      { priority:1, action:`Lock account '${alert.user}'`, rationale:"Prevent credential compromise.", time_est:"~5 min", category:"Containment" },
      { priority:2, action:`Check for successful logins from ${alert.source_ip}`, rationale:"Determine if already compromised.", time_est:"~15 min", category:"Investigation" },
      { priority:2, action:"Enable MFA on targeted accounts", rationale:"Raises the bar for future attacks.", time_est:"~30 min", category:"Hardening" },
      { priority:3, action:"Update threat intel with new IOCs", rationale:"Improves future detection.", time_est:"~20 min", category:"Hardening" },
    ],
    explained_at: new Date().toISOString(),
  };
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  const diff = Math.floor((Date.now() - d) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return d.toLocaleDateString();
}
function fmtTimestamp(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-US", { month:"short", day:"numeric", hour:"2-digit", minute:"2-digit" });
}

// ── usePolling hook ───────────────────────────────────────────────────────────
// Polls `url` at `intervalMs`. Calls onData(json) on success, onFallback() on
// network/API failure. Returns { lastPollAt, pollCount, error }.
function usePolling({ url, intervalMs = 15000, onData, onFallback, enabled = true }) {
  const [lastPollAt, setLastPollAt] = useState(null);
  const [pollCount,  setPollCount]  = useState(0);
  const [error,      setError]      = useState(null);
  const cbData     = useRef(onData);
  const cbFallback = useRef(onFallback);
  useEffect(() => { cbData.current     = onData;     }, [onData]);
  useEffect(() => { cbFallback.current = onFallback; }, [onFallback]);

  useEffect(() => {
    if (!enabled) return;
    const poll = async () => {
      try {
        if (!url) throw new Error("no url");
        const res = await fetch(url, { signal: AbortSignal.timeout(6000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        setError(null);
        cbData.current?.(await res.json());
      } catch (err) {
        setError(err.message);
        cbFallback.current?.();
      } finally {
        setLastPollAt(new Date());
        setPollCount(c => c + 1);
      }
    };
    poll();                               // immediate first call
    const t = setInterval(poll, intervalMs);
    return () => clearInterval(t);
  }, [url, intervalMs, enabled]);

  return { lastPollAt, pollCount, error };
}

// ── Icons (inline SVG) ────────────────────────────────────────────────────────
const Icon = ({ name, size=16, color="currentColor" }) => {
  const paths = {
    shield:    "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
    alert:     "M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4M12 17h.01",
    eye:       "M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8zM12 9a3 3 0 100 6 3 3 0 000-6z",
    activity:  "M22 12h-4l-3 9L9 3l-3 9H2",
    layers:    "M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5",
    grid:      "M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z",
    cpu:       "M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18",
    zap:       "M13 2L3 14h9l-1 8 10-12h-9l1-8z",
    x:         "M18 6L6 18M6 6l12 12",
    refresh:   "M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15",
    brain:     "M9.5 2A2.5 2.5 0 0112 4.5v15a2.5 2.5 0 01-4.96-.44 2.5 2.5 0 01-2.96-3.08 3 3 0 01-.34-5.58 2.5 2.5 0 011.32-4.24A2.5 2.5 0 019.5 2zm5 0A2.5 2.5 0 0112 4.5v15a2.5 2.5 0 004.96-.44 2.5 2.5 0 002.96-3.08 3 3 0 00.34-5.58 2.5 2.5 0 00-1.32-4.24A2.5 2.5 0 0014.5 2z",
    check:     "M20 6L9 17l-5-5",
    info:      "M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10zM12 8h.01M11 12h1v4h1",
    clock:     "M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10zM12 6v6l4 2",
    target:    "M22 12A10 10 0 1112 2a10 10 0 0110 10zM12 8v4M12 16h.01",
    incident:  "M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1zM4 22v-7",
  };
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d={paths[name] || paths.shield} />
    </svg>
  );
};

// ── Risk score bar ────────────────────────────────────────────────────────────
const RiskBar = ({ score, width=72 }) => (
  <div style={{ display:"flex", alignItems:"center", gap:6 }}>
    <div className="risk-bar" style={{ width }}>
      <div className="risk-fill" style={{ width:`${score}%`, background: TIER_BAR_COLOR(score) }} />
    </div>
    <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:TIER_BAR_COLOR(score), minWidth:24 }}>
      {score}
    </span>
  </div>
);

// ── Custom chart tooltip ──────────────────────────────────────────────────────
const ChartTip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="custom-tooltip">
      <div style={{ marginBottom:4, color:"var(--text-2)" }}>{label}</div>
      {payload.map(p => (
        <div key={p.name} style={{ color:p.color, display:"flex", gap:8, justifyContent:"space-between" }}>
          <span>{p.name}</span><strong>{p.value}</strong>
        </div>
      ))}
    </div>
  );
};

// ── Header ────────────────────────────────────────────────────────────────────
function Header({ stats, connected }) {
  return (
    <header className="header">
      <div className="header-brand">
        <Icon name="shield" size={22} color="var(--accent)" />
        SECUINTELL
        <span style={{ fontSize:11, color:"var(--text-3)", fontWeight:400, marginLeft:4 }}>v2.0 · SIEM</span>
      </div>
      <div className="header-right">
        <div className="status-pill">
          <div className={`status-dot ${stats.openCritical > 0 ? "red" : ""}`} />
          {stats.openCritical > 0 ? `${stats.openCritical} CRITICAL` : "ALL CLEAR"}
        </div>
        <div className="status-pill">
          <div className={`status-dot ${connected ? "" : "warn"}`} />
          {connected ? "LIVE" : "DEMO MODE"}
        </div>
        <div className="status-pill">
          <Icon name="clock" size={12} />
          <span id="live-clock" />
        </div>
      </div>
    </header>
  );
}

// ── Sidebar ───────────────────────────────────────────────────────────────────
function Sidebar({ view, setView, counts }) {
  const nav = [
    { id:"dashboard", icon:"grid",     label:"Dashboard" },
    { id:"alerts",    icon:"alert",    label:"Alerts",    badge: counts.open, badgeCls: counts.open > 5 ? "" : "warn" },
    { id:"incidents", icon:"incident", label:"Incidents", badge: counts.incidents, badgeCls: "" },
    { id:"live",      icon:"activity", label:"Live Feed", badge:"LIVE", badgeCls:"ok" },
    { id:"mitre",     icon:"layers",   label:"MITRE ATT&CK" },
    { id:"fim",       icon:"eye",      label:"File Integrity", badge: null, badgeCls:"warn" },
  ];
  return (
    <nav className="sidebar">
      <div className="nav-section-label">Navigation</div>
      {nav.map(n => (
        <div key={n.id} className={`nav-item ${view===n.id?"active":""}`} onClick={() => setView(n.id)}>
          <Icon name={n.icon} size={15} />
          {n.label}
          {n.badge != null && (
            <span className={`nav-badge ${n.badgeCls}`}>{n.badge}</span>
          )}
        </div>
      ))}
      <div style={{ flex:1 }} />
      <div className="sidebar-footer">
        SECUINTELL SIEM<br />
        <span style={{ color:"var(--text-3)" }}>Build 2025.04</span>
      </div>
    </nav>
  );
}

// ── Dashboard view ────────────────────────────────────────────────────────────
function DashboardView({ alerts, incidents, onExplain }) {
  const timeline = makeTimelineData();
  const sevCounts = alerts.reduce((a, x) => { a[x.severity] = (a[x.severity]||0)+1; return a; }, {});
  const pieData = Object.entries(sevCounts).map(([name, value]) => ({ name, value }));
  const topAlerts = [...alerts].filter(a => a.status !== "resolved").sort((a,b) => b.risk_score - a.risk_score).slice(0, 8);
  const openInc = incidents.filter(i => i.status !== "resolved");
  const anomalyCount = alerts.filter(a => a.is_anomalous).length;

  return (
    <>
      {/* Stat cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Alerts</div>
          <div className="stat-value">{alerts.length}</div>
          <div className="stat-delta">last 24 hours</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Open Critical</div>
          <div className={`stat-value ${alerts.filter(a=>a.severity==="CRITICAL"&&a.status==="open").length>0?"crit":""}`}>
            {alerts.filter(a=>a.severity==="CRITICAL"&&a.status==="open").length}
          </div>
          <div className="stat-delta">requires response</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Active Incidents</div>
          <div className={`stat-value ${openInc.length>0?"high":""}`}>{openInc.length}</div>
          <div className="stat-delta">correlated chains</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Anomalies Detected</div>
          <div className="stat-value" style={{ color:"#a78bff" }}>{anomalyCount}</div>
          <div className="stat-delta">isolation forest</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Avg Risk Score</div>
          <div className={`stat-value ${alerts.length ? "" : "accent"}`}>
            {alerts.length ? Math.round(alerts.reduce((s,a)=>s+a.risk_score,0)/alerts.length) : 0}
          </div>
          <div className="stat-delta">/ 100 weighted</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">MITRE Tactics</div>
          <div className="stat-value accent">{MITRE_TACTICS.filter(t=>t.count>0).length}</div>
          <div className="stat-delta">of 12 observed</div>
        </div>
      </div>

      {/* Charts */}
      <div className="chart-grid">
        <div className="card">
          <div className="card-header">
            <span className="card-title"><Icon name="activity" size={14}/>Alert Timeline — 24h</span>
          </div>
          <div className="card-body" style={{ padding:"12px 8px 8px" }}>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={timeline} margin={{ top:4, right:8, left:-20, bottom:0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="time" tick={{ fill:"#3d5570", fontSize:10, fontFamily:"JetBrains Mono" }} tickLine={false} interval={3} />
                <YAxis tick={{ fill:"#3d5570", fontSize:10, fontFamily:"JetBrains Mono" }} tickLine={false} />
                <Tooltip content={<ChartTip />} />
                <Area type="monotone" dataKey="critical" stackId="1" stroke="#ff3355" fill="rgba(255,51,85,0.25)" strokeWidth={1.5} name="Critical" />
                <Area type="monotone" dataKey="high"     stackId="1" stroke="#ff7700" fill="rgba(255,119,0,0.2)"  strokeWidth={1.5} name="High" />
                <Area type="monotone" dataKey="medium"   stackId="1" stroke="#f0c020" fill="rgba(240,192,32,0.15)" strokeWidth={1.5} name="Medium" />
                <Area type="monotone" dataKey="low"      stackId="1" stroke="#3d9bff" fill="rgba(61,155,255,0.1)"  strokeWidth={1.5} name="Low" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title"><Icon name="zap" size={14}/>Severity Split</span>
          </div>
          <div className="card-body" style={{ display:"flex", flexDirection:"column", alignItems:"center", padding:"8px 0 16px" }}>
            <ResponsiveContainer width="100%" height={140}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={40} outerRadius={62}
                  dataKey="value" paddingAngle={2} strokeWidth={0}>
                  {pieData.map(e => <Cell key={e.name} fill={SEV_COLOR[e.name] || "#555"} />)}
                </Pie>
                <Tooltip content={<ChartTip />} />
              </PieChart>
            </ResponsiveContainer>
            <div style={{ display:"flex", gap:12, flexWrap:"wrap", justifyContent:"center", marginTop:4 }}>
              {pieData.map(e => (
                <div key={e.name} style={{ display:"flex", alignItems:"center", gap:5, fontSize:11, fontFamily:"var(--font-mono)", color:"var(--text-2)" }}>
                  <div style={{ width:8, height:8, borderRadius:2, background:SEV_COLOR[e.name] }} />
                  {e.name} <strong style={{ color:SEV_COLOR[e.name] }}>{e.value}</strong>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Top risk alerts + active incidents side by side */}
      <div className="two-col">
        <div className="card">
          <div className="card-header">
            <span className="card-title"><Icon name="target" size={14}/>Highest Risk Alerts</span>
            <span style={{ fontSize:11, fontFamily:"var(--font-mono)", color:"var(--text-3)" }}>by risk score</span>
          </div>
          <table className="data-table">
            <thead><tr>
              <th>Event</th><th>IP</th><th>Risk</th><th></th>
            </tr></thead>
            <tbody>
              {topAlerts.map(a => (
                <tr key={a.id} onClick={() => onExplain(a)}>
                  <td>
                    <span className={`badge ${a.severity}`} style={{ marginRight:6 }}>{a.severity}</span>
                    <span style={{ fontSize:12, color:"var(--text-2)" }}>{a.event_type?.replace(/_/g," ")}</span>
                  </td>
                  <td className="ip-mono">{a.source_ip}</td>
                  <td><RiskBar score={a.risk_score} width={60} /></td>
                  <td>
                    <button className="btn primary" style={{ padding:"3px 8px", fontSize:10 }} onClick={e=>{e.stopPropagation();onExplain(a);}}>
                      AI ▸
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title"><Icon name="incident" size={14}/>Active Incidents</span>
            <span className={`badge ${openInc.length>0?"CRITICAL":"LOW"}`}>{openInc.length} open</span>
          </div>
          <div style={{ padding:"8px 0" }}>
            {openInc.slice(0,5).map(inc => (
              <div key={inc.id} style={{ padding:"10px 16px", borderBottom:"1px solid rgba(255,255,255,0.03)" }}>
                <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
                  <span className={`badge ${inc.severity}`}>{inc.severity}</span>
                  <span style={{ fontSize:12, fontWeight:600, flex:1 }}>{inc.title}</span>
                </div>
                <div style={{ display:"flex", gap:12, fontSize:11, fontFamily:"var(--font-mono)", color:"var(--text-3)" }}>
                  <span>{inc.source_ip}</span>
                  <span>{inc.alert_count} alerts</span>
                  <span>{fmtTime(inc.last_seen)}</span>
                </div>
              </div>
            ))}
            {openInc.length === 0 && <div className="empty-state">No active incidents</div>}
          </div>
        </div>
      </div>
    </>
  );
}

// ── Alerts view ───────────────────────────────────────────────────────────────
function AlertsView({ alerts, onExplain }) {
  const [filterSev, setFilterSev]  = useState("ALL");
  const [filterAnomaly, setFilterAnomaly] = useState(false);
  const [filterStatus, setFilterStatus] = useState("ALL");
  const [search, setSearch] = useState("");

  const filtered = alerts.filter(a => {
    if (filterSev !== "ALL" && a.severity !== filterSev) return false;
    if (filterAnomaly && !a.is_anomalous) return false;
    if (filterStatus !== "ALL" && a.status !== filterStatus) return false;
    if (search && !a.message?.toLowerCase().includes(search.toLowerCase()) && !a.source_ip?.includes(search) && !a.event_type?.includes(search.toUpperCase())) return false;
    return true;
  });

  return (
    <div className="card" style={{ flex:1 }}>
      <div className="card-header">
        <span className="card-title"><Icon name="alert" size={14}/>All Alerts</span>
        <span style={{ fontSize:11, fontFamily:"var(--font-mono)", color:"var(--text-3)" }}>{filtered.length} / {alerts.length}</span>
      </div>
      <div className="filters">
        <input className="filter-input" placeholder="Search message, IP, event type…" value={search} onChange={e=>setSearch(e.target.value)} />
        {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(s => (
          <button key={s} className={`filter-btn ${filterSev===s?"active":""}`} onClick={() => setFilterSev(s)}>{s}</button>
        ))}
        <button className={`filter-btn ${filterAnomaly?"active":""}`} onClick={() => setFilterAnomaly(!filterAnomaly)}>⚡ Anomaly</button>
        {["ALL","open","investigating","resolved"].map(s => (
          <button key={s} className={`filter-btn ${filterStatus===s?"active":""}`} onClick={() => setFilterStatus(s)}>{s}</button>
        ))}
      </div>
      <div style={{ overflowX:"auto" }}>
        <table className="data-table">
          <thead><tr>
            <th>Severity</th><th>Event</th><th>Message</th>
            <th>Source IP</th><th>Host</th><th>Risk</th>
            <th>MITRE</th><th>Status</th><th>Time</th><th></th>
          </tr></thead>
          <tbody>
            {filtered.map(a => (
              <tr key={a.id} onClick={() => onExplain(a)}>
                <td>
                  <span className={`badge ${a.severity}`}>{a.severity}</span>
                  {a.is_anomalous && <span className="badge ANOMALY" style={{ marginLeft:4 }}>⚡</span>}
                </td>
                <td style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--text-2)", whiteSpace:"nowrap" }}>
                  {a.event_type?.replace(/_/g," ")}
                </td>
                <td className="truncate" style={{ maxWidth:240, fontSize:12, color:"var(--text-2)" }}>{a.message}</td>
                <td className="ip-mono">{a.source_ip}</td>
                <td style={{ fontSize:12, color:"var(--text-2)" }}>{a.hostname}</td>
                <td><RiskBar score={a.risk_score} /></td>
                <td>
                  {a.mitre_matches?.slice(0,1).map(m => (
                    <span key={m.technique_id} className="mitre-tech-tag">{m.technique_id}</span>
                  ))}
                </td>
                <td><span className={`badge ${a.status}`}>{a.status}</span></td>
                <td style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--text-3)", whiteSpace:"nowrap" }}>{fmtTime(a.created_at)}</td>
                <td>
                  <button className="btn primary" style={{ padding:"3px 9px", fontSize:10 }} onClick={e=>{e.stopPropagation();onExplain(a);}}>
                    <Icon name="brain" size={11} /> Explain
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && <div className="empty-state">No alerts match current filters</div>}
      </div>
    </div>
  );
}

// ── Incidents view ────────────────────────────────────────────────────────────
function IncidentsView({ incidents }) {
  const [filter, setFilter] = useState("ALL");
  const shown = incidents.filter(i => filter === "ALL" || i.status === filter || i.severity === filter);

  return (
    <>
      <div style={{ display:"flex", alignItems:"center", gap:10, flexWrap:"wrap" }}>
        {["ALL","open","investigating","resolved","CRITICAL","HIGH","MEDIUM"].map(f => (
          <button key={f} className={`filter-btn ${filter===f?"active":""}`} onClick={() => setFilter(f)}>{f}</button>
        ))}
      </div>
      <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
        {shown.map(inc => (
          <div key={inc.id} className={`incident-card ${inc.severity}`}>
            <div>
              <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6, flexWrap:"wrap" }}>
                <span className={`badge ${inc.severity}`}>{inc.severity}</span>
                <span style={{ fontWeight:700, fontSize:15 }}>{inc.title}</span>
                <span className={`badge ${inc.status}`}>{inc.status}</span>
              </div>
              {inc.chain_name && (
                <div className="incident-chain">
                  <Icon name="zap" size={10} color="var(--info)" /> {inc.chain_name}
                </div>
              )}
              <div style={{ marginTop:8, display:"flex", gap:16, fontSize:12, fontFamily:"var(--font-mono)", color:"var(--text-3)", flexWrap:"wrap" }}>
                <span>Src: <span style={{ color:"var(--text-2)" }}>{inc.source_ip}</span></span>
                <span>Alerts: <span style={{ color:"var(--text-2)" }}>{inc.alert_count}</span></span>
                <span>Tactic: <span style={{ color:"var(--text-2)" }}>{inc.tactic}</span></span>
                <span>First: <span style={{ color:"var(--text-2)" }}>{fmtTimestamp(inc.first_seen)}</span></span>
                <span>Last: <span style={{ color:"var(--text-2)" }}>{fmtTimestamp(inc.last_seen)}</span></span>
              </div>
            </div>
            <div style={{ display:"flex", flexDirection:"column", alignItems:"flex-end", gap:8 }}>
              <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--text-3)" }}>{inc.incident_id}</span>
              <button className="btn" style={{ fontSize:11 }}>Investigate →</button>
            </div>
          </div>
        ))}
        {shown.length === 0 && <div className="empty-state">No incidents match filter</div>}
      </div>
    </>
  );
}

// ── Live Feed ─────────────────────────────────────────────────────────────────
function LiveFeedView({ alerts }) {
  const [feed, setFeed] = useState(() => [...alerts].sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp)).slice(0,30));
  const [paused, setPaused] = useState(false);
  const [newIds, setNewIds] = useState(new Set());
  const ref = useRef();

  useEffect(() => {
    if (paused) return;
    const t = setInterval(() => {
      const entry = makeAlert(Date.now());
      entry.timestamp = new Date().toISOString();
      setFeed(f => [entry, ...f.slice(0, 99)]);
      // FIX: was using .values().next() short-circuit which always resolved
      // to a single-item set, losing accumulation. Now correctly adds id then
      // clears after 2 s via a dedicated timeout per entry.
      setNewIds(prev => new Set([...prev, entry.id]));
      setTimeout(() => setNewIds(prev => { const n = new Set(prev); n.delete(entry.id); return n; }), 2000);
    }, rand(2000, 5000));
    return () => clearInterval(t);
  }, [paused]);

  return (
    <div className="card" style={{ flex:1 }}>
      <div className="card-header">
        <span className="card-title"><Icon name="activity" size={14}/>Live Log Feed</span>
        <div style={{ display:"flex", gap:8 }}>
          <div className="status-pill"><div className={`status-dot ${paused ? "warn" : ""}`}/>{paused?"PAUSED":"STREAMING"}</div>
          <button className="btn" onClick={() => setPaused(p=>!p)}>{paused ? "Resume" : "Pause"}</button>
        </div>
      </div>
      <div ref={ref} style={{ overflowY:"auto", maxHeight:"calc(100vh - 280px)" }}>
        {feed.map((e, i) => (
          <div key={e.id+i} className={`feed-row ${newIds.has(e.id)?"new":""}`}>
            <span className="feed-time">{new Date(e.timestamp).toLocaleTimeString()}</span>
            <span className={`badge ${e.severity}`} style={{ alignSelf:"flex-start", marginTop:1 }}>{e.severity[0]}</span>
            <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--text-3)", whiteSpace:"nowrap", alignSelf:"flex-start", marginTop:2 }}>{e.event_type?.replace(/_/g," ").slice(0,14)}</span>
            <span className="feed-msg">{e.message}</span>
            <span className="ip-mono" style={{ whiteSpace:"nowrap", color:"var(--text-3)" }}>{e.source_ip}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── MITRE ATT&CK view ─────────────────────────────────────────────────────────
function MitreView() {
  const [selected, setSelected] = useState(null);
  const max = Math.max(...MITRE_TACTICS.map(t=>t.count));

  return (
    <>
      <div className="card">
        <div className="card-header">
          <span className="card-title"><Icon name="layers" size={14}/>MITRE ATT&CK Coverage</span>
          <span style={{ fontSize:11, fontFamily:"var(--font-mono)", color:"var(--text-3)" }}>
            {MITRE_TACTICS.filter(t=>t.count>0).length}/12 tactics observed
          </span>
        </div>
        <div className="mitre-grid">
          {MITRE_TACTICS.map(t => {
            const intensity = t.count / max;
            const col = intensity > 0.7 ? "var(--crit)" : intensity > 0.4 ? "var(--high)" : intensity > 0.2 ? "var(--med)" : "var(--low)";
            return (
              <div key={t.tactic_id} className={`mitre-cell ${selected?.tactic_id===t.tactic_id?"selected":""}`}
                onClick={() => setSelected(selected?.tactic_id===t.tactic_id ? null : t)}
                style={{ borderColor: selected?.tactic_id===t.tactic_id ? "var(--accent)" : undefined }}>
                <div className="mitre-cell-count" style={{ color: col }}>{t.count}</div>
                <div className="mitre-cell-name">{t.tactic}</div>
                <div style={{ marginTop:4, color:"var(--text-3)", fontSize:10, fontFamily:"var(--font-mono)" }}>{t.tactic_id}</div>
              </div>
            );
          })}
        </div>
      </div>

      {selected && (
        <div className="card">
          <div className="card-header">
            <span className="card-title"><Icon name="info" size={14}/>{selected.tactic}</span>
            <span style={{ fontSize:11, fontFamily:"var(--font-mono)", color:"var(--accent)" }}>{selected.count} alerts</span>
          </div>
          <div style={{ padding:"16px 18px" }}>
            <div style={{ marginBottom:8, fontSize:12, color:"var(--text-2)" }}>Techniques observed:</div>
            <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
              {selected.techniques.map(t => (
                <div key={t} style={{ background:"var(--bg-hover)", border:"1px solid var(--border)", borderRadius:4, padding:"6px 12px", fontFamily:"var(--font-mono)", fontSize:12 }}>
                  <span style={{ color:"var(--accent)" }}>{t}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ padding:"0 16px 8px" }}>
            <ResponsiveContainer width="100%" height={80}>
              <BarChart data={[{ name:selected.tactic, count:selected.count }]} layout="vertical" margin={{ left:0, right:16 }}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="name" hide />
                <Bar dataKey="count" fill="var(--accent)" radius={2} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <span className="card-title"><Icon name="zap" size={14}/>Tactic Alert Distribution</span>
        </div>
        <div className="card-body" style={{ padding:"12px 8px 8px" }}>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={MITRE_TACTICS} margin={{ top:4, right:8, left:-20, bottom:60 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
              <XAxis dataKey="tactic" tick={{ fill:"#3d5570", fontSize:9, fontFamily:"JetBrains Mono" }} tickLine={false} angle={-35} textAnchor="end" interval={0} />
              <YAxis tick={{ fill:"#3d5570", fontSize:10, fontFamily:"JetBrains Mono" }} tickLine={false} />
              <Tooltip content={<ChartTip />} />
              <Bar dataKey="count" fill="var(--accent)" radius={[2,2,0,0]} opacity={0.85} name="Alerts" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </>
  );
}

// ── File Integrity Monitoring ─────────────────────────────────────────────────
const FIM_BASELINE = [
  { path:"/etc/passwd",           hash:"a3f1b2c9d4e5f6a7", owner:"root", perms:"644", size:"2.1 KB",  critical:true  },
  { path:"/etc/sudoers",          hash:"b7e2d3a1c8f4e9b0", owner:"root", perms:"440", size:"756 B",   critical:true  },
  { path:"/etc/ssh/sshd_config",  hash:"c4d9e1f2a3b7c8d5", owner:"root", perms:"600", size:"3.4 KB",  critical:true  },
  { path:"/etc/hosts",            hash:"d1a2b3c4e5f6d7e8", owner:"root", perms:"644", size:"221 B",   critical:false },
  { path:"/var/log/auth.log",     hash:"e8f7a6b5c4d3e2f1", owner:"syslog",perms:"640", size:"14.2 KB", critical:false },
  { path:"/usr/bin/sudo",         hash:"f2e3d4c5b6a7f8e9", owner:"root", perms:"4755", size:"182 KB",  critical:true  },
  { path:"/etc/crontab",          hash:"a9b8c7d6e5f4a3b2", owner:"root", perms:"644", size:"1.1 KB",  critical:true  },
  { path:"/home/ubuntu/.bashrc",  hash:"b3c4d5e6f7a8b9c0", owner:"ubuntu",perms:"644", size:"3.7 KB",  critical:false },
  { path:"/etc/nginx/nginx.conf", hash:"c0d1e2f3a4b5c6d7", owner:"root", perms:"644", size:"2.8 KB",  critical:false },
  { path:"/usr/local/bin/deploy", hash:"d7e8f9a0b1c2d3e4", owner:"deploy",perms:"755", size:"48 KB",   critical:false },
];
const FIM_CHANGE_TYPES = ["MODIFIED","MODIFIED","MODIFIED","DELETED","PERMISSION_CHANGED","OWNER_CHANGED"];
function newHash() { return [...Array(16)].map(()=>Math.floor(Math.random()*16).toString(16)).join(""); }
function makeFIMEvent(file, seq) {
  const type = FIM_CHANGE_TYPES[rand(0, FIM_CHANGE_TYPES.length - 1)];
  return {
    id: `fim_${seq}_${Date.now()}`,
    path: file.path,
    change_type: type,
    severity: file.critical ? (type === "DELETED" ? "CRITICAL" : "HIGH") : "MEDIUM",
    old_hash: file.hash,
    new_hash: type === "DELETED" ? null : newHash(),
    old_perms: file.perms,
    new_perms: type === "PERMISSION_CHANGED" ? `${rand(600,777)}` : file.perms,
    old_owner: file.owner,
    new_owner: type === "OWNER_CHANGED" ? USERS[rand(0, USERS.length - 1)] : file.owner,
    detected_at: new Date().toISOString(),
    acknowledged: false,
  };
}

function FIMView() {
  const [baseline]   = useState(() => FIM_BASELINE.map(f => ({ ...f, status:"clean", last_scan: new Date().toISOString() })));
  const [files,      setFiles]      = useState(() => baseline.map(f => ({ ...f })));
  const [events,     setEvents]     = useState([]);
  const [scanning,   setScanning]   = useState(false);
  const [scanCount,  setScanCount]  = useState(0);
  const [lastScan,   setLastScan]   = useState(null);
  const [interval_,  setInterval_]  = useState(20);   // seconds
  const [filter,     setFilter]     = useState("ALL");
  const [ackIds,     setAckIds]     = useState(new Set());
  const seqRef = useRef(0);

  // Run one FIM scan: randomly tamper 0–2 files
  const runScan = useCallback(() => {
    setScanning(true);
    setTimeout(() => {
      const newEvents = [];
      const updatedFiles = files.map(f => ({ ...f, last_scan: new Date().toISOString() }));

      // 40% chance to detect 1 change, 15% chance to detect 2
      const numChanges = Math.random() < 0.15 ? 2 : Math.random() < 0.40 ? 1 : 0;
      const targets = [...updatedFiles].sort(() => Math.random() - 0.5).slice(0, numChanges);
      targets.forEach(target => {
        seqRef.current += 1;
        const ev = makeFIMEvent(target, seqRef.current);
        newEvents.push(ev);
        const idx = updatedFiles.findIndex(f => f.path === target.path);
        if (idx !== -1) {
          updatedFiles[idx] = {
            ...updatedFiles[idx],
            status: ev.change_type === "DELETED" ? "deleted" : "tampered",
            hash:   ev.new_hash ?? updatedFiles[idx].hash,
            perms:  ev.new_perms,
            owner:  ev.new_owner,
          };
        }
      });

      setFiles(updatedFiles);
      if (newEvents.length) setEvents(prev => [...newEvents, ...prev].slice(0, 200));
      setScanCount(c => c + 1);
      setLastScan(new Date());
      setScanning(false);
    }, rand(800, 1800));   // simulate scan duration
  }, [files]);

  // Auto-scan
  useEffect(() => {
    const t = setInterval(runScan, interval_ * 1000);
    return () => clearInterval(t);
  }, [runScan, interval_]);

  const tamperedCount  = files.filter(f => f.status === "tampered").length;
  const deletedCount   = files.filter(f => f.status === "deleted").length;
  const unackEvents    = events.filter(e => !ackIds.has(e.id));
  const shownEvents    = filter === "ALL" ? events : events.filter(e => e.severity === filter || e.change_type === filter);

  const statusColor = { clean:"var(--accent)", tampered:"var(--high)", deleted:"var(--crit)" };
  const sevColor    = { CRITICAL:"var(--crit)", HIGH:"var(--high)", MEDIUM:"var(--med)", LOW:"var(--low)" };
  const changeIcon  = { MODIFIED:"✎", DELETED:"✗", PERMISSION_CHANGED:"⚿", OWNER_CHANGED:"👤" };

  return (
    <>
      {/* Summary bar */}
      <div className="stats-grid" style={{ gridTemplateColumns:"repeat(4,1fr)" }}>
        {[
          { label:"Watched Files",   value: files.length,                           sub:"in baseline" },
          { label:"Clean",           value: files.filter(f=>f.status==="clean").length, sub:"no changes" },
          { label:"Tampered",        value: tamperedCount,  sub:"hash/perm/owner mismatch", color:"var(--high)" },
          { label:"Unacked Alerts",  value: unackEvents.length, sub:"need acknowledgement", color: unackEvents.length>0?"var(--crit)":undefined },
        ].map(s => (
          <div key={s.label} className="stat-card">
            <div className="stat-label">{s.label}</div>
            <div className="stat-value" style={{ color: s.color }}>{s.value}</div>
            <div className="stat-delta">{s.sub}</div>
          </div>
        ))}
      </div>

      {/* Controls */}
      <div className="card">
        <div className="card-header">
          <span className="card-title"><Icon name="shield" size={14}/>File Integrity Monitor</span>
          <div style={{ display:"flex", gap:10, alignItems:"center" }}>
            <span style={{ fontSize:11, fontFamily:"var(--font-mono)", color:"var(--text-dim,#5a7a85)" }}>
              Scan #{scanCount} · interval {interval_}s
              {lastScan && ` · last ${lastScan.toLocaleTimeString()}`}
            </span>
            <select
              value={interval_}
              onChange={e => setInterval_(Number(e.target.value))}
              style={{ background:"var(--surface,#0b1618)", border:"1px solid var(--border,#1a3038)", color:"var(--text,#c8dde2)", borderRadius:4, padding:"3px 8px", fontSize:12, fontFamily:"var(--font-mono,monospace)" }}>
              {[10,20,30,60].map(v=><option key={v} value={v}>{v}s</option>)}
            </select>
            <button className="btn primary" onClick={runScan} disabled={scanning}
              style={{ display:"flex", alignItems:"center", gap:6 }}>
              {scanning
                ? <><div className="spinner" style={{ width:10, height:10 }} /> Scanning…</>
                : <><Icon name="refresh" size={12}/> Scan Now</>}
            </button>
          </div>
        </div>

        {/* File table */}
        <div style={{ overflowX:"auto" }}>
          <table className="data-table">
            <thead><tr>
              <th>Status</th><th>Path</th><th>Critical</th>
              <th>Hash</th><th>Perms</th><th>Owner</th><th>Last Scan</th>
            </tr></thead>
            <tbody>
              {files.map(f => (
                <tr key={f.path} style={{ opacity: f.status==="deleted" ? 0.55 : 1 }}>
                  <td>
                    <span style={{ display:"inline-flex", alignItems:"center", gap:5,
                      color: statusColor[f.status], fontFamily:"var(--font-mono,monospace)", fontSize:11, fontWeight:600 }}>
                      <span style={{ width:7, height:7, borderRadius:"50%", background:statusColor[f.status], display:"inline-block" }}/>
                      {f.status.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ fontFamily:"var(--font-mono,monospace)", fontSize:11, color:"var(--text,#c8dde2)" }}>{f.path}</td>
                  <td style={{ textAlign:"center" }}>
                    {f.critical && <span style={{ color:"var(--crit,#ff4560)", fontSize:12 }}>⚑</span>}
                  </td>
                  <td style={{ fontFamily:"var(--font-mono,monospace)", fontSize:10, color:"var(--text-dim,#5a7a85)" }}>
                    {f.hash?.slice(0,8)}…
                  </td>
                  <td style={{ fontFamily:"var(--font-mono,monospace)", fontSize:11 }}>{f.perms}</td>
                  <td style={{ fontSize:11, color:"var(--text,#c8dde2)" }}>{f.owner}</td>
                  <td style={{ fontFamily:"var(--font-mono,monospace)", fontSize:10, color:"var(--text-dim,#5a7a85)" }}>
                    {f.last_scan ? new Date(f.last_scan).toLocaleTimeString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* FIM event log */}
      <div className="card">
        <div className="card-header">
          <span className="card-title"><Icon name="activity" size={14}/>Integrity Event Log</span>
          <div style={{ display:"flex", gap:8, alignItems:"center" }}>
            {unackEvents.length > 0 && (
              <button className="btn" style={{ fontSize:11 }}
                onClick={() => setAckIds(prev => new Set([...prev, ...unackEvents.map(e=>e.id)]))}>
                Ack All ({unackEvents.length})
              </button>
            )}
            {["ALL","CRITICAL","HIGH","MEDIUM","MODIFIED","DELETED","PERMISSION_CHANGED"].map(f => (
              <button key={f} className={`filter-btn ${filter===f?"active":""}`}
                onClick={() => setFilter(f)} style={{ fontSize:10 }}>{f}</button>
            ))}
          </div>
        </div>

        {shownEvents.length === 0 ? (
          <div className="empty-state" style={{ padding:32 }}>
            {events.length === 0
              ? "No integrity events yet — waiting for next scan…"
              : "No events match current filter"}
          </div>
        ) : (
          <div style={{ overflowY:"auto", maxHeight:"420px" }}>
            {shownEvents.map(ev => {
              const acked = ackIds.has(ev.id);
              return (
                <div key={ev.id} style={{
                  padding:"12px 16px",
                  borderBottom:"1px solid rgba(255,255,255,0.04)",
                  opacity: acked ? 0.45 : 1,
                  display:"flex", gap:14, alignItems:"flex-start",
                  background: acked ? "transparent" : `${sevColor[ev.severity]}08`,
                }}>
                  {/* Change type icon */}
                  <div style={{ fontSize:18, lineHeight:1, color:sevColor[ev.severity], width:20, flexShrink:0, marginTop:2 }}>
                    {changeIcon[ev.change_type] || "?"}
                  </div>

                  <div style={{ flex:1, minWidth:0 }}>
                    {/* Top row */}
                    <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4, flexWrap:"wrap" }}>
                      <span className={`badge ${ev.severity}`}>{ev.severity}</span>
                      <span style={{ fontFamily:"var(--font-mono,monospace)", fontSize:11,
                        color:sevColor[ev.severity], background:`${sevColor[ev.severity]}18`,
                        border:`1px solid ${sevColor[ev.severity]}40`, borderRadius:3, padding:"1px 6px" }}>
                        {ev.change_type.replace(/_/g," ")}
                      </span>
                      <span style={{ fontFamily:"var(--font-mono,monospace)", fontSize:12, color:"var(--text,#c8dde2)", fontWeight:600 }}>
                        {ev.path}
                      </span>
                    </div>

                    {/* Hash diff */}
                    {ev.change_type === "MODIFIED" && (
                      <div style={{ display:"flex", gap:8, fontSize:10, fontFamily:"var(--font-mono,monospace)",
                        color:"var(--text-dim,#5a7a85)", marginBottom:4, flexWrap:"wrap" }}>
                        <span>OLD: <span style={{ color:"var(--crit,#ff4560)" }}>{ev.old_hash}</span></span>
                        <span>→</span>
                        <span>NEW: <span style={{ color:"var(--warn,#f5a623)" }}>{ev.new_hash}</span></span>
                      </div>
                    )}

                    {/* Perm/owner diff */}
                    {(ev.change_type === "PERMISSION_CHANGED" || ev.change_type === "OWNER_CHANGED") && (
                      <div style={{ fontSize:10, fontFamily:"var(--font-mono,monospace)", color:"var(--text-dim,#5a7a85)", marginBottom:4 }}>
                        {ev.change_type === "PERMISSION_CHANGED"
                          ? <>{`perms: `}<span style={{color:"var(--crit)"}}>{ev.old_perms}</span>{` → `}<span style={{color:"var(--warn)"}}>{ev.new_perms}</span></>
                          : <>{`owner: `}<span style={{color:"var(--crit)"}}>{ev.old_owner}</span>{` → `}<span style={{color:"var(--warn)"}}>{ev.new_owner}</span></>}
                      </div>
                    )}

                    <div style={{ fontSize:10, fontFamily:"var(--font-mono,monospace)", color:"var(--text-dim,#5a7a85)" }}>
                      {new Date(ev.detected_at).toLocaleString()}
                    </div>
                  </div>

                  {/* Ack button */}
                  {!acked && (
                    <button className="btn" style={{ fontSize:10, flexShrink:0 }}
                      onClick={() => setAckIds(prev => new Set([...prev, ev.id]))}>
                      Ack
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </>
  );
}

// ── Explain panel ─────────────────────────────────────────────────────────────
function ExplainPanel({ alert, onClose }) {
  const [data, setData]     = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    setData(null);
    // Try real API first, fall back to offline explanation
    const doExplain = async () => {
      try {
        const r = await fetch(`${API}/explain/${alert.id}`, { method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(alert), signal: AbortSignal.timeout(8000) });
        if (!r.ok) throw new Error("API error");
        setData(await r.json());
      } catch {
        // Backend not reachable — generate offline explanation
        await new Promise(r => setTimeout(r, 600)); // brief delay for UX
        setData(fakeExplain(alert));
      } finally {
        setLoading(false);
      }
    };
    doExplain();
  }, [alert.id]);

  const scoreColor = data ? TIER_BAR_COLOR(data.risk_score) : "var(--text-3)";
  const confColor  = { HIGH:"var(--crit)", MEDIUM:"var(--high)", LOW:"var(--text-2)" };

  return (
    <div className="explain-overlay" onClick={onClose}>
      <div className="explain-panel" onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="explain-header">
          <div>
            <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
              <Icon name="brain" size={16} color="var(--accent)" />
              <span style={{ fontWeight:700, fontSize:16, color:"var(--text-1)" }}>Explain This Alert</span>
            </div>
            <div style={{ display:"flex", gap:6, flexWrap:"wrap" }}>
              <span className={`badge ${alert.severity}`}>{alert.severity}</span>
              <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--text-3)" }}>{alert.id}</span>
              {alert.is_anomalous && <span className="badge ANOMALY">⚡ ANOMALY</span>}
            </div>
          </div>
          <button className="btn" onClick={onClose}><Icon name="x" size={14} /></button>
        </div>

        <div className="explain-body">
          {loading ? (
            <div style={{ display:"flex", flexDirection:"column", gap:12, padding:"8px 0" }}>
              <div style={{ display:"flex", alignItems:"center", gap:10, color:"var(--text-2)", fontFamily:"var(--font-mono)", fontSize:13 }}>
                <div className="spinner" /> Analysing alert…
              </div>
              {[120,200,160,180,100].map((w,i) => <div key={i} className="skeleton" style={{ height:14, width:`${w}px`, maxWidth:"100%" }} />)}
            </div>
          ) : data ? (
            <>
              {/* Risk score + summary */}
              <div className="explain-section">
                <div className="explain-section-title">Risk Assessment</div>
                <div style={{ padding:14 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:20, marginBottom:14 }}>
                    <div style={{ textAlign:"center" }}>
                      <div className="score-big" style={{ color:scoreColor }}>{data.risk_score}</div>
                      <div style={{ fontSize:10, fontFamily:"var(--font-mono)", color:"var(--text-3)", marginTop:2 }}>/ 100</div>
                    </div>
                    <div style={{ flex:1 }}>
                      <div style={{ marginBottom:8 }}>
                        <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:scoreColor, background:`${scoreColor}20`, border:`1px solid ${scoreColor}50`, padding:"2px 8px", borderRadius:3 }}>
                          {data.risk_tier || data.severity} RISK
                        </span>
                        <span style={{ marginLeft:8, fontFamily:"var(--font-mono)", fontSize:11, color:confColor[data.confidence] || "var(--text-2)" }}>
                          {data.confidence} CONFIDENCE
                        </span>
                        {data.llm_provider && (
                          <span className="provider-tag" style={{ marginLeft:8 }}>
                            {data.llm_provider === "offline" ? "⚙ OFFLINE" : data.llm_provider === "gemini" ? "◆ GEMINI" : "◆ OPENAI"}
                          </span>
                        )}
                      </div>
                      {/* Score breakdown */}
                      {data.score_breakdown && (
                        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"2px 12px" }}>
                          {Object.entries(data.score_breakdown).map(([k,v]) => v > 0 && (
                            <div key={k} style={{ display:"flex", justifyContent:"space-between", fontSize:10, fontFamily:"var(--font-mono)", color:"var(--text-3)", padding:"1px 0" }}>
                              <span>{k.replace(/_/g," ")}</span>
                              <span style={{ color:"var(--text-2)" }}>+{v}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                  <div style={{ fontSize:14, fontWeight:600, color:"var(--text-1)", lineHeight:1.5 }}>{data.summary}</div>
                </div>
              </div>

              {/* MITRE matches */}
              {data.mitre_matches?.length > 0 && (
                <div className="explain-section">
                  <div className="explain-section-title">MITRE ATT&CK Mapping</div>
                  <div style={{ padding:12 }}>
                    {data.mitre_matches.map(m => (
                      <div key={m.technique_id} style={{ marginBottom:10, padding:"10px 12px", background:"var(--bg-hover)", borderRadius:4, border:"1px solid var(--border)" }}>
                        <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
                          <span className="mitre-badge">{m.technique_id}</span>
                          <span style={{ fontWeight:600, fontSize:13 }}>{m.technique}</span>
                          <span style={{ marginLeft:"auto", fontFamily:"var(--font-mono)", fontSize:10, color:"var(--info)" }}>{m.tactic}</span>
                        </div>
                        <div style={{ fontSize:12, color:"var(--text-2)", marginBottom:6 }}>{m.description}</div>
                        {m.mitigations?.length > 0 && (
                          <div style={{ display:"flex", flexWrap:"wrap", gap:4 }}>
                            {m.mitigations.map(mit => (
                              <span key={mit} style={{ padding:"1px 6px", borderRadius:3, background:"var(--accent-dim)", color:"var(--accent)", border:"1px solid var(--accent-glow)", fontSize:10, fontFamily:"var(--font-mono)" }}>{mit}</span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* AI narrative */}
              <div className="explain-section">
                <div className="explain-section-title">What Happened</div>
                <div className="explain-section-body">{data.what_happened}</div>
              </div>
              <div className="explain-section">
                <div className="explain-section-title">Why It Matters</div>
                <div className="explain-section-body">{data.why_it_matters}</div>
              </div>
              <div className="explain-section">
                <div className="explain-section-title">Attack Stage</div>
                <div style={{ padding:14 }}>
                  <span className="incident-chain"><Icon name="zap" size={10} color="var(--info)" /> {data.attack_stage}</span>
                </div>
              </div>

              {/* Suggested actions */}
              {data.suggested_actions?.length > 0 && (
                <div className="explain-section">
                  <div className="explain-section-title">Suggested Actions — Playbook</div>
                  <div style={{ padding:"8px 14px" }}>
                    {data.suggested_actions.map((a, i) => (
                      <div key={i} className="action-row">
                        <div className={`action-priority p${a.priority}`}>{a.priority}</div>
                        <div style={{ flex:1 }}>
                          <div style={{ fontWeight:600, fontSize:13, marginBottom:2 }}>{a.action}</div>
                          <div style={{ fontSize:12, color:"var(--text-2)" }}>{a.rationale}</div>
                        </div>
                        <div style={{ display:"flex", flexDirection:"column", alignItems:"flex-end", gap:4, flexShrink:0 }}>
                          <span className="cat-tag">{a.category}</span>
                          <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--text-3)" }}>{a.time_est}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* LLM recommended actions */}
              {data.recommended_actions?.length > 0 && (
                <div className="explain-section">
                  <div className="explain-section-title">AI Recommended Actions</div>
                  <div style={{ padding:"8px 14px" }}>
                    {data.recommended_actions.map((a, i) => (
                      <div key={i} style={{ display:"flex", gap:10, padding:"8px 0", borderBottom:"1px solid rgba(255,255,255,0.03)" }}>
                        <Icon name="check" size={14} color="var(--accent)" />
                        <span style={{ fontSize:13, color:"var(--text-1)" }}>{a}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Analyst notes */}
              {data.analyst_notes && (
                <div className="explain-section">
                  <div className="explain-section-title">Analyst Notes</div>
                  <div className="explain-section-body" style={{ color:"var(--text-2)", fontSize:13 }}>{data.analyst_notes}</div>
                </div>
              )}
            </>
          ) : null}
        </div>
      </div>
    </div>
  );
}

// ── Root App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [view, setView]                 = useState("dashboard");
  const [explainAlert, setExplainAlert] = useState(null);
  const [connected, setConnected]       = useState(false);
  const [alerts,    setAlerts]          = useState(() => MOCK_ALERTS);
  const [incidents, setIncidents]       = useState(() => MOCK_INCIDENTS);

  // Live clock
  useEffect(() => {
    const tick = () => {
      const el = document.getElementById("live-clock");
      if (el) el.textContent = new Date().toLocaleTimeString("en-US", { hour12:false });
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);

  // ── Polling: alerts ───────────────────────────────────────────────────────
  // Tries GET /alerts every 15 s. On API failure, injects 1–3 fresh mock
  // events so the dashboard never goes stale in demo mode.
  const handleAlertData = useCallback((json) => {
    const incoming = Array.isArray(json) ? json : Array.isArray(json?.alerts) ? json.alerts : null;
    // Only replace state if the backend actually returned alerts.
    // An empty array means the endpoint exists but has no data yet —
    // keep existing alerts so the UI never goes blank.
    if (incoming && incoming.length > 0) setAlerts(incoming);
    setConnected(true);
  }, []);

  const handleAlertFallback = useCallback(() => {
    setConnected(false);
    // Inject fresh mock events to simulate live ingestion
    const count = rand(1, 3);
    const fresh = Array.from({ length: count }, (_, i) => {
      const a = makeAlert(Date.now() + i);
      a.timestamp = new Date().toISOString();
      a.created_at = new Date().toISOString();
      return a;
    });
    setAlerts(prev => {
      const merged = [...fresh, ...prev];
      // Deduplicate by id, keep newest 60
      const seen = new Set();
      return merged.filter(a => { if (seen.has(a.id)) return false; seen.add(a.id); return true; }).slice(0, 60);
    });
  }, []);

  const { lastPollAt, pollCount, error: pollError } = usePolling({
    url:         `${API}/alerts`,
    intervalMs:  15000,
    onData:      handleAlertData,
    onFallback:  handleAlertFallback,
  });

  // ── Polling: incidents ────────────────────────────────────────────────────
  usePolling({
    url:        `${API}/incidents`,
    intervalMs: 30000,
    onData:     useCallback((json) => {
      const incoming = Array.isArray(json) ? json : Array.isArray(json?.incidents) ? json.incidents : null;
      if (incoming && incoming.length > 0) setIncidents(incoming);
    }, []),
    onFallback: useCallback(() => {
      // Simulate occasional incident status changes in demo mode
      if (Math.random() < 0.3) {
        setIncidents(prev => prev.map(inc =>
          inc.status === "open" && Math.random() < 0.2
            ? { ...inc, status:"investigating", last_seen: new Date().toISOString() }
            : inc
        ));
      }
    }, []),
  });

  const openCritical  = alerts.filter(a => a.severity === "CRITICAL" && a.status === "open").length;
  const openIncidents = incidents.filter(i => i.status !== "resolved").length;
  const stats = { openCritical };

  const VIEWS = {
    dashboard: <DashboardView alerts={alerts} incidents={incidents} onExplain={setExplainAlert} />,
    alerts:    <AlertsView    alerts={alerts} onExplain={setExplainAlert} />,
    incidents: <IncidentsView incidents={incidents} />,
    live:      <LiveFeedView  alerts={alerts} />,
    mitre:     <MitreView />,
    fim:       <FIMView />,
  };

  const PAGE_TITLES = {
    dashboard: "Dashboard",      alerts: "Alerts",
    incidents: "Incidents",      live:   "Live Feed",
    mitre:     "MITRE ATT&CK",  fim:    "File Integrity Monitoring",
  };

  const pollStatus = connected
    ? `Connected → ${API} · poll #${pollCount} · ${lastPollAt?.toLocaleTimeString() ?? "—"}`
    : `Demo mode · ${pollError ?? "backend unreachable"} · mock refresh every 15 s`;

  return (
    <div className="shell">
      <Header stats={stats} connected={connected} />
      <Sidebar view={view} setView={setView} counts={{ open:openCritical, incidents:openIncidents }} />
      <main className="main">
        <div>
          <div className="page-title">{PAGE_TITLES[view]}</div>
          <div className="page-sub">{pollStatus}</div>
        </div>
        {VIEWS[view]}
      </main>
      {explainAlert && <ExplainPanel alert={explainAlert} onClose={() => setExplainAlert(null)} />}
    </div>
  );
}
