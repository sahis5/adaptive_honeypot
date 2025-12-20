// frontend/src/App.jsx
import React, { useEffect, useState, useMemo } from "react";
import axios from "axios";
import dayjs from "dayjs";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import "./styles.css";
import { ThemeProvider, useTheme } from "./ThemeContext";
import RetroGlobe from "./components/RetroGlobe";

// Use Vite env (import.meta.env) — browser-safe
const BACKEND = import.meta.env.VITE_BACKEND_URL ?? "http://localhost:5000";
const TOKEN = import.meta.env.VITE_ADMIN_TOKEN ?? "supersecretlocaltoken";


/* friendly mapping for attack categories */
const friendlyType = (decision) => {
  if (!decision) return "Unknown";
  const at = decision.attack_type || decision.label || "";
  if (typeof at === "string" && at.trim().length) {
    const low = at.toLowerCase();
    if (low.includes("sql")) return "SQLi";
    if (low.includes("xss")) return "XSS";
    if (low.includes("port")) return "Port Scan";
    if (low.includes("brute")) return "Brute Force";
    if (low.includes("benign") || low.includes("normal")) return "Benign";
    return at.split("-")[0].trim();
  }
  const r = (decision.reason || "").toLowerCase();
  if (r.includes("sqli")) return "SQLi";
  if (r.includes("xss")) return "XSS";
  if (r.includes("portscan")) return "Port Scan";
  if (r.includes("bruteforce")) return "Brute Force";
  if (r.includes("ml_detected")) return (decision.attack_type || "ML Attack");
  if (r.includes("no_match")) return "Benign";
  return "Unknown";
};

// Cyber-themed colors
const COLORS = {
  SQLi: "#ef4444",        // Red
  XSS: "#f97316",         // Orange
  "Port Scan": "#fbbf24", // Amber
  "Brute Force": "#84cc16", // Lime
  Benign: "#3b82f6",      // Blue
  Unknown: "#64748b",     // Slate
  Default: "#6366f1"      // Indigo
};

const colorFor = (label) => COLORS[label] || COLORS.Default;

function formatTs(ts) {
  if (!ts) return "";
  const t = Number(ts);
  if (!Number.isNaN(t)) {
    if (t > 1e12) return dayjs(t).format("HH:mm:ss");
    if (t > 1e9) return dayjs(t * 1000).format("HH:mm:ss");
  }
  const parsed = dayjs(ts);
  if (parsed.isValid()) return parsed.format("HH:mm:ss");
  return dayjs().format("HH:mm:ss");
}

function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  return (
    <button className="btn btn-ghost" onClick={toggleTheme} title="Toggle Theme">
      {theme === 'dark' ? '☀️ Light' : '🌙 Dark'}
    </button>
  );
}

function DashboardContent() {
  const [status, setStatus] = useState(null);
  const [recent, setRecent] = useState([]);
  const [loading, setLoading] = useState(false);
  const { theme } = useTheme();

  // Chart customization based on theme
  const chartStroke = theme === 'dark' ? '#94a3b8' : '#64748b';
  const gridStroke = theme === 'dark' ? '#334155' : '#e2e8f0';
  const tooltipBg = theme === 'dark' ? '#1e293b' : '#ffffff';
  const tooltipBorder = theme === 'dark' ? '#334155' : '#e2e8f0';

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${BACKEND}/debug/status?token=${TOKEN}`, { timeout: 4000 });
      setStatus(res.data);
      const logs = res.data?.recent_logs ?? res.data?.recent_events ?? res.data?.recent ?? [];
      const arr = Array.isArray(logs) ? logs.slice().reverse() : [];
      setRecent(arr.slice(0, 200));
    } catch (err) {
      console.error("status fetch error", err?.message || err);
      setStatus({ error: err?.message || "Cannot reach backend" });
      setRecent([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  const parsedEvents = useMemo(() => {
    return recent.map((ev, idx) => {
      const decision = ev.decision || ev.action_result?.decision || ev;
      const src = ev.src_ip || ev.source || ev.ip || ev.action_result?.src_ip || ev.host || "n/a";
      const ts = ev.ts || ev.time || ev.timestamp || ev.t || ev.created || Date.now();
      const label = friendlyType(decision);
      const conf = Number(decision?.confidence ?? decision?.conf ?? 0);
      const action = ev.action || ev.action_result?.action || (ev.event === "honeypot_action" ? "redirect" : "normal");
      const raw = ev.payload || ev.msg || ev.message || "";
      return {
        id: `${idx}-${ts || Math.random()}`,
        src,
        ts,
        when: formatTs(ts),
        label,
        conf,
        action,
        raw,
        decision,
      };
    });
  }, [recent]);

  const attacksByType = useMemo(() => {
    const counts = {};
    parsedEvents.forEach((e) => {
      counts[e.label] = (counts[e.label] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [parsedEvents]);

  const attacksOverTime = useMemo(() => {
    const map = {};
    parsedEvents.forEach((e) => {
      const key = formatTs(e.ts);
      map[key] = (map[key] || 0) + 1;
    });
    const entries = Object.entries(map).map(([time, value]) => ({ time, attacks: value }));
    return entries.sort((a, b) => a.time.localeCompare(b.time));
  }, [parsedEvents]);

  // Determine if under active attack (event within last 10 seconds and not Benign)
  const isAttackActive = useMemo(() => {
    if (parsedEvents.length === 0) return false;
    const latest = parsedEvents[0];
    const now = Date.now();
    // heuristic: if ts is recent
    let t = Number(latest.ts);
    if (t > 1e12) { /* ms */ } else if (t > 1e9) { t = t * 1000; } else { return false; }

    const diff = now - t;
    return (diff < 10000 && latest.label !== 'Benign' && latest.label !== 'Unknown');
  }, [parsedEvents]);

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div style={{ background: tooltipBg, padding: '10px', border: `1px solid ${tooltipBorder}`, borderRadius: '8px' }}>
          <p style={{ margin: 0, fontWeight: 'bold' }}>{label}</p>
          <p style={{ margin: 0 }}>{`${payload[0].name}: ${payload[0].value}`}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="page">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">🛡️</div>
          <h1>Adaptive Honeypot Command Center</h1>
        </div>
        <div className="top-actions">
          <ThemeToggle />
          <button className="btn btn-primary" onClick={fetchStatus}>
            {loading ? <span className="shimmer">Refreshing...</span> : "Refresh Data"}
          </button>
          <a className="btn btn-ghost" href={BACKEND} target="_blank" rel="noreferrer">API Root</a>
        </div>
      </header>

      <section className="summary">
        {/* Retro Globe Card */}
        {/* Retro Globe Card */}
        <div className="card globe-card" style={{ padding: 0, position: 'relative', overflow: 'hidden', minHeight: '160px', background: 'var(--bg-card)' }}>
          <div style={{ width: '100%', height: '100%', position: 'absolute', inset: 0 }}>
            <RetroGlobe isAlert={isAttackActive} />
          </div>

          {/* Status Overlay - bottom left, hover only (handled in css) */}
          <div className="threat-status" style={{
            position: 'absolute',
            bottom: 15,
            left: 15,
            pointerEvents: 'none',
            zIndex: 10
          }}>
            <div className="card-title" style={{ marginBottom: 2 }}>Threat Status</div>
            <div className="big-stat" style={{
              fontSize: '1.2rem',
              color: isAttackActive ? 'var(--danger)' : 'var(--primary)',
              textShadow: '0 2px 4px rgba(0,0,0,0.5)'
            }}>
              {isAttackActive ? "⚠ CRITICAL ALERT" : "SYSTEM SECURE"}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-title">System Status</div>
          <div className="big-stat">
            {status && !status.error ?
              <span className="status-indicator status-online">● Online</span> :
              <span className="status-indicator status-offline">● Offline</span>
            }
          </div>
          <div className="meta-text">Last heartbeat: {dayjs().format("HH:mm:ss")}</div>
        </div>

        <div className="card">
          <div className="card-title">Active Models</div>
          <div className="big-stat">
            {status?.models_list
              ? (Array.isArray(status.models_list) ? status.models_list.length : Object.keys(status.models_list || {}).length)
              : 0}
          </div>
          <div className="meta-text">AI Detection Engines</div>
        </div>

        <div className="card">
          <div className="card-title">Total Detections</div>
          <div className="big-stat">{parsedEvents.length}</div>
          <div className="meta-text">In current session</div>
        </div>
      </section>

      <section className="main-grid">
        <div className="card events-card">
          <div className="card-title" style={{ marginBottom: '16px' }}>Live Threat Feed</div>

          {parsedEvents.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
              No threats detected in current window.
            </div>
          ) : (
            <div className="table-container">
              <table className="events-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Classification</th>
                    <th>Confidence</th>
                    <th>Response Action</th>
                  </tr>
                </thead>
                <tbody>
                  {parsedEvents.slice(0, 15).map(ev => (
                    <tr key={ev.id}>
                      <td className="mono" style={{ color: 'var(--text-muted)' }}>{ev.when}</td>
                      <td className="mono">{ev.src}</td>
                      <td>
                        <span className="badge" style={{
                          backgroundColor: `${colorFor(ev.label)}20`,
                          color: colorFor(ev.label)
                        }}>
                          {ev.label}
                        </span>
                      </td>
                      <td>
                        {/* Progress bar style confidence */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <div style={{ flex: 1, height: '4px', background: 'var(--border)', borderRadius: '2px', width: '60px' }}>
                            <div style={{
                              width: `${(ev.conf || 0) * 100}%`,
                              height: '100%',
                              background: ev.conf > 0.8 ? 'var(--success)' : 'var(--warning)',
                              borderRadius: '2px'
                            }} />
                          </div>
                          <span style={{ fontSize: '0.75rem' }}>{Math.round((ev.conf || 0) * 100)}%</span>
                        </div>
                      </td>
                      <td>
                        <span className={`badge ${ev.action === "redirect" ? "badge-warning" : "badge-success"}`}>
                          {ev.action === 'redirect' ? '⚠️ HONEYPOT' : 'ALLOW'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="right-panel" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div className="card chart-card">
            <div className="card-title">Attack Distribution</div>
            <div className="chart-body">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={attacksByType}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={60}
                    outerRadius={85}
                    paddingAngle={4}
                    stroke="none"
                  >
                    {attacksByType.map((entry) => (
                      <Cell key={entry.name} fill={colorFor(entry.name)} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '10px', fontSize: '0.75rem' }}>
              {attacksByType.map(a => (
                <div key={a.name} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: colorFor(a.name) }} />
                  <span style={{ color: 'var(--text-muted)' }}>{a.name}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="card chart-card">
            <div className="card-title">Traffic Velocity</div>
            <div className="chart-body">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={attacksOverTime}>
                  <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} vertical={false} />
                  <XAxis
                    dataKey="time"
                    stroke={chartStroke}
                    fontSize={12}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    allowDecimals={false}
                    stroke={chartStroke}
                    fontSize={12}
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip content={<CustomTooltip />} />
                  <Line
                    type="monotone"
                    dataKey="attacks"
                    stroke="var(--primary)"
                    strokeWidth={3}
                    dot={{ r: 4, fill: 'var(--bg-card)', strokeWidth: 2 }}
                    activeDot={{ r: 6 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="card" style={{ maxHeight: '300px', display: 'flex', flexDirection: 'column' }}>
            <div className="card-title">Backend Diagnostics</div>
            <div className="terminal-box custom-scrollbar">
              {status ? JSON.stringify(status, null, 2) : "Establishing connection..."}
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button className="btn btn-ghost" style={{ width: '100%' }} onClick={() => setRecent([])}>Clear Local Log</button>
            </div>
          </div>
        </div>
      </section>

      <footer className="footer">
        System Auto-Refresh: 3000ms • Connected to {BACKEND}
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <DashboardContent />
    </ThemeProvider>
  );
}
