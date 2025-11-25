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

// Use Vite env (import.meta.env) — browser-safe
// Vite exposes env vars via import.meta.env
const BACKEND = import.meta.env.VITE_BACKEND_URL ?? "http://localhost:5000";
const TOKEN   = import.meta.env.VITE_ADMIN_TOKEN ?? "supersecretlocaltoken";


/* small friendly mapping for long attack categories / reasons -> short labels */
const friendlyType = (decision) => {
  if (!decision) return "Unknown";

  // prefer explicit attack_type if present and short
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

  // fallback on reason names
  const r = (decision.reason || "").toLowerCase();
  if (r.includes("sqli")) return "SQLi";
  if (r.includes("xss")) return "XSS";
  if (r.includes("portscan")) return "Port Scan";
  if (r.includes("bruteforce")) return "Brute Force";
  if (r.includes("ml_detected")) return (decision.attack_type || "ML Attack");
  if (r.includes("no_match")) return "Benign";

  return "Unknown";
};

const colorFor = (label) => {
  switch (label) {
    case "SQLi": return "#e63946";
    case "XSS": return "#f77f00";
    case "Port Scan": return "#ffbe0b";
    case "Brute Force": return "#8ac926";
    case "Benign": return "#a8dadc";
    case "Unknown": return "#6c757d";
    default: return "#457b9d";
  }
};

function formatTs(ts) {
  if (!ts) return "";
  const t = Number(ts);
  if (!Number.isNaN(t)) {
    // heuristics for seconds/millis
    if (t > 1e12) return dayjs(t).format("HH:mm:ss");
    if (t > 1e9) return dayjs(t * 1000).format("HH:mm:ss");
  }
  // fallback - try to parse string timestamps
  const parsed = dayjs(ts);
  if (parsed.isValid()) return parsed.format("HH:mm:ss");
  return dayjs().format("HH:mm:ss");
}

export default function App() {
  const [status, setStatus] = useState(null);
  const [recent, setRecent] = useState([]);
  const [loading, setLoading] = useState(false);

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${BACKEND}/debug/status?token=${TOKEN}`, { timeout: 4000 });
      setStatus(res.data);
      // select recent_logs or recent_events (some backends differ)
      const logs = res.data?.recent_logs ?? res.data?.recent_events ?? res.data?.recent ?? [];
      // ensure array and reverse so newest appear first in UI
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
    const t = setInterval(fetchStatus, 3000);
    return () => clearInterval(t);
  }, []);

  const parsedEvents = useMemo(() => {
    return recent.map((ev, idx) => {
      // normalize across different event shapes
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

  // attacks by type (pie)
  const attacksByType = useMemo(() => {
    const counts = {};
    parsedEvents.forEach((e) => {
      counts[e.label] = (counts[e.label] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [parsedEvents]);

  // attacks over time (line)
  const attacksOverTime = useMemo(() => {
    const map = {};
    parsedEvents.forEach((e) => {
      const key = formatTs(e.ts);
      map[key] = (map[key] || 0) + 1;
    });
    // keep chronological order
    const entries = Object.entries(map).map(([time, value]) => ({ time, attacks: value }));
    return entries.sort((a,b) => a.time.localeCompare(b.time));
  }, [parsedEvents]);

  return (
    <div className="page">
      <header className="topbar">
        <h1>Adaptive Honeypot — Dashboard</h1>
        <div className="top-actions">
          <button className="btn" onClick={fetchStatus}>{loading ? "Refreshing..." : "Refresh now"}</button>
          <a className="btn ghost" href={BACKEND} target="_blank" rel="noreferrer">Open backend root</a>
        </div>
      </header>

      <section className="summary">
        <div className="card small">
          <div className="card-title">Service</div>
          <div className="big">
            {status && !status.error ? <span className="online">Online</span> : <span className="offline">Offline</span>}
          </div>
          <div className="muted">Last: {dayjs().format("DD/MM/YYYY, HH:mm:ss")}</div>
        </div>

        <div className="card small">
          <div className="card-title">Models loaded</div>
          <div className="big">
            {status?.models_list
              ? (Array.isArray(status.models_list) ? status.models_list.length : Object.keys(status.models_list || {}).length)
              : 0}
          </div>
          <div className="muted small-wrap">{status?.external_models_dir ?? "—"}</div>
        </div>

        <div className="card small">
          <div className="card-title">Q-table</div>
          <div className="big">{status?.q_table_exists ? "Yes" : "No"}</div>
          <div className="muted">RL Q-table loaded?</div>
        </div>

        <div className="card small">
          <div className="card-title">Recent detections</div>
          <div className="big">{parsedEvents.length}</div>
          <div className="muted">recent events shown</div>
        </div>
      </section>

      <section className="main-grid">
        <div className="card events">
          <div className="card-title">Recent events</div>
          {parsedEvents.length === 0 ? (
            <div className="empty">No recent events</div>
          ) : (
            <table className="events-table">
              <thead>
                <tr><th>Time</th><th>Source</th><th>Type</th><th>Conf</th><th>Action</th></tr>
              </thead>
              <tbody>
                {parsedEvents.slice(0, 10).map(ev => (
                  <tr key={ev.id}>
                    <td>{ev.when}</td>
                    <td>{ev.src}</td>
                    <td>{ev.label}</td>
                    <td>{Math.round((ev.conf || 0) * 100)}%</td>
                    <td><span className={`badge ${ev.action === "redirect" ? "badge-warn" : "badge-ok"}`}>{ev.action}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card status">
          <div className="card-title">Backend status</div>
          <pre className="status-box">{status ? JSON.stringify(status, null, 2) : "No status"}</pre>
          <div className="card-actions">
            <button className="btn" onClick={() => { setRecent([]); }}>Clear events</button>
            <a className="btn ghost" href={`${BACKEND}/debug/status?token=${TOKEN}`} target="_blank" rel="noreferrer">Open backend UI</a>
          </div>
        </div>

        <div className="card chart-card">
          <div className="card-title">Attacks by type</div>
          <div style={{ width: "100%", height: 220 }}>
            <ResponsiveContainer>
              <PieChart>
                <Pie data={attacksByType} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2}>
                  {attacksByType.map((entry) => (
                    <Cell key={entry.name} fill={colorFor(entry.name)} />
                  ))}
                </Pie>
                <Tooltip formatter={(v) => `${v} events`} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card chart-card">
          <div className="card-title">Attacks over time</div>
          <div style={{ width: "100%", height: 220 }}>
            <ResponsiveContainer>
              <LineChart data={attacksOverTime}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Line type="monotone" dataKey="attacks" stroke="#1f77b4" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      <footer className="footer">Dashboard automatically refreshes every 3s.</footer>
    </div>
  );
}
