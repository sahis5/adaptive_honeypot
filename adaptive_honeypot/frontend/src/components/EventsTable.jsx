import React from "react";

export default function EventsTable({events=[]}) {
  return (
    <div className="card table-wrap">
      <h3 style={{marginTop:0}}>Recent events</h3>
      {events.length === 0 ? (
        <div style={{padding:'18px 0', color:'#6b7280'}}>No recent events</div>
      ) : (
        <table className="events-table" aria-label="recent events">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Type</th>
              <th>Conf</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e, idx) => (
              <tr key={idx}>
                <td>{e.time || e.ts || e.timestamp || String(e.time_ms || "")}</td>
                <td style={{minWidth:110}}>{e.src_ip || e.source || "—"}</td>
                <td>{e.attack_type || e.type || "Unknown"}</td>
                <td>{Math.round((e.confidence || e.conf || 0) * 100) + "%"}</td>
                <td>
                  { (e.route === "honeypot") ? <span className="badge honeypot">redirect_honeypot</span> : <span className="badge normal">normal</span> }
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
