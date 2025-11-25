import React from "react";

function Row({ it }) {
  return (
    <tr>
      <td className="mono">{new Date(it.ts).toLocaleTimeString()}</td>
      <td>{it.src_ip}</td>
      <td><strong>{it.attack}</strong></td>
      <td className="muted">{it.route}</td>
      <td className="payload">{it.detail}</td>
    </tr>
  );
}

export default function AttacksTable({ items = [] }) {
  if (!items || items.length === 0) {
    return <div className="empty">No recent events</div>;
  }
  return (
    <div className="table-wrap">
      <table className="attacks-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Source</th>
            <th>Attack</th>
            <th>Route</th>
            <th>Payload / details</th>
          </tr>
        </thead>
        <tbody>
          {items.map(it => <Row key={it._id} it={it} />)}
        </tbody>
      </table>
    </div>
  );
}
