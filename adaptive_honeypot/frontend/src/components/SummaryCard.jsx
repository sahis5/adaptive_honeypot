import React from "react";

export default function SummaryCard({ title, value, hint, error }) {
  return (
    <div className={`card summary ${error ? "error-card" : ""}`}>
      <h3>{title}</h3>
      <div className="big">{value}</div>
      {hint && <div className="muted small">{hint}</div>}
    </div>
  );
}
