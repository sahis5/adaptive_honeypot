import React from "react";

export default function StatsCard({label, value, hint, className}) {
  return (
    <div className={`card stat ${className || ""}`}>
      <div className="label" style={{fontSize:12}}>{label}</div>
      <div className="value">{value}</div>
      {hint && <div style={{color:"#6b7280", fontSize:12, marginTop:6}}>{hint}</div>}
    </div>
  );
}
