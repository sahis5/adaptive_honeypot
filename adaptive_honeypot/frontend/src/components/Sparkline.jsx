import React from "react";

/*
  Minimal sparkline: draws an SVG polyline scaled to values array.
  values: array of numbers
*/
export default function Sparkline({ values = [] , width=200, height=40}) {
  if (!values || values.length === 0) {
    return <div className="spark-empty">—</div>;
  }
  const max = Math.max(...values);
  const min = Math.min(...values);
  const range = Math.max(1, max - min);
  const step = width / Math.max(1, values.length - 1);
  const points = values.map((v,i) => {
    const x = i * step;
    const y = height - ((v - min) / range) * height;
    return `${x},${y}`;
  }).join(" ");

  return (
    <svg width={width} height={height} className="sparkline" viewBox={`0 0 ${width} ${height}`}>
      <polyline fill="none" stroke="currentColor" strokeWidth="2" points={points} />
    </svg>
  );
}
