import React from "react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Legend } from "recharts";

const COLORS = ["#1f77b4","#ff7f0e","#2ca02c","#d62728","#9467bd","#8c564b"];

export function AttacksByType({data=[]}) {
  // data: [{name: 'SQLi', value: 5}, ...]
  return (
    <div className="card" style={{height:260}}>
      <h4 style={{marginTop:0}}>Attacks by type</h4>
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={60} innerRadius={24} label>
            {data.map((entry, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
          </Pie>
          <Tooltip/>
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export function AttacksOverTime({data=[]}) {
  // data: [{time: '10:00', attacks: 3}, ...]
  return (
    <div className="card" style={{height:260}}>
      <h4 style={{marginTop:0}}>Attacks over time</h4>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="colorAtt" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#1f77b4" stopOpacity={0.8}/>
              <stop offset="95%" stopColor="#1f77b4" stopOpacity={0.05}/>
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="time" />
          <YAxis allowDecimals={false} />
          <Tooltip />
          <Legend />
          <Area type="monotone" dataKey="attacks" stroke="#1f77b4" fill="url(#colorAtt)" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
