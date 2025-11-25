import React from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'

const COLORS = ['#0088FE','#00C49F','#FFBB28','#FF8042','#A020F0','#FF4D4F','#2ECC71']

export default function ChartView({ events = [] }) {
  // count top attack reasons in the incoming events
  const counts = {}
  events.forEach(e => {
    if (e.event === 'incoming') {
      const r = (e.decision && e.decision.reason) ? e.decision.reason : 'unknown'
      counts[r] = (counts[r] || 0) + 1
    }
  })
  const data = Object.keys(counts).slice(0,6).map((k,i)=>({ name:k, value: counts[k] }))
  if (data.length === 0) return <div><h3>Activity</h3><div className="small">No events yet</div></div>

  return (
    <div>
      <h3>Activity</h3>
      <div style={{height:200}}>
        <ResponsiveContainer>
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" outerRadius={70} fill="#8884d8">
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
