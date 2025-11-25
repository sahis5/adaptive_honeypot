import React, { useState } from 'react'
import axios from 'axios'

export default function ConfigPanel({ config, setConfig, backend, refresh }) {
  const [threshold, setThreshold] = useState(config.ml_conf_threshold || 0.65)
  const [enabled, setEnabled] = useState(config.honeypot_enabled !== false)

  const apply = async () => {
    try {
      await axios.post(`${backend}/config`, { ml_conf_threshold: parseFloat(threshold) })
      await axios.post(`${backend}/toggle_honeypot`, { enabled: !!enabled })
      await refresh()
      alert('Config applied')
    } catch (e) {
      console.error(e)
      alert('Failed to apply config')
    }
  }

  return (
    <div>
      <h3>Controls</h3>
      <div style={{marginBottom:8}}>
        <label>ML attack threshold: {threshold}</label>
        <input type="range" min="0" max="1" step="0.01" value={threshold} onChange={e => setThreshold(e.target.value)} style={{width:'100%'}} />
      </div>
      <div style={{marginBottom:12}}>
        <label><input type="checkbox" checked={enabled} onChange={e=>setEnabled(e.target.checked)} /> Honeypot enabled</label>
      </div>
      <div>
        <button className="btn" onClick={apply}>Apply</button>
      </div>

      <hr />
      <h4>Test Vectors</h4>
      <div style={{display:'flex', flexDirection:'column', gap:8}}>
        <button className="btn" onClick={() => axios.post(`${backend}/simulate_traffic`, { src_ip: '10.0.0.9', payload: 'select * from users;' }).then(()=>refresh())}>Send SQLi</button>
        <button className="btn" onClick={() => axios.post(`${backend}/simulate_traffic`, { src_ip: '10.0.0.10', payload: '<script>alert(1)</script>' }).then(()=>refresh())}>Send XSS</button>
        <button className="btn" onClick={() => {
          for(let i=0;i<20;i++) axios.post(`${backend}/simulate_traffic`, { src_ip:'10.0.0.20', payload: `GET /path${i}`})
          .then(()=>refresh())
        }}>Send PortScan-style</button>
      </div>
    </div>
  )
}
