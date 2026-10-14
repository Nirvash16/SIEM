import React, { useEffect, useState } from 'react'
import { api, connectTelemetry, fmtBps } from '../lib/api.js'

const TYPE_BADGE = {
  INCIDENT_SEEDED: 'text-slate-400', TIER1_AUTONOMOUS_EXECUTION: 'text-neon-green',
  MITIGATION_APPLIED: 'text-neon-cyan', PROPOSAL_CREATED: 'text-neon-amber',
  DDOS_VOLUME_SPIKE: 'text-neon-red', IPS_DROP: 'text-neon-violet',
}

export default function TriggerFeed() {
  const [events, setEvents] = useState([])
  const [live, setLive] = useState([])
  const [policies, setPolicies] = useState([])

  useEffect(() => {
    api.triggerFeed().then(setEvents).catch(() => {})
    api.policies().then(setPolicies).catch(() => {})
    const t = setInterval(() => api.triggerFeed().then(setEvents).catch(() => {}), 8000)
    return () => clearInterval(t)
  }, [])

  // live WebSocket telemetry stream appended to feed
  useEffect(() => {
    const ws = connectTelemetry((ev) => {
      if (ev.topic === 'snapshot') return
      setLive((prev) => [{ topic: ev.topic, payload: ev.payload || ev, ts: new Date().toISOString() }, ...prev].slice(0, 20))
    })
    return () => ws?.close()
  }, [])

  const all = [...live, ...events].slice(0, 40)

  return (
    <div className="grid grid-cols-2 gap-3 h-full overflow-hidden">
      <div className="panel flex flex-col min-h-0">
        <div className="px-3 py-2 border-b border-edge text-[10px] uppercase tracking-widest text-neon-cyan">
          Active IDS/IPS/DDoS Trigger Feed <span className="text-neon-green">● LIVE (ws)</span>
        </div>
        <div className="overflow-y-auto flex-1 text-[11px]">
          {all.map((e, i) => {
            const type = e.payload?.type || e.topic
            return (
              <div key={i} className="border-b border-edge/40 px-3 py-1.5 hover:bg-void/60">
                <span className={`${TYPE_BADGE[type] || 'text-slate-300'} font-bold`}>{type}</span>
                <span className="text-slate-500 ml-2">{new Date(e.ts).toLocaleTimeString('en-GB')}</span>
                <div className="text-slate-400 truncate">{JSON.stringify(e.payload).slice(0, 160)}</div>
              </div>
            )
          })}
        </div>
      </div>

      <div className="panel flex flex-col min-h-0">
        <div className="px-3 py-2 border-b border-edge text-[10px] uppercase tracking-widest text-neon-cyan">
          Firewall / IPS / DDoS Policy History
        </div>
        <div className="overflow-y-auto flex-1 text-[11px] p-3 space-y-2">
          {policies.map((c) => (
            <div key={c.id} className="border border-edge rounded p-2">
              <div className="flex justify-between">
                <span className="font-bold text-neon-amber">{c.rule_type}</span>
                <span className="text-slate-500">{c.enforcement_layer}</span>
              </div>
              <div className="text-slate-400 mt-1 break-all">{JSON.stringify(c.rule_definition).slice(0, 200)}</div>
              <div className="text-slate-600 mt-1">
                device {c.device_id} · by {c.applied_by_agent}{c.approved_by_human ? ` · human: ${c.approved_by_human}` : ' · AUTONOMOUS'}
                {c.expires_at ? ` · expires ${new Date(c.expires_at).toLocaleTimeString('en-GB')}` : ' · PERMANENT'}
              </div>
              {!c.rolled_back && (
                <button onClick={() => api.rollbackChange(c.id).then(() => api.policies().then(setPolicies))}
                  className="badge border border-neon-red text-neon-red mt-1 hover:bg-neon-red/20">ROLLBACK</button>
              )}
              {c.rolled_back && <span className="badge bg-edge text-slate-500 mt-1">ROLLED BACK</span>}
            </div>
          ))}
          {policies.length === 0 && <div className="text-slate-600">No policy changes recorded yet.</div>}
        </div>
      </div>
    </div>
  )
}
