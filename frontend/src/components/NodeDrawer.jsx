import React, { useEffect, useState } from 'react'
import { api, fmtBps, fmtNum } from '../lib/api.js'

const hexToAscii = (hex) => {
  let out = ''
  for (let i = 0; i < hex.length; i += 2) {
    const c = parseInt(hex.slice(i, i + 2), 16)
    out += c >= 32 && c < 127 ? String.fromCharCode(c) : '.'
  }
  return out
}

export default function NodeDrawer({ nodeId, onClose }) {
  const [detail, setDetail] = useState(null)
  const [traces, setTraces] = useState([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!nodeId) return
    setLoading(true); setDetail(null)
    api.nodeDetail(nodeId).then(setDetail).catch(() => setDetail({ error: 'Node detail unavailable' }))
      .finally(() => setLoading(false))
    // pull agent reasoning traces for any related incident
    Promise.resolve().then(async () => {
      const incidents = await api.incidents().catch(() => [])
      const ip = nodeId.includes('.') ? nodeId : (detail?.node?.label || '').split('\n')[0]
      const rel = incidents.filter((i) => JSON.stringify(i).includes(ip))
      const all = await Promise.all(rel.map((i) => api.traces(i.incident_id).catch(() => [])))
      setTraces(all.flat().slice(0, 8))
    })
  }, [nodeId]) // eslint-disable-line

  if (!nodeId) return null
  return (
    <aside className="fixed inset-y-0 right-0 w-[480px] max-w-full z-40 bg-panel/95 backdrop-blur border-l border-neon-cyan/40 shadow-glow overflow-y-auto p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-neon-cyan font-bold uppercase tracking-widest text-sm">Entity Detail Drawer</h3>
        <button onClick={onClose} className="badge border border-neon-red text-neon-red">✕ CLOSE</button>
      </div>

      {loading && <div className="text-slate-500 animate-pulse text-xs">QUERYING Neo4j / TimescaleDB…</div>}

      {detail && !detail.error && (
        <>
          <div className="panel p-3 mb-3">
            <div className="text-[10px] text-slate-500 uppercase">{detail.node.node_type} · {detail.node.status}</div>
            <div className="whitespace-pre-line font-bold">{detail.node.label}</div>
            <div className="mt-2 grid grid-cols-2 gap-2 text-[11px]">
              <div className="border border-edge rounded px-2 py-1">bps: <span className="text-neon-red">{fmtBps(detail.live_metrics.bps)}</span></div>
              <div className="border border-edge rounded px-2 py-1">pps: <span className="text-neon-red">{fmtNum(detail.live_metrics.pps)}</span></div>
            </div>
          </div>

          <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Active IDS Signatures (SID)</div>
          <div className="flex flex-wrap gap-1 mb-3">
            {detail.active_sids.map((s) => <span key={s} className="badge bg-neon-violet/15 text-neon-violet border border-neon-violet/30">{s}</span>)}
          </div>

          <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Raw PCAP Trace · Hex/ASCII Inspection</div>
          <div className="space-y-2 mb-3">
            {detail.pcap_traces.map((p) => (
              <div key={p.frame} className="border border-edge rounded p-2 text-[10px]">
                <div className="text-slate-500">frame {p.frame} · {p.proto} · ts {p.ts}</div>
                <div className="text-neon-green break-all mt-1">{p.hex.match(/.{1,32}/g)?.join('\n') || p.hex}</div>
                <div className="text-neon-amber mt-1 break-all">{p.ascii}</div>
                <div className="text-slate-600 break-all">{hexToAscii(p.hex)}</div>
              </div>
            ))}
          </div>

          <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Related Incidents</div>
          {detail.related_incidents.length === 0 && <div className="text-xs text-slate-600 mb-3">none correlated</div>}
          {detail.related_incidents.map((i) => (
            <div key={i.incident_id} className="border border-edge rounded p-2 mb-2 text-[11px]">
              <span className={`badge mr-2 ${i.tier === 3 ? 'bg-neon-red/20 text-neon-red' : i.tier === 2 ? 'bg-neon-amber/20 text-neon-amber' : 'bg-neon-green/20 text-neon-green'}`}>T{i.tier}</span>
              {i.title} <span className="text-slate-500">· conf {(i.confidence_score * 100).toFixed(0)}%</span>
            </div>
          ))}

          <div className="text-[10px] uppercase tracking-widest text-slate-500 mt-4 mb-1">Agent Reasoning Traces (Neo4j provenance)</div>
          {traces.map((t, idx) => (
            <details key={idx} className="border border-edge rounded mb-2 text-[11px]">
              <summary className="p-2 cursor-pointer text-neon-cyan">{t.agent_name} · step {t.step_number} · Δ{(t.confidence_delta ?? 0).toFixed(2)}</summary>
              <div className="p-2 pt-0 text-slate-400 whitespace-pre-wrap">{t.llm_thought_process}</div>
              <div className="p-2 pt-0 text-[10px] text-slate-600">tools: {JSON.stringify(t.tool_calls_executed).slice(0, 240)}</div>
            </details>
          ))}
        </>
      )}
      {detail?.error && <div className="text-neon-red text-xs">{detail.error}</div>}
    </aside>
  )
}
