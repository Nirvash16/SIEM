import React, { useEffect, useState } from 'react'
import TopologyView from './components/TopologyView.jsx'
import VisibilityDashboard from './components/VisibilityDashboard.jsx'
import ApprovalQueue from './components/ApprovalQueue.jsx'
import TriggerFeed from './components/TriggerFeed.jsx'
import IntelTraining from './components/IntelTraining.jsx'
import NodeDrawer from './components/NodeDrawer.jsx'
import { api, connectTelemetry } from './lib/api.js'

const TABS = [
  ['TOPOLOGY', 'Live Incident & Network Topology'],
  ['VISIBILITY', 'DDoS Visibility Matrix'],
  ['APPROVALS', 'CISO HITL Approval Queue'],
  ['FIREWALL', 'IDS/IPS/DDoS Trigger Feed · Firewall Mgmt'],
  ['INTEL', 'Threat Intel & Training Pipeline'],
]

export default function App() {
  const [tab, setTab] = useState('TOPOLOGY')
  const [health, setHealth] = useState(null)
  const [wsUp, setWsUp] = useState(false)
  const [selectedNode, setSelectedNode] = useState(null)
  const [pendingCount, setPendingCount] = useState(0)

  useEffect(() => {
    const load = () => {
      api.health().then(setHealth).catch(() => setHealth({ status: 'OFFLINE' }))
      api.queue().then((q) => setPendingCount(q.length)).catch(() => {})
    }
    load(); const t = setInterval(load, 15000); return () => clearInterval(t)
  }, [tab])

  useEffect(() => {
    let ws, closed = false
    const tryConnect = () => { if (closed) return; ws = connectTelemetry(() => setWsUp(true)); ws.onopen = () => setWsUp(true); ws.onclose = () => { setWsUp(false); if (!closed) setTimeout(tryConnect, 4000) } }
    tryConnect()
    return () => { closed = true; ws?.close() }
  }, [])

  return (
    <div className="scanlines h-screen flex flex-col p-3 gap-3 overflow-hidden">
      {/* Header */}
      <header className="panel px-4 py-2 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-4">
          <div className="text-neon-cyan font-extrabold tracking-[0.3em] text-sm">⬢ AI CYBER COMMAND</div>
          <nav className="flex gap-1">
            {TABS.map(([id, title]) => (
              <button key={id} title={title} onClick={() => setTab(id)}
                className={`px-3 py-1 rounded text-[10px] font-bold uppercase tracking-wider border ${
                  tab === id ? 'bg-neon-cyan/20 text-neon-cyan border-neon-cyan shadow-glow' : 'border-edge text-slate-500 hover:text-slate-300'}`}>
                {id}{id === 'APPROVALS' && pendingCount > 0 && (
                  <span className="ml-2 badge bg-neon-red text-void animate-pulse">{pendingCount}</span>)}
              </button>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-4 text-[10px]">
          <span className="text-slate-500 hidden lg:block italic">TENET: Comprehensive Network Visibility is non-negotiable</span>
          <span className={health?.status === 'OPERATIONAL' ? 'text-neon-green' : 'text-neon-red'}>
            ● CORE {health?.status || '…'}
          </span>
          <span className={wsUp ? 'text-neon-green' : 'text-neon-amber'}>● WS TELEMETRY {wsUp ? 'LIVE' : 'CONNECTING'}</span>
          <span className="text-neon-violet">INC {health?.incidents ?? '—'} · MITIG {health?.active_mitigations ?? '—'} · INTEL {health?.intel_corpus ?? '—'}</span>
        </div>
      </header>

      {/* Main view */}
      <main className="flex-1 min-h-0 relative">
        {tab === 'TOPOLOGY' && (
          <div className="grid grid-cols-4 gap-3 h-full">
            <div className="col-span-3"><TopologyView onSelectNode={setSelectedNode} /></div>
            <div className="flex flex-col gap-3 min-h-0">
              <div className="flex-1 min-h-0"><VisibilityDashboard /></div>
            </div>
          </div>
        )}
        {tab === 'VISIBILITY' && <VisibilityDashboard />}
        {tab === 'APPROVALS' && <ApprovalQueue onActioned={() => api.health().then(setHealth)} />}
        {tab === 'FIREWALL' && <TriggerFeed />}
        {tab === 'INTEL' && <IntelTraining />}
      </main>

      <NodeDrawer nodeId={selectedNode} onClose={() => setSelectedNode(null)} />
    </div>
  )
}
