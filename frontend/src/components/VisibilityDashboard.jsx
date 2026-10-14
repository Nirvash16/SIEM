import React, { useEffect, useState } from 'react'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { api, fmtBps, fmtNum } from '../lib/api.js'

// Dynamic class strings are unsafe with Tailwind JIT — map to full literals.
const KPI_COLOR = { cyan: 'text-neon-cyan', violet: 'text-neon-violet', green: 'text-neon-green', amber: 'text-neon-amber' }

export default function VisibilityDashboard() {
  const [snap, setSnap] = useState(null)
  useEffect(() => {
    const load = () => api.visibility().then(setSnap).catch(() => {})
    load(); const t = setInterval(load, 10000); return () => clearInterval(t)
  }, [])
  if (!snap) return <div className="panel p-6 text-neon-cyan animate-pulse">ESTABLISHING VISIBILITY LINK…</div>

  const chartData = snap.baselines.map((b) => ({
    ts: new Date(b.ts).toLocaleTimeString('en-GB'),
    expected: Math.round(b.expected_bps / 1e6),
    actual: Math.round(b.actual_bps / 1e6),
    anomaly: b.anomaly_score,
  }))

  return (
    <div className="flex flex-col gap-3 h-full overflow-y-auto pr-1">
      {/* KPI strip */}
      <div className="grid grid-cols-4 gap-2">
        {[
          ['INGRESS', fmtBps(snap.total_ingress_bps), 'cyan'],
          ['PACKETS/S', fmtNum(snap.total_pps), 'violet'],
          ['ACTIVE FLOWS', fmtNum(snap.active_flows), 'green'],
          ['IDS SENSORS', `${snap.sensors_online}/${snap.sensors_total}`, snap.sensors_online === snap.sensors_total ? 'green' : 'amber'],
        ].map(([k, v, c]) => (
          <div key={k} className="panel p-3">
            <div className="text-[9px] uppercase tracking-widest text-slate-500">{k}</div>
            <div className={`text-lg font-extrabold ${KPI_COLOR[c]}`}>{v}</div>
          </div>
        ))}
      </div>

      {/* Baseline vs Anomaly heatmap chart — the fundamental tenet */}
      <div className="panel p-3">
        <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">
          Traffic Baseline vs Anomaly · NetFlow/sFlow/eBPF (Mbps)
        </div>
        <ResponsiveContainer width="100%" height={170}>
          <AreaChart data={chartData}>
            <CartesianGrid stroke="#16233b" strokeDasharray="3 3" />
            <XAxis dataKey="ts" tick={{ fill: '#64748b', fontSize: 9 }} interval="preserveStartEnd" />
            <YAxis tick={{ fill: '#64748b', fontSize: 9 }} width={44} />
            <Tooltip contentStyle={{ background: '#0a101c', border: '1px solid #16233b', fontSize: 11 }} />
            <Area type="monotone" dataKey="expected" stroke="#34d399" fill="rgba(52,211,153,0.12)" name="Expected baseline" />
            <Area type="monotone" dataKey="actual" stroke="#f87171" fill="rgba(248,113,113,0.18)" name="Actual ingress" />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Attack class breakdown */}
      <div className="panel p-3">
        <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Active DDoS Attack Classes</div>
        <div className="grid grid-cols-3 gap-2 text-center">
          {Object.entries(snap.attack_breakdown).map(([k, v]) => (
            <div key={k} className={`border border-edge rounded p-2 ${v > 0 ? 'bg-neon-red/10 shadow-glow-red' : ''}`}>
              <div className={`text-xl font-extrabold ${v > 0 ? 'text-neon-red' : 'text-slate-600'}`}>{v}</div>
              <div className="text-[9px] uppercase text-slate-500">{k}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Top adversarial talkers */}
      <div className="panel p-3">
        <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Top Adversarial Talkers</div>
        <table className="w-full text-[11px]">
          <thead><tr className="text-slate-500"><th className="text-left">SRC IP</th><th className="text-right">BPS</th><th className="text-right">PPS</th></tr></thead>
          <tbody>
            {snap.top_talkers.slice(0, 6).map((t) => (
              <tr key={t.ip} className="border-t border-edge/50">
                <td className="py-1 text-neon-red">{t.ip}</td>
                <td className="text-right">{fmtBps(t.bps)}</td>
                <td className="text-right">{fmtNum(t.pps)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
