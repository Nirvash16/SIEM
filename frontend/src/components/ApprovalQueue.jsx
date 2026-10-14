import React, { useState } from 'react'
import Editor, { DiffEditor } from '@monaco-editor/react'
import { api, fmtBps } from '../lib/api.js'

const TIER_COLOR = { 1: 'badge bg-neon-green/20 text-neon-green', 2: 'badge bg-neon-amber/20 text-neon-amber', 3: 'badge bg-neon-red/20 text-neon-red animate-pulse' }
const IMPACT_COLOR = { CRITICAL: 'text-neon-red', HIGH: 'text-neon-red', MEDIUM: 'text-neon-amber', LOW: 'text-neon-green' }

function ruleToText(rule) {
  if (!rule) return ''
  return [
    `# ${rule.rule_id} — ${rule.action} @ ${rule.enforcement_layer}`,
    `src:      ${rule.src_ip_cidr}`,
    `dst:      ${rule.dst_ip_cidr}:${rule.dst_port}/${rule.protocol || 'TCP'}`,
    rule.rate_limit_pps ? `rate_limit: ${rule.rate_limit_pps.toLocaleString()} pps` : null,
    rule.duration_seconds ? `ttl:      ${rule.duration_seconds}s (auto-expiry sweeper armed)` : 'ttl:      PERMANENT',
    '',
    rule.rule_definition_preview || '',
  ].filter((l) => l !== null).join('\n')
}

const BASELINE_TEXT = `# Current enforced policy set (baseline before proposed change)
# No rule matching ${'{attack signature}'} exists on this enforcement layer.
permit ip any any  # legacy default — to be constrained by proposal`

export default function ApprovalQueue({ onActioned }) {
  const [queue, setQueue] = useState([])
  const [expanded, setExpanded] = useState(null)
  const [reviewer, setReviewer] = useState('Human_CISO')
  const [notes, setNotes] = useState('')
  const [busy, setBusy] = useState(null)
  const [error, setError] = useState(null)
  const [diffMode, setDiffMode] = useState(true)

  const load = () => api.queue().then(setQueue).catch((e) => setError(e.message))
  React.useEffect(() => { load(); const t = setInterval(load, 12000); return () => clearInterval(t) }, [])

  const review = async (proposalId, action) => {
    setBusy(`${proposalId}:${action}`); setError(null)
    try {
      await api.review(proposalId, action, reviewer, notes)
      setNotes(''); load(); onActioned?.()
    } catch (e) { setError(`${action} failed: ${e.message}`) } finally { setBusy(null) }
  }

  const oneClick = async (preset, incidentId) => {
    setBusy(`${incidentId}:${preset}`); setError(null)
    try { await api.oneClick(preset, incidentId); load(); onActioned?.() }
    catch (e) { setError(`One-click blocked: ${e.message}`) } finally { setBusy(null) }
  }

  const PRESETS = [
    ['deploy_temporary_ips_drop_1h', 'Deploy Temporary IPS Drop (1h)', 'border-neon-cyan text-neon-cyan'],
    ['commit_permanent_ngfw_policy', 'Commit Permanent NGFW Policy', 'border-neon-red text-neon-red'],
    ['reroute_to_honeypot', 'Reroute to Honeypot', 'border-neon-violet text-neon-violet'],
    ['activate_upstream_scrubbing', 'Activate Upstream DDoS Scrubbing', 'border-neon-green text-neon-green'],
  ]

  return (
    <div className="flex flex-col gap-3 h-full overflow-y-auto pr-1">
      <div className="panel px-4 py-2 flex items-center justify-between sticky top-0 z-10">
        <h2 className="text-neon-cyan font-bold text-sm tracking-widest uppercase">CISO Action Approval Queue · HITL Gate</h2>
        <div className="flex items-center gap-2 text-[10px]">
          <label className="text-slate-500">REVIEWER ID</label>
          <input value={reviewer} onChange={(e) => setReviewer(e.target.value)}
            className="bg-void border border-edge rounded px-2 py-1 w-36 focus:border-neon-cyan outline-none" />
          <button onClick={() => setDiffMode(!diffMode)} className="badge border border-edge text-slate-400 hover:text-neon-cyan">
            {diffMode ? 'DIFF VIEW' : 'RAW VIEW'}
          </button>
        </div>
      </div>

      {error && <div className="panel border-neon-red text-neon-red px-3 py-2 text-xs">{error}</div>}
      {queue.length === 0 && <div className="panel p-6 text-center text-slate-500 text-sm">QUEUE CLEAR — no pending human approvals.</div>}

      {queue.map((p) => {
        const open = expanded === p.proposal_id
        const ruleText = ruleToText(p.firewall_rule)
        return (
          <div key={p.proposal_id} className={`panel p-4 ${int(p.tier) === 3 ? 'border-neon-red/60 shadow-glow-red' : ''}`}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={TIER_COLOR[p.tier]}>TIER {p.tier}</span>
                  <span className="badge bg-edge text-slate-300">{p.attack_class}</span>
                  <span className="badge bg-edge text-slate-400">{p.status}</span>
                  <span className="text-[10px] text-slate-500">{p.proposal_id} · inc {p.incident_id}</span>
                </div>
                <div className="mt-2 text-sm font-bold text-slate-100">{p.proposed_action}</div>
                <div className="text-[11px] text-slate-400 mt-1">Target: {p.target_entity}</div>
                <div className="text-[11px] text-neon-green mt-1">+ {p.expected_security_benefit}</div>
                <div className="text-[11px] text-neon-amber mt-1">⚠ {p.business_impact_analysis}</div>
              </div>
              <button onClick={() => setExpanded(open ? null : p.proposal_id)}
                className="badge border border-neon-cyan text-neon-cyan shrink-0">{open ? 'HIDE ▴' : 'REVIEW ▾'}</button>
            </div>

            {open && (
              <div className="mt-4 grid grid-cols-2 gap-4">
                {/* Blast Radius Visualizer */}
                <div>
                  <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Blast Radius Visualizer</div>
                  <ul className="space-y-1">
                    {p.blast_radius.map((b, i) => (
                      <li key={i} className="flex justify-between border border-edge rounded px-2 py-1 text-[11px]">
                        <span>{b.entity} <span className="text-slate-600">[{b.entity_type}]</span></span>
                        <span className={`font-bold ${IMPACT_COLOR[b.impact] || 'text-slate-400'}`}>{b.impact}</span>
                      </li>
                    ))}
                  </ul>
                  <div className="text-[10px] uppercase tracking-widest text-slate-500 mt-3 mb-1">Downstream Dependencies</div>
                  <div className="text-[11px] text-slate-300">{p.downstream_dependencies.join(' · ')}</div>
                  <div className="text-[10px] uppercase tracking-widest text-slate-500 mt-3 mb-1">Rollback Safety Check</div>
                  <ol className="text-[11px] text-slate-400 list-decimal list-inside">
                    {p.rollback_steps.map((s, i) => <li key={i}>{s}</li>)}
                  </ol>
                  <div className="text-[10px] text-slate-500 mt-2">Required approvers: {p.required_approvers.join(', ')}</div>
                </div>

                {/* Rule Diff Viewer (Monaco) */}
                <div>
                  <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Firewall/WAF Rule Diff Viewer</div>
                  <div className="h-64 border border-edge rounded overflow-hidden">
                    {diffMode ? (
                      <DiffEditor
                        original={BASELINE_TEXT} modified={ruleText} language="shell"
                        theme="vs-dark" options={{ readOnly: true, minimap: { enabled: false }, fontSize: 11, renderSideBySide: false }}
                      />
                    ) : (
                      <Editor value={ruleText} language="shell" theme="vs-dark"
                        options={{ readOnly: true, minimap: { enabled: false }, fontSize: 11 }} />
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Action controls + One-Click Mitigation Bar */}
            <div className="mt-4 flex flex-wrap gap-2">
              <button disabled={!!busy} onClick={() => review(p.proposal_id, 'APPROVED')}
                className="badge bg-neon-green/20 text-neon-green border border-neon-green hover:bg-neon-green/30 disabled:opacity-40">
                {busy === `${p.proposal_id}:APPROVED` ? 'EXECUTING…' : '✓ APPROVE & EXECUTE'}
              </button>
              <button disabled={!!busy} onClick={() => review(p.proposal_id, 'REJECTED')}
                className="badge bg-neon-red/20 text-neon-red border border-neon-red hover:bg-neon-red/30 disabled:opacity-40">
                {busy === `${p.proposal_id}:REJECTED` ? 'ESCALATING…' : '✕ REJECT & ESCALATE'}
              </button>
              <span className="mx-2 text-edge">│</span>
              {PRESETS.map(([key, label, cls]) => (
                <button key={key} disabled={!!busy} title={`One-click preset → ${p.incident_id}`}
                  onClick={() => oneClick(key, p.incident_id)}
                  className={`badge border ${cls} hover:brightness-150 disabled:opacity-40`}>
                  {busy === `${p.incident_id}:${key}` ? 'FIRING…' : label}
                </button>
              ))}
            </div>
            <textarea placeholder="Human feedback notes (logged as RLHF/DPO signal for agent fine-tuning)…"
              value={notes} onChange={(e) => setNotes(e.target.value)} rows={2}
              className="mt-3 w-full bg-void border border-edge rounded px-2 py-1 text-[11px] focus:border-neon-cyan outline-none" />
          </div>
        )
      })}
    </div>
  )
}

const int = (t) => (typeof t === 'number' ? t : parseInt(String(t), 10))
