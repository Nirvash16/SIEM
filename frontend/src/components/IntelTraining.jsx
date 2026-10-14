import React, { useEffect, useState } from 'react'
import Editor from '@monaco-editor/react'
import { api } from '../lib/api.js'

export default function IntelTraining() {
  const [feedsMap, setFeedsMap] = useState({})
  const [entries, setEntries] = useState([])
  const [training, setTraining] = useState(null)
  const [dpo, setDpo] = useState([])
  const [tab, setTab] = useState('dpo')
  const [scraping, setScraping] = useState(false)
  const [log, setLog] = useState('// Monaco viewer — SFT / DPO training corpus previews\n// Chosen = mitigations that preserved legitimate traffic\n// Rejected = rules causing false-positive outages or hallucinated syntax')
  const [sft, setSft] = useState(null)

  const load = () => {
    api.feeds().then(setFeedsMap).catch(() => {})
    api.intelEntries().then(setEntries).catch(() => {})
    api.trainingStatus().then(setTraining).catch(() => {})
    api.dpoPreview().then(setDpo).catch(() => {})
    api.sftPreview().then(setSft).catch(() => {})
  }
  useEffect(load, [])

  const scrape = async () => {
    setScraping(true)
    try { const r = await api.runScrape(); setLog(JSON.stringify(r, null, 2)); load() }
    catch (e) { setLog(`Scrape error: ${e.message}`) } finally { setScraping(false) }
  }

  const editorValue =
    tab === 'dpo' ? JSON.stringify(dpo, null, 2)
      : tab === 'sft' ? JSON.stringify(sft, null, 2)
        : log

  return (
    <div className="grid grid-cols-3 gap-3 h-full overflow-hidden">
      {/* Threat feeds */}
      <div className="panel flex flex-col min-h-0">
        <div className="px-3 py-2 border-b border-edge flex items-center justify-between">
          <span className="text-[10px] uppercase tracking-widest text-neon-cyan">Intelligence Scrapers</span>
          <button onClick={scrape} disabled={scraping}
            className="badge border border-neon-green text-neon-green hover:bg-neon-green/20 disabled:opacity-40">
            {scraping ? 'SCRAPING…' : '▶ RUN PIPELINE'}
          </button>
        </div>
        <div className="overflow-y-auto flex-1 p-3 space-y-2 text-[11px]">
          {Object.entries(feedsMap).map(([name, url]) => (
            <div key={name} className="border border-edge rounded p-2">
              <div className="flex justify-between">
                <span className="text-slate-200 font-bold">{name.replace(/_/g, ' ')}</span>
                <span className="badge bg-neon-green/15 text-neon-green">ENABLED</span>
              </div>
              <div className="text-slate-500 truncate" title={url}>{url}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Training status + corpus */}
      <div className="panel flex flex-col min-h-0">
        <div className="px-3 py-2 border-b border-edge text-[10px] uppercase tracking-widest text-neon-cyan">
          LoRA/QLoRA Fine-Tuning Pipeline
        </div>
        <div className="p-3 text-[11px] space-y-2">
          {training && (
            <>
              <div className="flex justify-between"><span className="text-slate-500">Verified human reviews</span>
                <span className="text-neon-amber font-bold">{training.verified_review_count} / {training.trigger_threshold}</span></div>
              <div className="h-2 bg-void rounded border border-edge overflow-hidden">
                <div className="h-full bg-neon-amber" style={{ width: `${Math.min(100, (training.verified_review_count / (training.trigger_threshold || 1000)) * 100)}%` }} />
              </div>
              <div className="text-slate-500">next LoRA run in <span className="text-neon-violet">{training.next_lora_run_in_reviews}</span> reviews · jobs: {(training.jobs || []).length}</div>
              <div className="text-slate-600">{training.method}. Reward shaping: chosen = attack mitigated AND legitimate goodput preserved.</div>
            </>
          )}
          <div className="text-[10px] uppercase tracking-widest text-slate-500 mt-3">Corpus Entries ({entries.length})</div>
          <div className="max-h-48 overflow-y-auto space-y-1">
            {entries.slice(0, 20).map((e, i) => (
              <div key={i} className="border border-edge/50 rounded px-2 py-1 truncate">
                <span className="text-neon-violet">[{e.feed}]</span>
                <span className="text-neon-amber ml-1">{e.entry_type}</span>{' '}
                <span className="text-slate-400">{e.identifier} — {e.summary}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Dataset preview (Monaco) */}
      <div className="panel flex flex-col min-h-0">
        <div className="px-3 py-2 border-b border-edge flex gap-2">
          {['dpo', 'sft', 'scrape-log'].map((t) => (
            <button key={t} onClick={() => setTab(t)}
              className={`badge ${tab === t ? 'bg-neon-cyan/20 text-neon-cyan border border-neon-cyan' : 'border border-edge text-slate-500'}`}>
              {t.toUpperCase()}
            </button>
          ))}
        </div>
        <div className="flex-1 min-h-0">
          <Editor
            language={tab === 'scrape-log' ? 'json' : 'json'} theme="vs-dark"
            value={editorValue}
            options={{ readOnly: true, minimap: { enabled: false }, fontSize: 10, wordWrap: 'on' }}
          />
        </div>
      </div>
    </div>
  )
}
