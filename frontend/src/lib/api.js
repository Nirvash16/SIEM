// API client for FastAPI Cyber Command Core (proxied via Vite at /api/v1)
const BASE = '/api/v1'

async function http(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.detail || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  health: () => http('/health'),
  incidents: () => http('/incidents'),
  incident: (id) => http(`/incidents/${id}`),
  traces: (id) => http(`/incidents/${id}/traces`),
  ingest: (payload) => http('/incidents/network-ingest', { method: 'POST', body: JSON.stringify(payload) }),

  queue: () => http('/approvals/queue'),
  review: (proposalId, action, reviewerId, notes = '') =>
    http(`/approvals/${proposalId}/review`, {
      method: 'POST',
      body: JSON.stringify({ action, reviewer_id: reviewerId, feedback_notes: notes }),
    }),
  rollbackChange: (changeId) => http(`/network/mitigations/${changeId}/rollback`, { method: 'POST' }),

  topology: () => http('/network/topology'),
  visibility: () => http('/network/visibility'),
  triggerFeed: () => http('/network/trigger-feed'),
  policies: () => http('/network/policies'),
  nodeDetail: (nodeId) => http(`/network/nodes/${nodeId}/detail`),
  oneClick: (preset, incidentId) =>
    http(`/network/one-click/${preset}?incident_id=${encodeURIComponent(incidentId)}`, { method: 'POST' }),

  feeds: () => http('/intel/feeds'),
  intelEntries: () => http('/intel/entries'),
  runScrape: () => http('/intel/scrape/run', { method: 'POST' }),
  dpoPreview: () => http('/intel/datasets/dpo-preview'),
  sftPreview: () => http('/intel/datasets/sft-preview'),
  trainingStatus: () => http('/intel/training/status'),
}

// Live telemetry WebSocket (NetFlow/sFlow/eBPF event stream via Redis bus)
export function connectTelemetry(onEvent) {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  const ws = new WebSocket(`${proto}://${window.location.host}/ws/telemetry`)
  ws.onmessage = (msg) => {
    try { onEvent(JSON.parse(msg.data)) } catch { /* ignore malformed frames */ }
  }
  ws.onerror = () => ws.close()
  return ws
}

export const fmtBps = (n) => {
  if (n == null) return '—'
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)} Gbps`
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)} Mbps`
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)} Kbps`
  return `${n} bps`
}

export const fmtNum = (n) => (n == null ? '—' : n >= 1e6 ? `${(n / 1e6).toFixed(2)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}K` : String(n))
