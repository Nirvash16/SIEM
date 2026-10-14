import React, { useCallback, useEffect, useMemo, useState } from 'react'
import ReactFlow, { Background, Controls, MiniMap, MarkerType, Handle, Position } from 'reactflow'
import 'reactflow/dist/style.css'
import { api, fmtBps } from '../lib/api.js'

const TYPE_STYLE = {
  ALERT: { border: '#f87171', icon: '⚠', glow: 'shadow-glow-red' },
  FIREWALL: { border: '#22d3ee', icon: '▣', glow: 'shadow-glow' },
  IDS_SENSOR: { border: '#a78bfa', icon: '◉', glow: '' },
  SCRUBBING_CENTER: { border: '#34d399', icon: '☁', glow: '' },
  HOST: { border: '#fbbf24', icon: '▤', glow: '' },
  MCP_SERVER: { border: '#38bdf8', icon: '⛓', glow: '' },
  IDENTITY: { border: '#94a3b8', icon: '☗', glow: '' },
}

function H({ position }) {
  return <Handle type="source" position={position} className="!w-1.5 !h-1.5 !bg-edge !border !border-neon-cyan/40" />
}

const nodeTypes = {
  cyber: (props) => {
    const s = TYPE_STYLE[props.data.node_type] || TYPE_STYLE.HOST
    const adversarial = props.data.status === 'adversarial'
    return (
      <div
        className={`relative px-3 py-2 rounded-md bg-panel border text-[11px] w-44 ${s.glow} ${adversarial ? 'animate-pulsered' : ''}`}
        style={{ borderColor: s.border }}
      >
        <H position={Position.Top} /><H position={Position.Bottom} />
        <H position={Position.Left} /><H position={Position.Right} />
        <div className="flex items-center gap-2 font-bold" style={{ color: s.border }}>
          <span>{s.icon}</span>
          <span className="uppercase tracking-wider text-[9px]">{props.data.node_type.replace(/_/g, ' ')}</span>
        </div>
        <div className="whitespace-pre-line leading-tight mt-1 text-slate-200">{props.data.label}</div>
        {props.data.metrics?.bps != null && (
          <div className="mt-1 text-[10px] text-neon-red">
            {fmtBps(props.data.metrics.bps)} · {((props.data.metrics.pps || 0) / 1e6).toFixed(2)}M pps
          </div>
        )}
      </div>
    )
  },
}

export default function TopologyView({ onSelectNode }) {
  const [graph, setGraph] = useState({ nodes: [], edges: [] })

  const load = useCallback(() => { api.topology().then(setGraph).catch(() => {}) }, [])
  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t) }, [load])

  const rfNodes = useMemo(() => graph.nodes.map((n) => ({
    id: n.id, type: 'cyber', position: { x: n.x * 12, y: n.y * 4 }, data: n,
  })), [graph])

  const rfEdges = useMemo(() => graph.edges.map((e) => {
    const inferred = e.edge_type === 'INFERRED_BY_AI'
    return {
      id: e.id, source: e.source, target: e.target, label: e.label,
      animated: inferred, // dashed animated lines = AI-inferred attack paths
      style: inferred
        ? { stroke: '#f87171', strokeWidth: 1.6, strokeDasharray: '6 6' }
        : { stroke: '#22d3ee', strokeWidth: 2.2 }, // solid glowing = DIRECTLY_OBSERVED packet logs
      markerEnd: { type: MarkerType.ArrowClosed, color: inferred ? '#f87171' : '#22d3ee' },
      labelStyle: { fill: '#94a3b8', fontSize: 9, fontFamily: 'JetBrains Mono' },
      labelBgStyle: { fill: '#0a101c' },
    }
  }), [graph])

  return (
    <div className="panel h-full flex flex-col">
      <div className="flex items-center justify-between px-4 py-2 border-b border-edge">
        <h2 className="text-neon-cyan font-bold text-sm tracking-widest uppercase">
          Live Incident & Network Visibility Topology
        </h2>
        <div className="flex gap-4 text-[10px]">
          <span className="flex items-center gap-1">
            <span className="inline-block w-6 h-0.5 bg-neon-cyan shadow-glow" /> DIRECTLY_OBSERVED
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block w-6 h-0.5 border-t border-dashed border-neon-red" /> INFERRED_BY_AI
          </span>
        </div>
      </div>
      <div className="flex-1 min-h-0">
        <ReactFlow
          nodes={rfNodes} edges={rfEdges} nodeTypes={nodeTypes} fitView
          onNodeClick={(_, n) => onSelectNode?.(n.id)}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#16233b" gap={28} />
          <MiniMap nodeColor={(n) => TYPE_STYLE[n.data.node_type]?.border || '#fbbf24'} maskColor="rgba(5,8,15,0.7)" />
          <Controls />
        </ReactFlow>
      </div>
    </div>
  )
}
