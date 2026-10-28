"use client";
import React, { useEffect, useState } from 'react'
import { api } from '@/lib/k1z-api'

// Attack-surface graph for a run: asks the backend to (re)build recon-graph.html
// from the run workspace (scripts/recon-graph.py), then renders it in an iframe.
export default function GraphView({ runId }) {
  const [state, setState] = useState('build') // build | ready | error
  const [src, setSrc] = useState('')
  const [msg, setMsg] = useState('')

  const build = () => {
    setState('build'); setMsg('')
    api.genGraph(runId)
      .then(() => { setSrc(api.graphUrl(runId)); setState('ready') })
      .catch(e => { setMsg(String(e?.message || e)); setState('error') })
  }
  useEffect(() => { build() }, [runId])

  if (state === 'build')
    return <Center><div className="animate-pulse">Building attack-surface graph…</div>
      <div className="text-[11px] opacity-60">linking subdomains · IPs · ASN · subnets · services · findings</div></Center>
  if (state === 'error')
    return <Center>
      <div>Graph build failed.</div>
      <div className="text-[11px] opacity-70 max-w-md break-words font-mono">{msg}</div>
      <button onClick={build} className="btn mt-2" style={{ fontSize: 12 }}>↻ Retry</button>
    </Center>

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-3 px-3 py-1.5 border-b border-[var(--border)] bg-[var(--surface)] flex-shrink-0">
        <span className="text-[11px] text-[var(--text-2)]">🕸 Attack-surface graph</span>
        <button onClick={build} className="ml-auto text-[11px] text-[var(--text-3)] hover:text-[var(--text)] transition-colors">↻ Rebuild</button>
        <a href={src} target="_blank" rel="noreferrer" className="text-[11px] text-[var(--text-3)] hover:text-[var(--text)] transition-colors">↗ open</a>
      </div>
      <iframe src={src} title="recon graph" className="flex-1 w-full" style={{ border: 0, background: '#0d1117' }} />
    </div>
  )
}

function Center({ children }) {
  return (
    <div className="h-full flex flex-col items-center justify-center gap-2 text-[var(--text-3)] text-[12px] text-center p-6">
      {children}
    </div>
  )
}
