"use client";
import React, { useEffect, useMemo, useState } from 'react'
import { api } from '@/lib/k1z-api'

// The attack-surface graph is per-target (it merges every run of that target),
// served as a standalone page by the API. This view just lets you pick a target
// and renders it inline — no need to open a specific run first.
const viewUrl = (name) => `/api/v1/targets/${encodeURIComponent(name)}/graph2/view`

export default function GraphClient() {
  const [targets, setTargets] = useState([])
  const [sel, setSel] = useState('')
  const [q, setQ] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getTargets()
      .then(d => {
        const list = Array.isArray(d) ? d : (d?.items || [])
        setTargets(list)
        let initial = ''
        try {
          const u = new URLSearchParams(window.location.search)
          initial = u.get('target') || localStorage.getItem('k1z_graph_target') || ''
        } catch { /* ignore */ }
        const names = list.map(t => t.name || t.target).filter(Boolean)
        if (!initial && names.length) initial = names[0]
        if (initial && names.includes(initial)) setSel(initial)
      })
      .catch(e => setErr(e?.message || 'Failed to load targets'))
      .finally(() => setLoading(false))
  }, [])

  const names = useMemo(
    () => targets.map(t => t.name || t.target).filter(Boolean),
    [targets],
  )
  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase()
    return s ? names.filter(n => n.toLowerCase().includes(s)) : names
  }, [names, q])

  const choose = (n) => {
    setSel(n)
    try { if (n) localStorage.setItem('k1z_graph_target', n) } catch { /* ignore */ }
  }

  // Definite viewport height (NOT h-full): the app shell is min-h-svh with no
  // definite-height root, so h-full collapses and the iframe/page over-scroll
  // into a black void. Sizing to the viewport minus the app header (3rem) and
  // the content padding (p-4 → 2rem / md:p-6 → 3rem) bounds it so the iframe
  // fills the pane. Mirrors the run-detail and function/commands pages.
  return (
    <div className="flex flex-col h-[calc(100vh-5rem)] md:h-[calc(100vh-6rem)] min-h-0">
      <div className="flex items-center gap-3 px-6 py-3 border-b border-[var(--border)] flex-shrink-0 flex-wrap">
        <div>
          <h1 className="text-base font-bold text-[var(--text)] font-mono">Attack-surface Graph</h1>
          <p className="text-[11px] text-[var(--text-2)]">Pick a target to view its aggregated recon graph (all runs merged)</p>
        </div>
        <div className="flex items-center gap-2 ml-auto flex-wrap">
          <input
            className="input py-1 w-48"
            placeholder="Filter targets…"
            value={q}
            onChange={e => setQ(e.target.value)}
          />
          <select
            className="input py-1 w-64 font-mono"
            value={sel}
            onChange={e => choose(e.target.value)}
          >
            <option value="">— select target —</option>
            {filtered.map(n => <option key={n} value={n}>{n}</option>)}
          </select>
          {sel && (
            <a href={viewUrl(sel)} target="_blank" rel="noreferrer" className="btn btn-ghost text-xs whitespace-nowrap">
              ↗ New tab
            </a>
          )}
        </div>
      </div>

      <div className="flex-1 min-h-0 bg-[var(--bg-soft)]">
        {loading ? (
          <p className="text-[var(--text-2)] p-6 text-sm">Loading targets…</p>
        ) : err ? (
          <p className="text-[var(--red)] p-6 text-sm">{err}</p>
        ) : names.length === 0 ? (
          <p className="text-[var(--text-2)] p-6 text-sm">No targets yet — register a target and run recon first.</p>
        ) : !sel ? (
          <p className="text-[var(--text-2)] p-6 text-sm">Select a target above to render its graph.</p>
        ) : (
          <iframe
            key={sel}
            src={viewUrl(sel)}
            title={`Graph — ${sel}`}
            className="w-full h-full border-0"
          />
        )}
      </div>
    </div>
  )
}
