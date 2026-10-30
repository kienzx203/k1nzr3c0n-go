"use client";
import React, { useEffect, useMemo, useState } from 'react'
import { api } from '@/lib/k1z-api'

// The attack-surface graph is per-target (it merges every run of that target) and
// is served as a standalone page by the API. This view is a target PICKER: click a
// target and its graph opens in a new tab — the graph UI is not embedded here.
const viewUrl = (name) => `/api/v1/targets/${encodeURIComponent(name)}/graph2/view`

const MODE_COLOR = {
  bounty: 'var(--green)',
  pentest: 'var(--accent)',
  redteam: 'var(--red)',
  oos: 'var(--text-3)',
}

function timeAgo(ts) {
  if (!ts) return null
  const s = (Date.now() - new Date(ts).getTime()) / 1000
  if (s < 0) return 'just now'
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

export default function GraphClient() {
  const [targets, setTargets] = useState([])
  const [q, setQ] = useState('')
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')

  useEffect(() => {
    api.getTargets()
      .then(d => setTargets(Array.isArray(d) ? d : (d?.items || [])))
      .catch(e => setErr(e?.message || 'Failed to load targets'))
      .finally(() => setLoading(false))
  }, [])

  const filtered = useMemo(() => {
    const list = targets.filter(t => t && t.name)
    const s = q.trim().toLowerCase()
    return s ? list.filter(t => t.name.toLowerCase().includes(s)) : list
  }, [targets, q])

  const open = (name) => {
    try { window.open(viewUrl(name), '_blank', 'noopener') } catch { /* ignore */ }
  }

  return (
    <div className="p-6 space-y-5">
      <div className="page-header">
        <div>
          <h1 className="page-title">Attack-surface Graph</h1>
          <p className="page-sub">
            Pick a target to open its full relationship graph — hosts · IPs · ASNs · ports · URLs · findings,
            merged across every run. The graph opens in a new tab.
          </p>
        </div>
      </div>

      <input
        className="input w-full max-w-md"
        placeholder="Filter targets…"
        value={q}
        onChange={e => setQ(e.target.value)}
      />

      {loading ? (
        <p className="text-sm" style={{ color: 'var(--text-2)' }}>Loading targets…</p>
      ) : err ? (
        <p className="text-sm" style={{ color: 'var(--red)' }}>{err}</p>
      ) : filtered.length === 0 ? (
        <p className="text-sm" style={{ color: 'var(--text-2)' }}>
          {targets.length === 0
            ? 'No targets yet — register a target and run recon first.'
            : 'No targets match your filter.'}
        </p>
      ) : (
        <div
          className="grid gap-3"
          style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))' }}
        >
          {filtered.map(t => (
            <button
              key={t.name}
              onClick={() => open(t.name)}
              className="card card-hover p-4 text-left"
              title={`Open the attack-surface graph for ${t.name}`}
            >
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="font-mono font-bold text-sm truncate" style={{ color: 'var(--text)' }}>
                  {t.name}
                </span>
                <span
                  className="text-[10px] font-mono px-1.5 py-0.5 rounded flex-shrink-0"
                  style={{
                    border: `1px solid ${MODE_COLOR[t.mode] || 'var(--border)'}`,
                    color: MODE_COLOR[t.mode] || 'var(--text-3)',
                  }}
                >
                  {t.mode || '—'}
                </span>
              </div>
              <div className="flex items-center justify-between text-[11px]" style={{ color: 'var(--text-2)' }}>
                <span>{(t.total_runs ?? 0)} run{t.total_runs === 1 ? '' : 's'}</span>
                <span className="truncate ml-2">
                  {t.last_run_at ? `${timeAgo(t.last_run_at)}${t.last_status ? ' · ' + t.last_status : ''}` : 'never scanned'}
                </span>
              </div>
              <div className="mt-3 text-[11px] font-mono" style={{ color: 'var(--accent)' }}>
                ↗ Open graph
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
