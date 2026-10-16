import React, { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api.js'
import SevBadge, { SEV_COLOR } from './SevBadge.jsx'

const KIND_LABEL = {
  vuln: 'Vulnerability', port: 'Port', http: 'HTTP',
  subdomain: 'Subdomain', url: 'URL',
  secret: 'Secret', param: 'Param', endpoint: 'Endpoint',
}

function StatusBadge({ status, onChange }) {
  const map = { open: '#f85149', fp: 'var(--text-2)', resolved: '#3fb950' }
  const color = map[status] || 'var(--text-2)'
  return (
    <select
      value={status}
      onChange={e => { e.stopPropagation(); onChange(e.target.value) }}
      onClick={e => e.stopPropagation()}
      style={{ background: 'transparent', border: `1px solid ${color}55`, borderRadius: 3,
               color, fontSize: 10, fontFamily: 'monospace', padding: '2px 4px', cursor: 'pointer' }}
    >
      <option value="open">OPEN</option>
      <option value="fp">FALSE+</option>
      <option value="resolved">RESOLVED</option>
    </select>
  )
}

export default function FindingsPanel({ runId }) {
  const [data, setData] = useState(null)
  const [filter, setFilter] = useState({ kind: '', severity: '', status: 'open' })
  const [expanded, setExpanded] = useState(null)
  const [loading, setLoading] = useState(false)
  const [reparsing, setReparsing] = useState(false)
  const pollRef = useRef(null)

  // Clear the reparse poll on unmount — otherwise it keeps firing load()
  // (setState on an unmounted component) after the user navigates away.
  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current) }, [])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = { ...filter }
      Object.keys(params).forEach(k => !params[k] && delete params[k])
      const res = await api.getRunFindings(runId, { limit: 500, ...params })
      setData(res)
    } catch (_) {
      setData({ total: 0, items: [] })
    } finally {
      setLoading(false)
    }
  }, [runId, filter])

  useEffect(() => { load() }, [load])

  const changeStatus = async (id, status) => {
    await api.patchFinding(id, { status })
    setData(prev => prev ? { ...prev, items: prev.items.map(f => f.id === id ? { ...f, status } : f) } : prev)
  }

  const reparse = async () => {
    setReparsing(true)
    try {
      await api.reparseFinding(runId)
      // Poll until findings count changes or 10 attempts
      let attempts = 0
      if (pollRef.current) clearInterval(pollRef.current)
      pollRef.current = setInterval(async () => {
        attempts++
        await load()
        if (attempts >= 10) { clearInterval(pollRef.current); pollRef.current = null; setReparsing(false) }
      }, 1500)
    } catch (_) { setReparsing(false) }
  }

  const items = data?.items || []
  const byKind = items.reduce((acc, f) => { acc[f.kind] = (acc[f.kind] || 0) + 1; return acc }, {})
  const bySev  = items.reduce((acc, f) => { if (f.kind === 'vuln') { acc[f.severity] = (acc[f.severity] || 0) + 1 } return acc }, {})

  const hasActiveFilter = filter.kind || filter.severity || filter.status

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-[var(--border)] flex-shrink-0 flex-wrap">
        <select className="input py-1 text-xs w-36" value={filter.kind} onChange={e => setFilter(f => ({ ...f, kind: e.target.value }))}>
          <option value="">All types</option>
          {Object.entries(KIND_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select className="input py-1 text-xs w-36" value={filter.severity} onChange={e => setFilter(f => ({ ...f, severity: e.target.value }))}>
          <option value="">All severities</option>
          {['critical','high','medium','low','info'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="input py-1 text-xs w-36" value={filter.status} onChange={e => setFilter(f => ({ ...f, status: e.target.value }))}>
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="fp">False positive</option>
          <option value="resolved">Resolved</option>
        </select>
        {hasActiveFilter && (
          <button className="btn btn-ghost text-[10px]" onClick={() => setFilter({ kind: '', severity: '', status: '' })}>
            ✕ Clear
          </button>
        )}
        <span className="text-xs text-[var(--text-2)] ml-auto">{data?.total ?? '—'} findings</span>
        <button onClick={reparse} disabled={reparsing} className="btn btn-ghost text-xs disabled:opacity-40">
          {reparsing ? '⌛ Reparsing…' : '↺ Reparse'}
        </button>
      </div>

      {/* Summary chips */}
      {items.length > 0 && (
        <div className="flex gap-2 px-4 py-2 border-b border-[var(--border)] flex-shrink-0 flex-wrap items-center">
          <span className="text-[10px] text-[var(--text-3)] mr-1">Types:</span>
          {Object.entries(byKind).map(([k, n]) => (
            <button key={k}
              onClick={() => setFilter(f => ({ ...f, kind: f.kind === k ? '' : k }))}
              className={`text-[10px] font-mono border rounded px-2 py-0.5 transition-colors
                ${filter.kind === k ? 'border-[var(--accent)] text-[var(--accent)]' : 'border-[var(--border)] text-[var(--text-2)] hover:border-[#58a6ff44]'}`}>
              {KIND_LABEL[k] || k} <strong>{n}</strong>
            </button>
          ))}
          {Object.keys(bySev).length > 0 && (
            <>
              <span className="text-[10px] text-[var(--text-3)] ml-2 mr-1">Vulns:</span>
              {['critical','high','medium','low','info'].filter(s => bySev[s]).map(s => {
                const c = SEV_COLOR[s]
                return (
                  <button key={s}
                    onClick={() => setFilter(f => ({ ...f, severity: f.severity === s ? '' : s }))}
                    style={{ color: c, borderColor: filter.severity === s ? c : c + '44', background: c + '11' }}
                    className="text-[10px] font-mono border rounded px-2 py-0.5 transition-colors">
                    {s.toUpperCase()} {bySev[s]}
                  </button>
                )
              })}
            </>
          )}
        </div>
      )}

      {/* Table */}
      <div className="flex-1 overflow-y-auto">
        {loading && <div className="p-8 text-center text-xs text-[var(--text-2)] animate-pulse">Loading findings…</div>}
        {!loading && items.length === 0 && (
          <div className="p-8 text-center text-xs text-[var(--text-2)]">
            {data?.total === 0
              ? 'No findings yet. Nuclei/httpx/naabu/SecretFinder results appear here.'
              : 'No findings match the current filter.'}
          </div>
        )}
        {!loading && items.map(f => (
          <div key={f.id} className="border-b border-[var(--surface-2)] hover:bg-[var(--surface-2)] cursor-pointer transition-colors"
            onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
            <div className="flex items-center gap-3 px-4 py-2.5 flex-wrap">
              {f.kind === 'vuln' && <SevBadge sev={f.severity} />}
              <span className="text-[10px] font-mono text-[var(--text-3)] border border-[var(--surface-2)] rounded px-1.5 py-0.5 whitespace-nowrap">
                {KIND_LABEL[f.kind] || f.kind}
              </span>
              <span className="text-xs text-[var(--text)] font-medium flex-1 min-w-0 truncate">{f.name || f.host}</span>
              <span className="text-[11px] font-mono text-[var(--text-2)] truncate max-w-[200px] hidden md:block">{f.host}</span>
              <StatusBadge status={f.status} onChange={v => changeStatus(f.id, v)} />
              <span className="text-[var(--text-3)] text-xs">{expanded === f.id ? '▲' : '▼'}</span>
            </div>

            {expanded === f.id && (
              <div className="px-4 pb-4 pt-2 text-xs space-y-1.5 border-t border-[var(--surface-2)] bg-[var(--bg-soft)]">
                {f.template_id && (
                  <div><span className="text-[var(--text-2)]">Template </span>
                    <span className="font-mono text-[var(--accent)]">{f.template_id}</span>
                  </div>
                )}
                {f.url && (
                  <div><span className="text-[var(--text-2)]">URL </span>
                    <a href={f.url} target="_blank" rel="noreferrer"
                      onClick={e => e.stopPropagation()}
                      className="font-mono text-[var(--accent)] hover:underline break-all">{f.url}</a>
                  </div>
                )}
                {f.ip && <div><span className="text-[var(--text-2)]">IP </span><span className="font-mono">{f.ip}</span></div>}
                {f.port && <div><span className="text-[var(--text-2)]">Port </span><span className="font-mono">{f.port}/{f.protocol || 'tcp'}</span></div>}
                {f.title && <div><span className="text-[var(--text-2)]">Title </span>{f.title}</div>}
                {Array.isArray(f.tech) && f.tech.length > 0 && (
                  <div className="flex gap-1.5 flex-wrap">
                    <span className="text-[var(--text-2)]">Tech </span>
                    {f.tech.map(t => (
                      <span key={t} className="text-[10px] font-mono bg-[var(--surface)] border border-[var(--border)] rounded px-1.5 py-0.5">{t}</span>
                    ))}
                  </div>
                )}
                {f.description && <p className="text-[var(--text-2)] leading-relaxed mt-1">{f.description}</p>}
                {f.evidence && (
                  <pre className="text-[10px] bg-[var(--surface)] border border-[var(--border)] rounded p-3 overflow-x-auto whitespace-pre-wrap break-all mt-2 max-h-48">
                    {f.evidence}
                  </pre>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
