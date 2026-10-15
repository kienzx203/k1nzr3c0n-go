import React, { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { formatDuration, timeAgo, durSecs } from '../utils.js'
import NewRunModal from '../components/NewRunModal.jsx'

const STATUSES = ['', 'queued', 'running', 'paused', 'completed', 'failed', 'cancelled']

export default function Runs() {
  const [data, setData]         = useState({ total: 0, items: [] })
  const [status, setStatus]     = useState('')
  const [search, setSearch]     = useState('')
  const [showModal, setShowModal] = useState(false)
  const [page, setPage]         = useState(0)
  const [selected, setSelected] = useState(new Set())
  const [deleting, setDeleting] = useState(false)
  const PAGE = 30

  const load = useCallback(() => {
    api.getRuns({ status: status || undefined, limit: PAGE, offset: page * PAGE })
      .then(setData).catch(() => {})
  }, [status, page])

  useEffect(() => { load(); const t = setInterval(load, 4000); return () => clearInterval(t) }, [load])

  // Clear selection when filter/page changes
  useEffect(() => { setSelected(new Set()) }, [status, search, page])

  const filtered = search
    ? data.items.filter(r => r.target.includes(search) || r.workflow.includes(search))
    : data.items

  const allChecked  = filtered.length > 0 && filtered.every(r => selected.has(r.id))
  const someChecked = selected.size > 0 && !allChecked

  function toggleAll() {
    if (allChecked) setSelected(new Set())
    else setSelected(new Set(filtered.map(r => r.id)))
  }

  function toggleOne(id) {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  async function deleteSelected() {
    if (!window.confirm(`Delete ${selected.size} run(s)? This cannot be undone.`)) return
    setDeleting(true)
    await Promise.all([...selected].map(id => api.deleteRun(id).catch(() => {})))
    setSelected(new Set())
    setDeleting(false)
    load()
  }

  async function cancelSelected() {
    const runningIds = filtered.filter(r => r.status === 'running' && selected.has(r.id)).map(r => r.id)
    if (!runningIds.length) return
    if (!window.confirm(`Cancel ${runningIds.length} running scan(s)?`)) return
    await Promise.all(runningIds.map(id => api.cancelRun(id).catch(() => {})))
    load()
  }

  const selectedRunning = filtered.filter(r => r.status === 'running' && selected.has(r.id)).length

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            Runs <span className="font-normal text-sm" style={{ color: 'var(--text-3)' }}>({data.total})</span>
          </h1>
          <p className="page-sub">Scan executions across all workflows</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M8 3v10M3 8h10" /></svg>
          New Run
        </button>
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap items-center">
        <input
          className="input w-56"
          placeholder="Search target / workflow…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <div className="flex gap-0.5 p-0.5 rounded-md" style={{ background: 'var(--surface)' , border: '1px solid var(--border)' }}>
          {STATUSES.map(s => (
            <button
              key={s || 'all'}
              onClick={() => { setStatus(s); setPage(0) }}
              className="px-2.5 py-1 rounded text-[11px] font-medium transition-colors capitalize"
              style={status === s
                ? { background: 'rgba(88,166,255,.15)', color: 'var(--accent)' }
                : { color: 'var(--text-2)' }}
            >
              {s || 'All'}
            </button>
          ))}
        </div>
      </div>

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <div className="flex items-center gap-2.5 px-4 py-2 rounded-lg fade-in"
             style={{ background: 'rgba(88,166,255,.08)', border: '1px solid rgba(88,166,255,.35)' }}>
          <span className="text-xs font-bold" style={{ color: 'var(--accent)' }}>
            {selected.size} selected
          </span>
          <div className="flex-1" />
          {selectedRunning > 0 && (
            <button className="btn btn-danger" onClick={cancelSelected}>
              ■ Cancel {selectedRunning} running
            </button>
          )}
          <button className="btn btn-danger" onClick={deleteSelected} disabled={deleting}>
            {deleting ? 'Deleting…' : `Delete ${selected.size}`}
          </button>
          <button className="btn btn-ghost" onClick={() => setSelected(new Set())}>
            Clear
          </button>
        </div>
      )}

      {/* Table */}
      <div className="card overflow-hidden">
        <table className="table-base">
          <thead>
            <tr>
              <th className="w-10">
                <input
                  type="checkbox"
                  checked={allChecked}
                  ref={el => { if (el) el.indeterminate = someChecked }}
                  onChange={toggleAll}
                  className="accent-[var(--accent)] cursor-pointer align-middle"
                />
              </th>
              {['Target', 'Workflow', 'Status', 'Started', 'Duration', ''].map((h, i) => (
                <th key={i}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-10 text-center" style={{ color: 'var(--text-2)' }}>No runs found.</td></tr>
            )}
            {filtered.map(r => {
              const isSelected = selected.has(r.id)
              return (
                <tr key={r.id} className="group" style={isSelected ? { background: 'rgba(88,166,255,.07)' } : undefined}>
                  <td className="px-4 py-2.5">
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => toggleOne(r.id)}
                      className="accent-[var(--accent)] cursor-pointer"
                    />
                  </td>
                  <td className="px-4 py-2.5 max-w-[220px] truncate">
                    <Link to={`/runs/${r.id}`} className="font-mono hover:underline" style={{ color: 'var(--accent)' }}>
                      {r.target}
                    </Link>
                  </td>
                  <td className="px-4 py-2.5 max-w-[160px] truncate" style={{ color: 'var(--text-2)' }}>{r.workflow}</td>
                  <td className="px-4 py-2.5">
                    <span className={`badge badge-${r.status}`}>{r.status}</span>
                  </td>
                  <td className="px-4 py-2.5" style={{ color: 'var(--text-2)' }} title={r.started_at || r.created_at}>
                    {timeAgo(r.started_at || r.created_at)}
                  </td>
                  <td className="px-4 py-2.5 font-mono" style={{ color: 'var(--text-2)' }}>
                    {r.status === 'running'
                      ? <span className="animate-pulse" style={{ color: 'var(--green)' }}>running…</span>
                      : formatDuration(durSecs(r))}
                  </td>
                  <td className="px-4 py-2.5 text-right whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity">
                    {r.status === 'running' && (
                      <button
                        className="btn btn-warning mr-1.5"
                        onClick={() => window.confirm(`Pause scan for ${r.target}?`) && api.pauseRun(r.id).then(load)}
                      >Pause</button>
                    )}
                    {r.status === 'running' && (
                      <button
                        className="btn btn-danger mr-1.5"
                        onClick={() => window.confirm(`Cancel scan for ${r.target}?`) && api.cancelRun(r.id).then(load)}
                      >Cancel</button>
                    )}
                    {(r.status === 'paused' || r.status === 'failed') && (
                      <button className="btn btn-success mr-1.5" onClick={() => api.resumeRun(r.id).then(load)}>
                        Resume
                      </button>
                    )}
                    <button
                      className="btn btn-ghost"
                      onClick={() => window.confirm(`Delete run for ${r.target}?`) && api.deleteRun(r.id).then(load)}
                    >Delete</button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {data.total > PAGE && (
        <div className="flex gap-2 justify-center items-center">
          <button className="btn btn-ghost" disabled={page === 0} onClick={() => setPage(p => p - 1)}>← Prev</button>
          <span className="text-xs font-mono" style={{ color: 'var(--text-2)' }}>
            {page + 1} / {Math.ceil(data.total / PAGE)}
          </span>
          <button className="btn btn-ghost" disabled={(page + 1) * PAGE >= data.total} onClick={() => setPage(p => p + 1)}>Next →</button>
        </div>
      )}

      {showModal && <NewRunModal onClose={() => setShowModal(false)} onCreated={() => { setShowModal(false); load() }} />}
    </div>
  )
}
