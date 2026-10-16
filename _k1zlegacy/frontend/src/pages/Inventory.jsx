import React, { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import AddFiltersMenu from '../components/AddFiltersMenu.jsx'

const scColor = sc =>
  sc >= 200 && sc < 300 ? '#3fb950' :
  sc >= 300 && sc < 400 ? '#d29922' :
  sc >= 400 && sc < 500 ? '#f85149' :
  sc >= 500 ? '#ff6e6e' : 'var(--text-2)'

function StatusChip({ code }) {
  if (code == null) return <span className="text-[13px] text-[var(--text-3)]">—</span>
  const c = scColor(code)
  return (
    <span
      className="text-[12px] font-mono font-bold px-1.5 py-0.5 rounded whitespace-nowrap"
      style={{ color: c, background: `${c}1a`, border: `1px solid ${c}44` }}
    >
      {code}
    </span>
  )
}

function Thumb({ runId, path, alt }) {
  if (!path) {
    return (
      <div className="w-16 h-11 rounded border border-[var(--border)] bg-[var(--bg-soft)] flex items-center justify-center text-[var(--border)] text-[13px] flex-shrink-0">
        ▢
      </div>
    )
  }
  const src = `/api/v1/runs/${runId}/files/${path}`
  return (
    <div className="relative w-16 h-11 flex-shrink-0 group/thumb" style={{ zIndex: 0 }}>
      <a href={src} target="_blank" rel="noreferrer">
        <img
          src={src}
          alt={alt}
          loading="lazy"
          className="w-16 h-11 object-cover object-top rounded border border-[var(--border)] bg-[var(--bg-soft)]
                     transition-transform duration-150 ease-out
                     group-hover/thumb:scale-[3] group-hover/thumb:z-20 group-hover/thumb:shadow-2xl
                     relative"
          style={{ transformOrigin: 'left bottom' }}
          onError={e => { e.target.style.visibility = 'hidden' }}
        />
      </a>
    </div>
  )
}

function AssetRow({ a, deleting, onDelete }) {
  const key = `${a.host}:${a.port || ''}`
  return (
    <tr className="border-b border-[var(--surface-2)] hover:bg-[var(--surface-2)] transition-colors">
      <td className="px-4 py-2">
        <Thumb runId={a.run_id} path={a.screenshot} alt={a.title || a.host} />
      </td>
      <td className="px-4 py-2 font-mono max-w-xs">
        <a href={a.url} target="_blank" rel="noreferrer" className="text-[var(--accent)] hover:underline">
          {a.host}{a.port ? `:${a.port}` : ''}
        </a>
        {a.title && <div className="text-[var(--text-2)] text-[13px] truncate max-w-xs">{a.title}</div>}
      </td>
      <td className="px-4 py-2"><StatusChip code={a.status_code} /></td>
      <td className="px-4 py-2 font-mono text-[var(--text-2)] text-[13px]">{a.ip || '—'}</td>
      <td className="px-4 py-2">
        <div className="flex flex-wrap gap-1 max-w-xs">
          {(a.tech || []).slice(0, 3).map(t => (
            <span key={t} className="text-[12px] px-1.5 py-0.5 rounded border border-[var(--border)] text-[var(--text-2)] bg-[var(--bg-soft)]">{t}</span>
          ))}
          {a.tech?.length > 3 && <span className="text-[12px] text-[var(--text-3)]">+{a.tech.length - 3}</span>}
          {!a.tech?.length && <span className="text-[var(--border)]">—</span>}
        </div>
      </td>
      <td className="px-4 py-2 text-[var(--text-2)] text-[13px] whitespace-nowrap">
        {a.last_seen ? new Date(a.last_seen).toLocaleDateString() : '—'}
        {a.run_id && (
          <Link to={`/runs/${a.run_id}`} className="block text-[var(--text-3)] hover:text-[var(--accent)] text-[12px]">source run ↗</Link>
        )}
      </td>
      <td className="px-4 py-2 text-right">
        <button
          className="text-[var(--text-3)] hover:text-[var(--red)] transition-colors"
          onClick={() => onDelete(a.host, a.port)}
          disabled={deleting === key}
          title="Remove from inventory"
        >
          {deleting === key ? '…' : '🗑'}
        </button>
      </td>
    </tr>
  )
}

const COLS = ['Shot', 'Host', 'Status', 'IP', 'Technology', 'Last Seen', '']
const ROW_LIMIT = 200

function TargetGroup({ target, assets, isCollapsed, onToggle, deleting, onDelete }) {
  const [showAll, setShowAll] = useState(false)
  const visible = showAll ? assets : assets.slice(0, ROW_LIMIT)
  return (
    <div className="card">
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-2 px-4 py-2.5 text-left hover:bg-[var(--surface-2)] transition-colors border-b border-[var(--border)]"
      >
        <span className="text-[var(--text-3)] text-[12px] w-3">{isCollapsed ? '▸' : '▾'}</span>
        <span className="font-mono font-bold text-[var(--text)] text-[14px]">{target}</span>
        <span className="text-[var(--text-2)] text-[13px]">({assets.length})</span>
      </button>
      {!isCollapsed && (
        <>
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[var(--border)]">
                {COLS.map(h => (
                  <th key={h} className="px-4 py-2 text-left text-[var(--text-2)] text-[13px] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.map(a => (
                <AssetRow key={`${a.host}:${a.port || ''}`} a={a} deleting={deleting} onDelete={onDelete} />
              ))}
            </tbody>
          </table>
          {assets.length > ROW_LIMIT && !showAll && (
            <button
              className="w-full text-center text-[13px] text-[var(--accent)] hover:underline py-2 border-t border-[var(--surface-2)]"
              onClick={() => setShowAll(true)}
            >
              Show remaining {assets.length - ROW_LIMIT} rows ↓
            </button>
          )}
        </>
      )}
    </div>
  )
}

export default function Inventory() {
  const [data, setData] = useState({ total: 0, items: [] })
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filters, setFilters] = useState({ tech: [], status: [], port: [] })
  const [stats, setStats] = useState(null)
  const [deleting, setDeleting] = useState(null)
  const [deleteError, setDeleteError] = useState(null)
  const [collapsed, setCollapsed] = useState(() => new Set())

  const load = () => {
    api.getAssets({
      q: search || undefined,
      tech: filters.tech,
      status_code: filters.status,
      port: filters.port,
      limit: 5000,
    }).then(setData).catch(() => {}).finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 8000)
    return () => clearInterval(t)
  }, [search, filters])

  const loadStats = () => { api.getAssetsStats().then(setStats).catch(() => {}) }
  useEffect(() => {
    loadStats()
    const t = setInterval(loadStats, 8000)
    return () => clearInterval(t)
  }, [])

  const filterCategories = useMemo(() => [
    {
      key: 'tech', label: 'Technology', icon: '▭',
      options: Object.entries(stats?.by_tech || {}).map(([v, count]) => ({ value: v, label: v, count })),
    },
    {
      key: 'status', label: 'Status', icon: '◔',
      options: Object.entries(stats?.by_status || {}).map(([v, count]) => ({ value: v, label: v, count })),
    },
    {
      key: 'port', label: 'Port', icon: '⚏',
      options: Object.entries(stats?.by_port || {}).map(([v, count]) => ({ value: v, label: v, count })),
    },
  ], [stats])

  const activeFilterCount = filters.tech.length + filters.status.length + filters.port.length

  const groups = useMemo(() => {
    const m = new Map()
    for (const a of data.items) {
      const t = a.target || a.host
      if (!m.has(t)) m.set(t, [])
      m.get(t).push(a)
    }
    return [...m.entries()].sort((a, b) => b[1].length - a[1].length)
  }, [data.items])

  function toggleGroup(target) {
    setCollapsed(prev => {
      const next = new Set(prev)
      next.has(target) ? next.delete(target) : next.add(target)
      return next
    })
  }

  async function handleDelete(host, port) {
    if (!window.confirm(`Remove ${host}${port ? ':' + port : ''} from inventory? This only removes it from this view, not the underlying run data.`)) return
    setDeleting(`${host}:${port}`)
    setDeleteError(null)
    try {
      await api.deleteAsset(host, port)
      load()
    } catch (e) {
      setDeleteError(`Failed to remove ${host}${port ? ':' + port : ''}: ${e.message || 'unknown error'}`)
    } finally {
      setDeleting(null)
    }
  }

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-lg font-bold text-[var(--text)]">
            Asset Inventory <span className="text-[var(--text-2)] text-sm font-normal">({data.total})</span>
          </h1>
          <p className="text-[13px] text-[var(--text-2)] mt-1">Every live host discovered across all runs, grouped by target and deduped by host:port — most recent sighting wins.</p>
        </div>
        <button className="btn btn-ghost" onClick={load} title="Refresh">↻ Refresh</button>
      </div>

      {/* Toolbar */}
      <div className="flex gap-3 flex-wrap items-center">
        <AddFiltersMenu categories={filterCategories} applied={filters} onApply={setFilters} />
        <input
          className="input w-64"
          placeholder="Search host names…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        {stats && (
          <span className="text-[13px] text-[var(--text-3)] ml-auto">
            {stats.with_screenshot} / {stats.total} with screenshot
          </span>
        )}
      </div>

      {deleteError && (
        <div className="text-[13px] text-[var(--red)] bg-[#f851491a] border border-[#f8514944] rounded px-3 py-2">
          {deleteError}
        </div>
      )}

      {/* Applied filter chips */}
      {activeFilterCount > 0 && (
        <div className="flex flex-wrap gap-1.5 items-center -mt-2">
          {filterCategories.flatMap(c => (filters[c.key] || []).map(v => (
            <span key={`${c.key}:${v}`} className="flex items-center gap-1 text-[12px] pl-2 pr-1 py-0.5 rounded-full border border-[var(--border)] text-[var(--text-2)]">
              <span className="opacity-60">{c.label}:</span> {v}
              <button
                onClick={() => setFilters(prev => ({ ...prev, [c.key]: prev[c.key].filter(x => x !== v) }))}
                className="hover:text-[var(--red)] transition-colors ml-0.5"
              >
                ✕
              </button>
            </span>
          )))}
          <button
            className="text-[12px] text-[var(--text-3)] hover:text-[var(--text-2)]"
            onClick={() => setFilters({ tech: [], status: [], port: [] })}
          >
            Clear all
          </button>
        </div>
      )}

      {loading && <div className="text-center text-[var(--text-3)] py-10">Loading…</div>}
      {!loading && groups.length === 0 && (
        <div className="text-center text-[var(--text-2)] py-10">
          No assets yet — run a workflow with an HTTP probe step (httpx) to populate this view.
        </div>
      )}

      {/* One table per target */}
      {groups.map(([target, assets]) => (
        <TargetGroup
          key={target}
          target={target}
          assets={assets}
          isCollapsed={collapsed.has(target)}
          onToggle={() => toggleGroup(target)}
          deleting={deleting}
          onDelete={handleDelete}
        />
      ))}
    </div>
  )
}
